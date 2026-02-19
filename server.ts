import { Database } from "bun:sqlite";
import { randomBytes, createHmac, timingSafeEqual } from "crypto";

const SECRET = randomBytes(32);
const MAX_SESSIONS = 10_000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const activeSessions = new Map<string, number>();

function evictExpired(): void {
  const now = Date.now();
  for (const [id, createdAt] of activeSessions) {
    if (now - createdAt > SESSION_TTL_MS) activeSessions.delete(id);
  }
}

function createToken(): string {
  if (activeSessions.size >= MAX_SESSIONS) evictExpired();
  if (activeSessions.size >= MAX_SESSIONS) {
    const oldest = activeSessions.keys().next().value!;
    activeSessions.delete(oldest);
  }

  const sessionId = randomBytes(16).toString("hex");
  const timestamp = Date.now().toString();
  const data = `${sessionId}:${timestamp}`;
  const sig = createHmac("sha256", SECRET).update(data).digest("hex");
  activeSessions.set(sessionId, Date.now());
  return `${data}:${sig}`;
}

function verifyToken(token: string): { valid: boolean; error?: string } {
  const parts = token.split(":");
  if (parts.length !== 3) return { valid: false, error: "Malformed token" };
  const [sessionId, timestamp, sig] = parts;

  if (!/^[0-9a-f]{64}$/.test(sig))
    return { valid: false, error: "Invalid signature" };

  const data = `${sessionId}:${timestamp}`;
  const expected = createHmac("sha256", SECRET).update(data).digest("hex");
  if (!timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex")))
    return { valid: false, error: "Invalid signature" };

  if (!activeSessions.delete(sessionId))
    return { valid: false, error: "Session already used or unknown" };

  const elapsed = Date.now() - Number(timestamp);
  if (!Number.isFinite(elapsed) || elapsed < 5000)
    return { valid: false, error: "Session too short" };

  return { valid: true };
}

const db = new Database("leaderboard.db");
db.run("PRAGMA journal_mode = WAL");
db.run(`
  CREATE TABLE IF NOT EXISTS leaderboard (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    score INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);
db.run("CREATE INDEX IF NOT EXISTS idx_score ON leaderboard(score DESC)");

const MAX_SLOTS = 10;

const getTop = db.prepare(
  "SELECT id, name, score, created_at FROM leaderboard ORDER BY score DESC, created_at ASC LIMIT ?"
);
const countRows = db.prepare("SELECT COUNT(*) as cnt FROM leaderboard");
const getMinTop = db.prepare(
  "SELECT MIN(score) as min_score FROM (SELECT score FROM leaderboard ORDER BY score DESC LIMIT ?)"
);
const insertScore = db.prepare(
  "INSERT INTO leaderboard (name, score) VALUES (?, ?) RETURNING id, name, score, created_at"
);
const deleteLowest = db.prepare(
  "DELETE FROM leaderboard WHERE id = (SELECT id FROM leaderboard ORDER BY score ASC, created_at DESC LIMIT 1)"
);

Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);

    // API: GET session token
    if (req.method === "GET" && url.pathname === "/api/session") {
      return Response.json({ token: createToken() });
    }

    // API: GET leaderboard
    if (req.method === "GET" && url.pathname === "/api/leaderboard") {
      const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "10") || 10, 1), 100);
      const rows = getTop.all(limit);
      return Response.json(rows);
    }

    // API: POST leaderboard
    if (req.method === "POST" && url.pathname === "/api/leaderboard") {
      try {
        const body = await req.json();
        const token = typeof body.token === "string" ? body.token : "";
        const { valid, error } = verifyToken(token);
        if (!valid) return Response.json({ error: error || "Invalid token" }, { status: 403 });

        const name = (typeof body.name === "string" ? body.name : "").trim().slice(0, 20);
        const score = typeof body.score === "number" ? Math.floor(body.score) : NaN;

        if (!name) return Response.json({ error: "Name is required" }, { status: 400 });
        if (!Number.isFinite(score) || score < 0) return Response.json({ error: "Score must be a non-negative integer" }, { status: 400 });

        const upsert = db.transaction(() => {
          const { cnt } = countRows.get() as { cnt: number };
          if (cnt >= MAX_SLOTS) {
            const { min_score } = getMinTop.get(MAX_SLOTS) as { min_score: number };
            if (score <= min_score) return null;
            deleteLowest.run();
          }
          return insertScore.get(name, score);
        });

        const entry = upsert();
        if (!entry) {
          return Response.json({ error: "Score too low to make the leaderboard" }, { status: 409 });
        }
        return Response.json(entry, { status: 201 });
      } catch (err) {
        if (err instanceof SyntaxError) {
          return Response.json({ error: "Invalid request body" }, { status: 400 });
        }
        console.error("Leaderboard POST error:", err);
        return Response.json({ error: "Internal server error" }, { status: 500 });
      }
    }

    // Static: serve index.html
    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(Bun.file("index.html"));
    }

    return new Response("Not Found", { status: 404 });
  },
});

console.log("Cross Five server running on http://localhost:3000");
