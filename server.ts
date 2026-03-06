import { Database } from "bun:sqlite";
import { randomBytes, createHmac, timingSafeEqual } from "crypto";

const SECRET = randomBytes(32);
const MAX_SESSIONS = 10_000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const activeSessions = new Map<string, number>();

const evictExpired = (): void => {
  const now = Date.now();
  for (const [id, createdAt] of activeSessions) {
    if (now - createdAt > SESSION_TTL_MS) activeSessions.delete(id);
  }
};

const createToken = (): string => {
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
};

type VerifyResult = { valid: boolean; error?: string };

const verifyToken = (token: string): VerifyResult => {
  const parts = token.split(":");
  if (parts.length !== 3) return { valid: false, error: "Malformed token" };
  const sessionId = parts[0]!;
  const timestamp = parts[1]!;
  const sig = parts[2]!;

  if (!/^[0-9a-f]{64}$/.test(sig))
    return { valid: false, error: "Invalid signature" };

  const data = `${sessionId}:${timestamp}`;
  const expected = createHmac("sha256", SECRET).update(data).digest("hex");
  const sigBuffer = Buffer.from(sig, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");
  if (!timingSafeEqual(sigBuffer, expectedBuffer))
    return { valid: false, error: "Invalid signature" };

  if (!activeSessions.delete(sessionId))
    return { valid: false, error: "Session already used or unknown" };

  const elapsed = Date.now() - Number(timestamp);
  if (!Number.isFinite(elapsed) || elapsed < 5000)
    return { valid: false, error: "Session too short" };

  return { valid: true };
};

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

type LeaderboardEntry = { id: number; name: string; score: number; created_at: string };

const insertScoreEntry = (name: string, score: number): LeaderboardEntry | null => {
  const { cnt } = countRows.get() as { cnt: number };
  if (cnt >= MAX_SLOTS) {
    const { min_score } = getMinTop.get(MAX_SLOTS) as { min_score: number };
    if (score <= min_score) return null;
    deleteLowest.run();
  }
  return insertScore.get(name, score) as LeaderboardEntry;
};

const handleSession = () => Response.json({ token: createToken() });

const handleLeaderboardGet = (url: URL) => {
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "10") || 10, 1), 100);
  const rows = getTop.all(limit);
  return Response.json(rows);
};

const handleLeaderboardPost = async (req: Request): Promise<Response> => {
  try {
    const body = await req.json() as Record<string, unknown>;
    const token = typeof body.token === "string" ? body.token : "";
    const { valid, error } = verifyToken(token);
    if (!valid) return Response.json({ error: error || "Invalid token" }, { status: 403 });

    const name = (typeof body.name === "string" ? body.name : "").trim().slice(0, 20);
    const score = typeof body.score === "number" ? Math.floor(body.score) : NaN;

    if (!name) return Response.json({ error: "Name is required" }, { status: 400 });
    if (!Number.isFinite(score) || score < 0) return Response.json({ error: "Score must be a non-negative integer" }, { status: 400 });

    const entry = insertScoreEntry(name, score);
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
};

const serveStatic = (pathname: string) => {
  if (pathname === "/" || pathname === "/index.html") {
    return new Response(Bun.file("index.html"));
  }
  return null;
};

Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);

    if (req.method === "GET" && url.pathname === "/api/session") return handleSession();
    if (req.method === "GET" && url.pathname === "/api/leaderboard") return handleLeaderboardGet(url);
    if (req.method === "POST" && url.pathname === "/api/leaderboard") return handleLeaderboardPost(req);

    const staticResp = serveStatic(url.pathname);
    if (staticResp) return staticResp;

    return new Response("Not Found", { status: 404 });
  },
});

console.log("Cross Five server running on http://localhost:3000");
