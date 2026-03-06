# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **Cross Five**, a browser-based puzzle game with a Bun.js backend for leaderboard functionality. The game involves placing dots on a cross-shaped board to form lines of 5 consecutive dots.

## Architecture

- **Frontend**: `index.html` — single file containing all HTML, CSS, and JavaScript
- **Backend**: `server.ts` — Bun.js HTTP server with SQLite leaderboard
- **Database**: `leaderboard.db` — auto-created SQLite file (WAL mode)
- **Docker**: `Dockerfile` using `oven/bun` for deployment
- **No build process**: Bun runs `server.ts` directly
- **No dependencies**: Pure vanilla JS frontend, Bun built-in SQLite backend
- **External assets**: Google Fonts CDN for typography

## Running the Game

### With Bun (development)
```bash
bun run server.ts
# Open http://localhost:3000
```

### With Docker (production)
```bash
docker build -t cross-five .
docker volume create cross-five-data
docker run -p 3000:3000 -v cross-five-data:/app cross-five
```

## Files

| File | Purpose |
|------|---------|
| `index.html` | Full frontend — game board, UI, overlays, API calls |
| `server.ts` | Bun HTTP server — serves `index.html`, leaderboard API |
| `Dockerfile` | Bun image for deployment |
| `.dockerignore` | Excludes db files, node_modules, .git from build |

## API Endpoints

- `GET /api/session` — issues an HMAC-signed session token for leaderboard submission
- `GET /api/leaderboard?limit=10` — returns top scores as JSON array
- `POST /api/leaderboard` — accepts `{ name, score, token }`, validates token and inserts; returns 403 if token invalid, 409 if score too low

## Session Token Auth

Leaderboard submissions are protected by HMAC-SHA256 signed session tokens:
- **Flow**: Frontend fetches a token via `GET /api/session` on game start/reset, includes it in the POST on submission
- **Token format**: `sessionId:timestamp:hmacSignature`
- **Server secret**: Random 32 bytes, regenerated on each server restart
- **Checks**: Valid HMAC signature (timing-safe compare), one-time use, minimum 5s elapsed since token creation
- **Storage**: Active session IDs held in an in-memory `Set` (cleared on restart)

## Code Structure (index.html)

The game logic is organized into distinct sections within the `<script>` tag:

1. **Constants & State**: Board dimensions, grid state, scoring, `gameOver` flag
2. **Cross Shape Definition**: Defines the playable cross-shaped area on a 20×20 grid
3. **Grid Management**: Initialize and reset game state
4. **Line Detection**: Core game logic for finding valid 5-dot lines and handling conflicts
5. **Rendering**: Canvas drawing with hover previews and visual feedback
6. **Interaction**: Mouse/touch event handlers
7. **Game Over Flow**: Give Up → board capture → name input → score submission
8. **Leaderboard**: Fetch and display top 10 scores with rank, name, score, date

## Key Game Mechanics

- **Grid**: 20×20 board with cross-shaped playable area (4-wide arms)
- **Objective**: Form lines of exactly 5 consecutive dots (horizontal, vertical, or diagonal)
- **Conflict Resolution**: Lines sharing 2+ dots in the same direction cannot both be claimed
- **Reuse**: Existing dots can be used to form additional non-conflicting lines
- **Game Over**: Player clicks "Give Up" to end the game and optionally submit score
- **Leaderboard**: Top 10 scores; new scores must beat the lowest to enter when full

## Styling

Uses a minimalist dark theme with:
- Background: `#0a0a0c`
- Accent color: `#c4956a` (warm tan)
- Font: DM Mono (monospace, from Google Fonts)
- Modals: `#111114` background, `#2a2a2e` borders
- Muted grid lines and subtle hover states

## Modifications

When modifying this code:
- Frontend changes go in `index.html`, backend changes in `server.ts`
- Test with `bun run server.ts` and open `http://localhost:3000`
- The game state is fully reset by the Reset button or page refresh
- Canvas rendering uses immediate mode (redraws entire board each frame)
- The leaderboard DB is auto-created on first run
