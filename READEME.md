# Auditoring Smart Contract — Workspace

## Overview

pnpm workspace monorepo using TypeScript. EVM smart contract security auditing engine with a React dashboard.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Frontend**: React + Vite + Tailwind CSS + shadcn/ui

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
  - **CRITICAL**: After codegen always overwrite `lib/api-zod/src/index.ts` with only `export * from "./generated/api";`
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

## Architecture

### Artifacts

- **API Server** (`artifacts/api-server/`) — Express 5 REST API on port from `$PORT` (8080 dev)
  - Routes: `/api/reports`, `/api/scanner/status`, `/api/scanner/endpoints`, `/api/scanner/run` (SSE)
- **UI** (`artifacts/contract-scanner-ui/`) — React dashboard at `/`
  - Pages: Dashboard, Scanner (live scan with SSE logs), Reports, ReportDetail, Endpoints

### Libraries

- `lib/db/` — Drizzle ORM schema + DB connection (`vulnerability_reports` table)
- `lib/api-spec/` — OpenAPI YAML spec (source of truth for all API shapes)
- `lib/api-client-react/` — Generated React Query hooks (via Orval)
- `lib/api-zod/` — Generated Zod validators (via Orval)

### Scanner Pipeline (SSE endpoint `/api/scanner/run`)

POST with `{ contractAddress, mode, simulation, fork }` returns a real-time SSE stream:
1. Bytecode fetch + decode
2. Opcode analysis (DELEGATECALL, SELFDESTRUCT, CALLCODE)
3. ABI selector extraction (4-byte database)
4. eth_call simulation (optional, +50 confidence)
5. Anvil fork validation (conditional on confidence ≥ 60 in auto mode)
6. Confidence score output + persist to DB

### Confidence Score

0-100 integer score on every report:
- Dangerous opcodes found: +15 each
- Flagged selectors: +10 each
- Simulation success: +50
- Value transfer in simulation: +30
- Fork validation confirms: +20
- `≥ 80` → CRITICAL, `≥ 60` → HIGH, `≥ 40` → MEDIUM, `≥ 20` → LOW, else INFO

## DB Schema Notes

- `vulnerability_reports` table has `confidence_score INTEGER NOT NULL DEFAULT 0`
- Always run `pnpm --filter @workspace/db run push-force` after schema changes

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
