# feraterra-mcp (`v4.9.5`)

Zero-dependency **Node.js `>=20` Model Context Protocol (MCP) `stdio` server**, **Streamable HTTP proxy (`--remote`)**, **offline agent skill installer (`install-skill`)**, and **ESM / TypeScript SDK** for [**FeraTerra**](https://feraterra.app) — sovereign central limit order book (CLOB) perpetuals, spot, basis spreads, stateless order simulation, and cryptographic `Keccak-256` + `secp256k1` solvency verification on Base (`https://testnet.feraterra.app`).

- **Zero npm dependencies:** Built strictly on Node.js `>=20` built-ins (`fetch`, `node:crypto`, `node:http`, `node:https`, `node:stream`) — `0` runtime dependencies and `0` install scripts for instant, supply-chain-clean `npx -y feraterra-mcp` execution.
- **Full MCP `2025-11-25` & `2025-06-18` `stdio` server + `--remote` Streamable HTTP proxy (`100%` schema coverage):** Supports protocol negotiation (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), `14` documented tools with top-level `title` + `ToolAnnotations`, `0` missing `inputSchema` descriptions, `resources/list`, `resources/templates/list`, `prompts/list`, `--read-only` guardrails (hiding mutating tools and prompts), and automatic credential scrubbing.
- **Offline portable trading skill (`install-skill`):** Bundles `skills/feraterra-trading/SKILL.md` (`v4.9.5`) and installs offline into `.agents/`, `.claude/`, `.cursor/`, or `.codex/` via `npx -y feraterra-mcp install-skill [--claude|--cursor|--codex|--dir <path>]`.
- **Stateless zero-key pre-trade safety (`account_id: 0`):** Simulate fills, net fees/rebates, and standalone Eigen-SPAN initial/maintenance margin (`IMR` / `MMR`) impact via `POST /order/preview` (`feraterra_preview_order` / `arena_preview_order`) with **zero API keys** and zero state mutation.
- **Headless protocol manifest (`GET /`) & machine-readable terms (`GET /terms`):** Inspect programmatic protocol disclosures, non-custodial L2 collateral vault Merkle emergency escape guarantees, and runtime posture via `feraterra_health_and_manifest`, `GET /terms` (`feraterra://protocol/terms`), and `client.getTerms()`.
- **Client-side cryptographic solvency audit & hardened HTTP transport:** Pure-BigInt `Keccak-256` and `secp256k1` signature recovery (`ecrecover`) verifying `ARENA_LEDGER_TIP_V2_1` WAL state roots, strict `https:` / loopback `http:` URL validation, `redirect: "error"` HMAC leak protection, and a `4 MiB` response body cap.

---

## Quick Start (`npx` — Zero Install)

Run the built-in loopback HTTP + MCP `stdio` + Streamable HTTP proxy + skill installer self-test:

```bash
npx -y feraterra-mcp --self-test
```

Install the portable `feraterra-trading` agent skill (`v4.9.5`) offline into your workspace:

```bash
# Default (.agents/skills/feraterra-trading/SKILL.md)
npx -y feraterra-mcp install-skill

# Agent-specific skill folders (--claude, --cursor, --codex) and explicit directory (--dir)
npx -y feraterra-mcp install-skill --claude --cursor --codex --dir ./my-trading-bot
```

Or install as an ESM / TypeScript SDK in any Node.js `>=20` project:

```bash
npm install feraterra-mcp
```

---

## MCP Client Configurations

For read-only market discovery, order book analysis, stateless `previewOrder` (`account_id: 0`), and cryptographic solvency audits, **no API keys are required**. Add `FERATERRA_ACCOUNT_ID`, `FERATERRA_API_KEY`, and `FERATERRA_API_SECRET` only when enabling authenticated account inspection and order execution.

### 1. Claude Desktop (`claude_desktop_config.json`)

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "feraterra": {
      "command": "npx",
      "args": ["-y", "feraterra-mcp"],
      "env": {
        "FERATERRA_API_URL": "https://testnet.feraterra.app"
      }
    }
  }
}
```

### 2. Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "feraterra": {
      "command": "npx",
      "args": ["-y", "feraterra-mcp"],
      "env": {
        "FERATERRA_API_URL": "https://testnet.feraterra.app"
      }
    }
  }
}
```

### 3. Streamable HTTP Proxy Mode (`--remote` / `--mcp-url`)

Bridge `stdio`-only MCP hosts (`JSONL` or `Content-Length`) to the hosted Streamable HTTP MCP gateway (`https://mcp.feraterra.app/mcp`) with optional `FERATERRA_BEARER_TOKEN` authentication:

```json
{
  "mcpServers": {
    "feraterra-remote": {
      "command": "npx",
      "args": ["-y", "feraterra-mcp", "--remote", "--mcp-url", "https://mcp.feraterra.app/mcp"],
      "env": {
        "FERATERRA_BEARER_TOKEN": "your-optional-bearer-token"
      }
    }
  }
}
```

### 4. Direct Hosted Streamable HTTP (Zero Local Process)

```json
{
  "mcpServers": {
    "feraterra-remote": {
      "type": "streamable-http",
      "url": "https://mcp.feraterra.app/mcp"
    }
  }
}
```

---

## Exposed MCP Tools (14)

| Tool | Endpoint / Mode | Auth | Description |
| :--- | :--- | :--- | :--- |
| `feraterra_health_and_manifest` *(alias: `arena_health_and_manifest`)* | `GET /health` + `GET /` (+ `GET /terms`) | Public | Fetch gateway health, conservation status, `wal_seq`, `chain_id`, L2 collateral vault address, and optional terms. |
| `feraterra_list_markets` | `GET /markets` | Public | List active perpetual, spot, basis spread, and bounded-claim markets with USD mark prices and BBOs. |
| `feraterra_get_orderbook` | `GET /book` | Public | Fetch live L2/L3 order book depth, USD levels, base sizes, and top-of-book spread. |
| `feraterra_get_trades` | `GET /trades` | Public | Fetch recent CLOB trade executions with USD prices and base quantities. |
| `feraterra_get_candles` | `GET /candles` | Public | Fetch `tick`, `1s`, or `1m` OHLCV candles with formatted USD OHLC and base volume. |
| `feraterra_get_leaderboard` | `GET /leaderboard` | Public | Retrieve ranked traders sorted by `equity`, `pnl`, `streak`, `volume`, or `roi`. |
| `feraterra_verify_ledger_tip` | `GET /ledger/tip` + `GET /health` | Public | Verify `ARENA_LEDGER_TIP_V2_1` `Keccak-256` digest, `secp256k1` operator signature, and conservation invariants. |
| `feraterra_preview_order` *(alias: `arena_preview_order`)* | `POST /order/preview` | Public (`account_id: 0`) / HMAC | Stateless zero-mutation order & Eigen-SPAN IMR/MMR simulation (`account_id: 0` or omitted = anonymous zero-key preview). |
| `feraterra_get_account` | `GET /account` | HMAC `X-Arena-*` | Inspect Eigen-SPAN equity, free/withdrawable USD, IMR/MMR, positions, and open orders. |
| `feraterra_place_order` | `POST /order` | HMAC `X-Arena-*` | Submit limit or market orders (`gtc`, `ioc`, `fok`, `post_only`, `reduce_only`). |
| `feraterra_replace_quote` | `POST /quote` | HMAC `X-Arena-*` | Atomically replace resting two-sided maker bid and ask quotes in 1 WAL step (default `tif: "post_only"`). |
| `feraterra_cancel_order` | `POST /cancel` | HMAC `X-Arena-*` | Cancel a specific resting order by `order_id`. |
| `feraterra_cancel_all_orders` | `POST /cancel_all` | HMAC `X-Arena-*` | Batch-cancel resting orders across all markets or filtered by market, side, or tag. |
| `feraterra_convert_units` | Local Pure Math | Offline | Convert exact fixed-point `ticks` (`$0.01`), `lots` (`0.0001`), and `micro_usd` (`1e-6`). |

> **Compatibility Aliases:** For drop-in compatibility with the hosted `mcp.feraterra.app` gateway, `FeraTerraMcpServer.callTool` also accepts `arena_health_and_manifest`, `arena_preview_order`, `arena_list_markets`, `arena_get_orderbook`, `arena_get_trades`, `arena_get_candles`, `arena_get_leaderboard`, `arena_verify_ledger_tip`, `arena_get_account_portfolio`, `arena_place_order`, `arena_replace_two_sided_quote`, `arena_cancel_order`, `arena_cancel_orders`, and `arena_cancel_all`.

## Exposed MCP Resources (4)

| Resource URI | Backing Endpoint | Description |
| :--- | :--- | :--- |
| `feraterra://markets/directory` | `GET /markets` | Live CLOB perpetual, spot, basis spread, and bounded-claim market catalog. |
| `feraterra://ledger/tip` | `GET /ledger/tip` + `GET /health` | Cryptographically verified `ARENA_LEDGER_TIP_V2_1` state root and operator signature. |
| `feraterra://protocol/terms` | `GET /terms` | Machine-readable headless protocol Terms of Service, L2 collateral vault Merkle escape guarantees, and risk disclosures. |
| `feraterra://server/config` | Local Gateway State | Active base URL, remote Streamable HTTP endpoint, credential posture, and read-only status. |

---

## Stateless Zero-Key Order Preview (`account_id: 0`) & Headless `GET /terms`

### 1. Anonymous Zero-Key Order & IMR Simulation (`POST /order/preview`)

Agents can simulate resting or crossing orders, net fees/rebates, and standalone Eigen-SPAN initial/maintenance margin (`IMR` / `MMR`) **before provisioning a wallet or API keys** by omitting `account_id` or passing `account_id: 0` to `feraterra_preview_order` (`arena_preview_order`):

```bash
curl -s -X POST https://testnet.feraterra.app/order/preview \
  -H "Content-Type: application/json" \
  -d '{"account_id":0,"market_id":1,"side":"bid","price_ticks":7000000,"qty_lots":1000,"tif":"post_only","stp":"cancel_resting"}'
```

When `FERATERRA_ACCOUNT_ID` (`> 0`), `FERATERRA_API_KEY`, and `FERATERRA_API_SECRET` are configured, omitting `account_id` automatically simulates against the authenticated account's live Eigen-SPAN portfolio; passing `account_id: 0` explicitly still forces a clean zero-key stateless simulation without attaching `X-Arena-*` HMAC headers.

### 2. Machine-Readable Headless Protocol Terms (`GET /terms`)

FeraTerra operates as a headless sovereign CLOB protocol (`website_ui: false`). Agents and integrators can retrieve machine-readable protocol Terms of Service, non-custodial L2 collateral vault Merkle emergency escape guarantees, and risk disclosures directly via `GET /terms` (or MCP resource `feraterra://protocol/terms`):

```bash
curl -s https://testnet.feraterra.app/terms
```

---

## Node.js / TypeScript ESM SDK Usage

```ts
import {
  FeraTerraClient,
  PACKAGE_VERSION,
  baseToLots,
  lotsToBase,
  strictBool,
  ticksToUsd,
  usdToTicks,
  verifyLedgerTip,
} from "feraterra-mcp";

// 1. Read-only + stateless preview (zero credentials needed)
const publicClient = new FeraTerraClient({
  baseUrl: "https://testnet.feraterra.app",
});

const status = await publicClient.getHealthAndManifest({ includeTerms: true });
const markets = await publicClient.listMarkets({ activeOnly: true });
const book = await publicClient.getOrderbook({ symbol: "BTC-USD-PERP", depth: 10 });
const trades = await publicClient.getTrades({ symbol: "BTC-USD-PERP", limit: 20 });
const candles = await publicClient.getCandles({ symbol: "BTC-USD-PERP", interval: "1m", limit: 60 });
const leaderboard = await publicClient.getLeaderboard({ limit: 10, sort: "equity" });
const solvency = await publicClient.verifySolvency();

// Stateless dry-run preview with account_id: 0
const preview = await publicClient.previewOrder({
  accountId: 0,
  symbol: "BTC-USD-PERP",
  side: "buy",
  price: "70000.00",
  amount: "0.1",
  postOnly: true,
});

// Fixed-point unit helpers (1 tick = $0.01, 1 lot = 0.0001 base)
const pxTicks = usdToTicks("70000.25"); // 7000025
const pxUsd = ticksToUsd(pxTicks);      // "70000.25"
const qtyLots = baseToLots("0.25");     // 2500
const qtyBase = lotsToBase(qtyLots);    // "0.2500"

// 2. Authenticated HMAC-SHA256 trading client
const tradingClient = new FeraTerraClient({
  baseUrl: process.env.FERATERRA_API_URL ?? "https://testnet.feraterra.app",
  accountId: Number(process.env.FERATERRA_ACCOUNT_ID),
  apiKey: process.env.FERATERRA_API_KEY,
  apiSecret: process.env.FERATERRA_API_SECRET,
});

const account = await tradingClient.getAccount();
const order = await tradingClient.placeOrder({
  symbol: "BTC-USD-PERP",
  side: "buy",
  price: "69950.00",
  amount: "0.1",
  postOnly: true,
});
await tradingClient.cancelOrder({ symbol: "BTC-USD-PERP", orderId: order.order_id });
```

---

## Environment Variables & CLI Flags

| Variable | CLI Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `FERATERRA_API_URL` | `--base-url <url>` | `https://testnet.feraterra.app` | FeraTerra HTTPS gateway URL (loopback `http://` also permitted for local testing). |
| `FERATERRA_REMOTE_MCP` | `--remote` | `false` | Proxy MCP `stdio` frames to Streamable HTTP gateway instead of local REST dispatch. |
| `FERATERRA_MCP_URL` | `--mcp-url <url>` | `https://mcp.feraterra.app/mcp` | Target Streamable HTTP MCP URL (implies `--remote` when `--mcp-url` is passed). |
| `FERATERRA_BEARER_TOKEN` | `--bearer-token <tok>` | *(optional)* | Optional `Authorization: Bearer` token forwarded in `--remote` proxy mode. |
| `FERATERRA_ACCOUNT_ID` | `--account-id <id>` | `0` | Default trader account ID (`0` uses stateless preview; `>0` required for `/account` and trading). |
| `FERATERRA_API_KEY` | `--api-key <key>` | *(optional)* | `X-Arena-API-Key` identifier for HMAC-SHA256 authenticated requests. |
| `FERATERRA_API_SECRET` | `--api-secret <secret>` | *(optional)* | HMAC-SHA256 signing secret (automatically redacted from MCP outputs and errors). |
| `FERATERRA_EXPECTED_OPERATOR` | `--expected-operator <0x...>` | *(optional)* | Pinned `0x...` Ethereum operator signer address for `GET /ledger/tip` verification. |
| `FERATERRA_READ_ONLY` | `--read-only` | `false` | Disables mutating tools and mutating prompts. |
| `FERATERRA_TIMEOUT_MS` | `--timeout-ms <ms>` | `10000` | Per-request HTTP timeout in milliseconds (`30000` in `--remote` mode). |

---

## Verification & Testing

```bash
node ./bin/feraterra-mcp.mjs --self-test
node --test test/mcp.test.mjs
```

---

## License

[MIT](./LICENSE) — Copyright (c) 2026 FeraTerra.
