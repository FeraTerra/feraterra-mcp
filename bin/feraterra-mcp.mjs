#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { PassThrough, Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_FERATERRA_API_URL,
  FeraTerraClient,
  PACKAGE_VERSION,
  REMOTE_FERATERRA_MCP_URL,
  baseToLots,
  computeHmacSignature,
  computeLedgerTipDigest,
  deriveEthAddress,
  keccak256,
  lotsToBase,
  microToUsd,
  signDigestSecp256k1,
  strictBool,
  ticksToUsd,
  usdToMicro,
  usdToTicks,
  validateEndpointUrl,
  verifyLedgerTip,
} from "../src/index.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PACKAGE_ROOT = path.resolve(__dirname, "..");

export const SERVER_NAME = "feraterra-mcp";
export const SERVER_VERSION = "4.9.5";
export const BUNDLED_SKILL_PATH = path.join(PACKAGE_ROOT, "skills", "feraterra-trading", "SKILL.md");
export const DEFAULT_MCP_PROTOCOL_VERSION = "2025-11-25";
export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
]);

const MAX_STDIO_MESSAGE_BYTES = 4 * 1024 * 1024;
const MAX_HEADER_BLOCK_BYTES = 65_536;
const MAX_BATCH_REQUESTS = 64;
const DEFAULT_REMOTE_TIMEOUT_MS = 30_000;

const SENSITIVE_FIELD_NAMES = new Set([
  "api_key",
  "apikey",
  "api_secret",
  "apisecret",
  "private_key",
  "privatekey",
  "wallet_privkey",
  "x-arena-signature",
  "authorization",
  "bearer_token",
  "bearertoken",
]);

const SECRET_KV_PATTERN =
  /("?(?:api_key|apiKey|api_secret|apiSecret|private_key|privateKey|wallet_privkey|bearer_token|bearerToken)"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,}\]]+)/gi;

function writeStderrLine(line) {
  process.stderr.write(`${line}\n`);
}

function resolveEnvBool(val, defaultVal = false) {
  if (val === undefined || val === null) return defaultVal;
  const s = String(val).trim().toLowerCase();
  if (!s) return defaultVal;
  if (s === "1" || s === "yes" || s === "on") return true;
  if (s === "0" || s === "no" || s === "off") return false;
  return strictBool(s, defaultVal);
}

function scrubText(text, secrets = []) {
  let out = String(text ?? "");
  for (const tok of secrets) {
    const clean = String(tok ?? "").trim();
    if (clean.length >= 6) {
      out = out.split(clean).join("[REDACTED]");
    }
  }
  return out.replace(SECRET_KV_PATTERN, "$1[REDACTED]");
}

function scrubValue(value, secrets = []) {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return scrubText(value, secrets);
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, secrets));
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_FIELD_NAMES.has(k.toLowerCase())) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = scrubValue(v, secrets);
      }
    }
    return out;
  }
  return value;
}

const READ_ONLY_TOOL_NAMES = new Set([
  "feraterra_health_and_manifest",
  "feraterra_list_markets",
  "feraterra_get_orderbook",
  "feraterra_get_trades",
  "feraterra_get_candles",
  "feraterra_get_leaderboard",
  "feraterra_verify_ledger_tip",
  "feraterra_preview_order",
  "feraterra_get_account",
  "feraterra_convert_units",
]);

const MUTATING_PROMPT_NAMES = new Set([
  "preview_and_execute_order",
]);

const DESTRUCTIVE_TOOL_NAMES = new Set([
  "feraterra_cancel_order",
  "feraterra_cancel_all_orders",
]);

function buildToolAnnotations(name, title) {
  if (name === "feraterra_convert_units") {
    return {
      title,
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    };
  }
  if (READ_ONLY_TOOL_NAMES.has(name)) {
    return {
      title,
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    };
  }
  if (DESTRUCTIVE_TOOL_NAMES.has(name)) {
    return {
      title,
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    };
  }
  return {
    title,
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  };
}

function buildToolDefinitions() {
  const raw = [
    {
      name: "feraterra_health_and_manifest",
      title: "Get Gateway Health, Manifest & Terms",
      description:
        "Fetch FeraTerra gateway health invariants (GET /health), headless protocol manifest (GET /), and optional machine-readable protocol terms (GET /terms) in a single read-only call. Use this first to inspect WAL sequence, double-entry conservation health, settlement chain_id, L2 collateral vault address, and supported endpoints before querying markets or submitting orders.",
      inputSchema: {
        type: "object",
        properties: {
          include_terms: {
            type: "boolean",
            default: false,
            description:
              "When true, also queries GET /terms alongside GET /health and GET / to include headless protocol risk disclosures.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_list_markets",
      title: "List FeraTerra Markets",
      description:
        "List FeraTerra CLOB markets (LinearPerpetual, FormulaPerpetual, Spot, BoundedClaim, and SpreadBook) via GET /markets with unified CCXT symbols, fixed-point precision (1 tick = $0.01, 1 lot = 1e-4 base), USD mark prices, and top-of-book BBO quotes. Read-only market catalog; use feraterra_get_orderbook instead for multi-level L2/L3 depth on a single market.",
      inputSchema: {
        type: "object",
        properties: {
          kind: {
            type: "string",
            description:
              "Optional market category filter ('perp', 'spot', 'formula_perp', 'bounded_claim', or 'spread_book'); empty string or omitted returns all market kinds.",
          },
          symbol: {
            type: "string",
            description:
              "Optional case-insensitive market symbol filter matching native (e.g. 'BTC-USD-PERP') or unified (e.g. 'BTC/USD:USD') symbols.",
          },
          active_only: {
            type: "boolean",
            default: true,
            description:
              "When true (default), excludes halted instruments and returns only live/active tradable markets.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_get_orderbook",
      title: "Get CLOB Orderbook",
      description:
        "Fetch a live L2/L3 resting CLOB order book snapshot (bids, asks, formatted USD price levels, base sizes, best bid/ask, spread, and WAL sequence) for a single FeraTerra market via GET /book. Read-only; use this to inspect resting liquidity before sizing orders, whereas feraterra_list_markets scans top-of-book BBOs across all markets and feraterra_get_trades retrieves historical executions. Provide either symbol or market_id.",
      inputSchema: {
        type: "object",
        properties: {
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP', 'BTC/USD:USD', or 'ETH-USD-SPOT'); mutually exclusive with market_id (defaults to 'BTC-USD-PERP' when both are omitted).",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1); mutually exclusive alternative to symbol.",
          },
          depth: {
            type: "integer",
            minimum: 1,
            maximum: 200,
            default: 20,
            description:
              "Maximum number of resting price levels to return per order book side (1..200, default 20).",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_get_trades",
      title: "Get Recent Trades",
      description:
        "Fetch recent matched CLOB trade executions for a single FeraTerra market via GET /trades with exact fixed-point ticks/lots (1 tick = $0.01, 1 lot = 1e-4 base) and formatted USD/base values. Read-only; use this for realized trade prints, whereas feraterra_get_candles fetches aggregated OHLCV bars and feraterra_get_orderbook inspects resting liquidity. Provide either symbol or market_id.",
      inputSchema: {
        type: "object",
        properties: {
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP' or 'BTC/USD:USD'); mutually exclusive with market_id (defaults to 'BTC-USD-PERP' when both are omitted).",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1); mutually exclusive alternative to symbol.",
          },
          limit: {
            type: "integer",
            minimum: 1,
            maximum: 512,
            default: 50,
            description:
              "Maximum number of recent matched trade executions to return (1..512, default 50).",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_get_candles",
      title: "Get OHLCV Candles",
      description:
        "Fetch aggregated OHLCV candlestick bars ('tick', '1s', or '1m' intervals) for a single FeraTerra market via GET /candles with exact integer ticks/lots (1 tick = $0.01, 1 lot = 1e-4 base) and formatted USD OHLC and base volume strings. Read-only; use feraterra_get_trades instead for individual execution prints or feraterra_get_orderbook for current resting depth. Provide either symbol or market_id.",
      inputSchema: {
        type: "object",
        properties: {
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP' or 'BTC/USD:USD'); mutually exclusive with market_id (defaults to 'BTC-USD-PERP' when both are omitted).",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1); mutually exclusive alternative to symbol.",
          },
          interval: {
            type: "string",
            enum: ["tick", "1s", "1m"],
            default: "1m",
            description:
              "OHLCV candle aggregation timeframe: 'tick' (per-match), '1s' (1-second bars), or '1m' (1-minute bars, default).",
          },
          limit: {
            type: "integer",
            minimum: 1,
            maximum: 240,
            default: 120,
            description:
              "Maximum number of recent OHLCV candlestick bars to return (1..240, default 120).",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_get_leaderboard",
      title: "Get Trader Leaderboard",
      description:
        "Fetch the public FeraTerra Gladiator Leaderboard via GET /leaderboard ranking active accounts by total USD equity, net PnL, maker BBO uptime streak, notional volume, or ROI. Read-only public benchmark; use feraterra_get_account instead to inspect private balances, Eigen-SPAN margin, positions, and open orders for your authenticated account.",
      inputSchema: {
        type: "object",
        properties: {
          limit: {
            type: "integer",
            minimum: 1,
            maximum: 100,
            default: 25,
            description:
              "Maximum number of ranked trader accounts to return (1..100, default 25).",
          },
          sort: {
            type: "string",
            enum: ["equity", "pnl", "streak", "volume", "roi"],
            default: "equity",
            description:
              "Leaderboard ranking metric: 'equity' (total USD equity, default), 'pnl' (net PnL), 'streak' (maker BBO uptime epochs), 'volume', or 'roi'.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_verify_ledger_tip",
      title: "Verify Cryptographic Solvency & Ledger Tip",
      description:
        "Fetch GET /ledger/tip (and optional GET /health) and cryptographically verify the ARENA_LEDGER_TIP_V2_1 Keccak-256 commitment digest, secp256k1 operator signature (ecrecover), and double-entry conservation invariants client-side using pure BigInt arithmetic. Read-only solvency verifier; requires zero credentials.",
      inputSchema: {
        type: "object",
        properties: {
          expected_operator_address: {
            type: "string",
            description:
              "Optional 0x-prefixed 20-byte Ethereum operator signer address to pin against the recovered secp256k1 signer (overrides FERATERRA_EXPECTED_OPERATOR).",
          },
          expected_chain_id: {
            type: "integer",
            minimum: 0,
            description:
              "Optional expected EVM settlement chain ID to assert against the signed ledger tip (e.g. 84532 for Base Sepolia or 8453 for Base Mainnet).",
          },
          expected_clearinghouse_address: {
            type: "string",
            description:
              "Optional 0x-prefixed 20-byte L2 collateral vault address to assert against the signed ledger tip commitment.",
          },
          include_health: {
            type: "boolean",
            default: true,
            description:
              "When true (default), also queries GET /health to verify double-entry conservation and daemon health invariants alongside signature verification.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_preview_order",
      title: "Preview Order (Stateless Dry-Run)",
      description:
        "Run a stateless, zero-mutation pre-trade order simulation via POST /order/preview (never mutates WAL, L3 book, or balances; supports account_id=0 or omitted account_id for anonymous zero-key order, fill, fee, and Eigen-SPAN IMR simulation without API keys, as well as account_id>=1 authenticated portfolio margin checks; also callable via alias arena_preview_order). Always call this to verify would_accept, fill price, net fee/rebate, and IMR impact before calling feraterra_place_order. Provide mutually exclusive market (symbol vs market_id), price (price_usd, price_ticks, or SpreadBook differential_usd), and size (amount_base vs qty_lots) fields.",
      inputSchema: {
        type: "object",
        properties: {
          account_id: {
            type: "integer",
            minimum: 0,
            description:
              "Account ID for simulation (0 = stateless anonymous zero-key order & Eigen-SPAN IMR simulation without credentials; >= 1 = simulate against the account's live portfolio; defaults to session account_id when authenticated or 0 when unauthenticated).",
          },
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP', 'BTC/USD:USD', or 'ETH-USD-SPOT'); mutually exclusive with market_id (defaults to 'BTC-USD-PERP' when both are omitted).",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1); mutually exclusive alternative to symbol.",
          },
          side: {
            type: "string",
            enum: ["buy", "sell", "bid", "ask"],
            default: "buy",
            description:
              "Simulated order direction: 'buy'/'bid' (long/buy) or 'sell'/'ask' (short/sell).",
          },
          order_type: {
            type: "string",
            enum: ["limit", "market"],
            default: "limit",
            description:
              "Simulated execution type: 'limit' (resting or crossing limit order, default) or 'market' (immediate IOC book sweep).",
          },
          is_market: {
            type: "boolean",
            default: false,
            description:
              "When true, simulates an immediate market sweep order (defaults tif to 'ioc' and allows 0 limit price).",
          },
          price_usd: {
            type: ["string", "number"],
            description:
              "Simulated limit price in exact USD decimal string or number (e.g. '70000.00', exact multiple of $0.01); mutually exclusive with price_ticks and differential_usd.",
          },
          price_ticks: {
            type: "integer",
            description:
              "Simulated limit price in fixed-point integer ticks (1 tick = $0.01; 0 allowed for market orders; SpreadBook par = 1000000); mutually exclusive with price_usd and differential_usd.",
          },
          differential_usd: {
            type: ["string", "number"],
            description:
              "Signed USD spread differential relative to $10,000.00 par (e.g. '-5.25') for SpreadBook markets only; mutually exclusive with price_usd and price_ticks.",
          },
          amount_base: {
            type: ["string", "number"],
            description:
              "Simulated order size in exact base-asset units (e.g. '0.1000', exact multiple of 0.0001; defaults to '0.01' when omitted); mutually exclusive with qty_lots.",
          },
          qty_lots: {
            type: "integer",
            minimum: 1,
            description:
              "Simulated order size in fixed-point integer lots (1 lot = 1e-4 base unit, minimum 1); mutually exclusive with amount_base.",
          },
          tif: {
            type: "string",
            enum: ["gtc", "ioc", "fok", "post_only"],
            description:
              "Simulated time-in-force policy: 'gtc' (Good-Til-Cancelled), 'ioc' (Immediate-Or-Cancel), 'fok' (Fill-Or-Kill), or 'post_only' (maker-only).",
          },
          stp: {
            type: "string",
            enum: ["cancel_resting", "cancel_incoming", "cancel_both", "decrement_and_cancel", "none"],
            default: "cancel_resting",
            description:
              "Simulated Self-Trade Prevention mode applied if the order crosses resting orders from the same account.",
          },
          reduce_only: {
            type: "boolean",
            default: false,
            description:
              "When true, simulates a strict position-reducing order that never increases directional exposure.",
          },
          post_only: {
            type: "boolean",
            default: false,
            description:
              "When true, constrains a GTC limit order simulation to strict maker-only ('post_only') execution.",
          },
          post_only_slide: {
            type: "boolean",
            default: false,
            description:
              "When true, simulates passive 1-tick BBO sliding instead of rejection if a maker order would cross resting liquidity.",
          },
          margin_spot: {
            type: "boolean",
            default: false,
            description:
              "When true on a Spot market, simulates cross-margined Spot borrowing/collateralization under Eigen-SPAN.",
          },
          client_tag: {
            type: "integer",
            minimum: 0,
            default: 0,
            description:
              "Optional unsigned strategy/OCO client tag (0 = untagged).",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_get_account",
      title: "Get Authenticated Account Portfolio",
      description:
        "Inspect an authenticated account's USD collateral (1 micro = $1e-6), Eigen-SPAN total equity, free/withdrawable margin, initial/maintenance margin requirements (IMR/MMR), active positions, and resting open orders via HMAC-SHA256 signed GET /account. Read-only; requires FERATERRA_API_KEY and FERATERRA_API_SECRET (use feraterra_get_leaderboard instead for public account rankings).",
      inputSchema: {
        type: "object",
        properties: {
          account_id: {
            type: "integer",
            minimum: 1,
            description:
              "Target FeraTerra trader account ID (>= 1); defaults to FERATERRA_ACCOUNT_ID when omitted.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_place_order",
      title: "Place Authenticated CLOB Order",
      description:
        "Submit a live authenticated single-leg limit or market order via HMAC-SHA256 signed POST /order. Mutates L3 order book, Eigen-SPAN margin locks, and WAL state; call feraterra_preview_order first for a zero-mutation dry run, or use feraterra_replace_quote for atomic two-sided bid+ask market-making. Provide mutually exclusive market (symbol vs market_id), price (price_usd vs price_ticks), and size (amount_base vs qty_lots) fields.",
      inputSchema: {
        type: "object",
        required: ["side"],
        properties: {
          account_id: {
            type: "integer",
            minimum: 1,
            description:
              "Authenticated trading account ID (>= 1); defaults to FERATERRA_ACCOUNT_ID when omitted.",
          },
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP', 'BTC/USD:USD', or 'ETH-USD-SPOT'); mutually exclusive with market_id.",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1); mutually exclusive with symbol.",
          },
          side: {
            type: "string",
            enum: ["buy", "sell", "bid", "ask"],
            description:
              "Order execution side: 'buy'/'bid' (long/buy) or 'sell'/'ask' (short/sell).",
          },
          order_type: {
            type: "string",
            enum: ["limit", "market"],
            default: "limit",
            description:
              "Order execution type: 'limit' (resting or crossing limit order, default) or 'market' (immediate IOC sweep).",
          },
          is_market: {
            type: "boolean",
            default: false,
            description:
              "When true, submits an immediate market sweep order (defaults tif to 'ioc' and allows 0 limit price).",
          },
          price_usd: {
            type: ["string", "number"],
            description:
              "Exact limit price in USD decimal string or number (e.g. '70000.00', exact multiple of $0.01); mutually exclusive with price_ticks (optional when is_market=true).",
          },
          price_ticks: {
            type: "integer",
            description:
              "Limit price in fixed-point integer ticks (1 tick = $0.01; 0 allowed for market orders; SpreadBook par = 1000000); mutually exclusive with price_usd.",
          },
          amount_base: {
            type: ["string", "number"],
            description:
              "Order quantity in exact base-asset decimal string or number (e.g. '0.1000', exact multiple of 0.0001); mutually exclusive with qty_lots.",
          },
          qty_lots: {
            type: "integer",
            minimum: 1,
            description:
              "Order quantity in fixed-point integer lots (1 lot = 1e-4 base unit, minimum 1); mutually exclusive with amount_base.",
          },
          tif: {
            type: "string",
            enum: ["gtc", "ioc", "fok", "post_only"],
            default: "gtc",
            description:
              "Time-in-force policy: 'gtc' (Good-Til-Cancelled), 'ioc' (Immediate-Or-Cancel), 'fok' (Fill-Or-Kill), or 'post_only' (maker-only).",
          },
          stp: {
            type: "string",
            enum: ["cancel_resting", "cancel_incoming", "cancel_both", "decrement_and_cancel", "none"],
            default: "cancel_resting",
            description:
              "Self-Trade Prevention mode applied if this order crosses resting orders from the same account.",
          },
          reduce_only: {
            type: "boolean",
            default: false,
            description:
              "When true, strictly reduces an existing open position and never increases directional exposure.",
          },
          post_only: {
            type: "boolean",
            default: false,
            description:
              "When true, upgrades a GTC limit order to strict maker-only ('post_only') execution.",
          },
          post_only_slide: {
            type: "boolean",
            default: false,
            description:
              "When true, slides a crossing maker order 1 tick passive of the opposing BBO instead of rejecting.",
          },
          client_tag: {
            type: "integer",
            minimum: 0,
            description:
              "Optional unsigned strategy/group tag (0 = untagged) used for OCO linking and tag-filtered batch cancels.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_replace_quote",
      title: "Replace Two-Sided Maker Quote",
      description:
        "Atomically cancel and replace both resting Bid and Ask maker quotes on a single market in 1 WAL step via HMAC-SHA256 signed POST /quote. Mutates resting maker quotes; prefer this over two separate feraterra_place_order calls when market-making. Provide mutually exclusive market (symbol vs market_id), bid/ask price (*_price_usd vs *_price_ticks), and bid/ask size (*_amount_base vs *_qty_lots) fields.",
      inputSchema: {
        type: "object",
        properties: {
          account_id: {
            type: "integer",
            minimum: 1,
            description:
              "Authenticated market-maker account ID (>= 1); defaults to FERATERRA_ACCOUNT_ID when omitted.",
          },
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP' or 'BTC/USD:USD'); mutually exclusive with market_id.",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1); mutually exclusive with symbol.",
          },
          bid_price_usd: {
            type: ["string", "number"],
            description:
              "Exact Bid quote price in USD decimal string or number (e.g. '69995.00', multiple of $0.01); mutually exclusive with bid_price_ticks.",
          },
          bid_price_ticks: {
            type: "integer",
            description:
              "Bid quote price in fixed-point integer ticks (1 tick = $0.01; 0 allowed when canceling bid side); mutually exclusive with bid_price_usd.",
          },
          bid_amount_base: {
            type: ["string", "number"],
            description:
              "Bid quote size in exact base units (e.g. '0.2500', multiple of 1e-4; '0' cancels resting bid without posting a new bid); mutually exclusive with bid_qty_lots.",
          },
          bid_qty_lots: {
            type: "integer",
            minimum: 0,
            description:
              "Bid quote size in fixed-point integer lots (1 lot = 1e-4 base, 0 = cancel resting bid side only); mutually exclusive with bid_amount_base.",
          },
          ask_price_usd: {
            type: ["string", "number"],
            description:
              "Exact Ask quote price in USD decimal string or number (e.g. '70005.00', multiple of $0.01); mutually exclusive with ask_price_ticks.",
          },
          ask_price_ticks: {
            type: "integer",
            description:
              "Ask quote price in fixed-point integer ticks (1 tick = $0.01; 0 allowed when canceling ask side); mutually exclusive with ask_price_usd.",
          },
          ask_amount_base: {
            type: ["string", "number"],
            description:
              "Ask quote size in exact base units (e.g. '0.2500', multiple of 1e-4; '0' cancels resting ask without posting a new ask); mutually exclusive with ask_qty_lots.",
          },
          ask_qty_lots: {
            type: "integer",
            minimum: 0,
            description:
              "Ask quote size in fixed-point integer lots (1 lot = 1e-4 base, 0 = cancel resting ask side only); mutually exclusive with ask_amount_base.",
          },
          tif: {
            type: "string",
            enum: ["gtc", "post_only", "ioc", "fok"],
            default: "post_only",
            description:
              "Time-in-force applied to both Bid and Ask quote legs (default 'post_only' for strict maker-only quoting).",
          },
          stp: {
            type: "string",
            enum: ["cancel_resting", "cancel_incoming", "cancel_both", "none"],
            default: "cancel_resting",
            description:
              "Self-Trade Prevention policy applied to both Bid and Ask quote legs.",
          },
          post_only_slide: {
            type: "boolean",
            default: false,
            description:
              "When true, slides any crossing quote leg 1 tick passive of the opposing BBO instead of rejecting.",
          },
          client_tag: {
            type: "integer",
            minimum: 0,
            description:
              "Optional unsigned quote-slot tag (0 = default market quote slot) for tagged quote management.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_cancel_order",
      title: "Cancel Resting Order",
      description:
        "Idempotently cancel one specific resting open order by order_id on a single FeraTerra market via HMAC-SHA256 signed POST /cancel. Removes the resting order without closing filled positions; use feraterra_cancel_all_orders for batch cancellation across markets/sides/tags, or submit a reduce_only feraterra_place_order to close an open position. Provide either symbol or market_id alongside order_id.",
      inputSchema: {
        type: "object",
        required: ["order_id"],
        properties: {
          account_id: {
            type: "integer",
            minimum: 1,
            description:
              "Authenticated account ID (>= 1) owning the resting order; defaults to FERATERRA_ACCOUNT_ID when omitted.",
          },
          symbol: {
            type: "string",
            description:
              "Unified or native market symbol (e.g. 'BTC-USD-PERP' or 'BTC/USD:USD'); required when market_id is omitted and mutually exclusive with market_id.",
          },
          market_id: {
            type: "integer",
            minimum: 1,
            description:
              "Numeric FeraTerra market identifier (>= 1) where the order rests; mutually exclusive with symbol.",
          },
          order_id: {
            type: "integer",
            minimum: 1,
            description:
              "Unique positive integer order_id of the resting open order to cancel.",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_cancel_all_orders",
      title: "Cancel All Resting Orders",
      description:
        "Idempotently batch-cancel resting open orders for an authenticated account across all markets or filtered by market, side, client_tag_filter, or market_bitmask via HMAC-SHA256 signed POST /cancel_all. Removes resting orders without closing filled positions; use feraterra_cancel_order instead to cancel a single order_id.",
      inputSchema: {
        type: "object",
        properties: {
          account_id: {
            type: "integer",
            minimum: 1,
            description:
              "Authenticated account ID (>= 1) whose resting orders will be cancelled; defaults to FERATERRA_ACCOUNT_ID when omitted.",
          },
          symbol: {
            type: "string",
            description:
              "Optional unified or native market symbol scope (e.g. 'BTC-USD-PERP'); mutually exclusive with market_id (omit both to cancel across all markets).",
          },
          market_id: {
            type: "integer",
            minimum: 0,
            default: 0,
            description:
              "Market ID scope (0 = cancel across all markets, >= 1 = single market); mutually exclusive with symbol.",
          },
          side: {
            type: "string",
            enum: ["", "buy", "sell", "bid", "ask"],
            default: "",
            description:
              "Optional side filter: '' (both sides, default), 'buy'/'bid' (bids only), or 'sell'/'ask' (asks only).",
          },
          client_tag_filter: {
            type: "integer",
            minimum: 0,
            description:
              "Optional strategy client_tag filter (0 or omitted = cancel all tags, > 0 = cancel only orders matching client_tag).",
          },
          market_bitmask: {
            type: "integer",
            minimum: 0,
            description:
              "Optional unsigned bitmask of market IDs for multi-market selective cancellation (0 or omitted = no bitmask filter).",
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "feraterra_convert_units",
      title: "Convert Fixed-Point Ticks, Lots & Micro-USD",
      description:
        "Pure offline fixed-point unit converter between human-readable decimal USD/base values and FeraTerra exact integer ticks (1 tick = $0.01 USD), lots (1 lot = 0.0001 base unit), and micro-USD (1 micro = $1e-6 USD). Read-only and zero-network; use this to verify exact fixed-point integer representations before submitting raw ticks, lots, or micro-USD.",
      inputSchema: {
        type: "object",
        properties: {
          usd: {
            type: ["string", "number"],
            description:
              "Exact USD decimal string or number (e.g. '70000.25') to convert into integer price ticks ($0.01) and micro-USD ($1e-6).",
          },
          ticks: {
            type: "integer",
            description:
              "Fixed-point integer price ticks (1 tick = $0.01 USD, e.g. 7000025) to format as an exact USD decimal string.",
          },
          base: {
            type: ["string", "number"],
            description:
              "Exact base-asset decimal quantity (e.g. '0.2500') to convert into fixed-point integer lots (1 lot = 1e-4 base unit).",
          },
          lots: {
            type: "integer",
            description:
              "Fixed-point integer quantity lots (1 lot = 1e-4 base unit, e.g. 2500) to format as an exact base-asset decimal string.",
          },
          micro_usd: {
            type: "integer",
            description:
              "Fixed-point integer micro-USD collateral units (1 micro = $1e-6 USD, e.g. 35500000) to format as an exact USD decimal string.",
          },
        },
        additionalProperties: false,
      },
    },
  ];

  return raw.map((spec) => ({
    name: spec.name,
    title: spec.title,
    description: spec.description,
    inputSchema: spec.inputSchema,
    annotations: buildToolAnnotations(spec.name, spec.title),
  }));
}

const ALL_TOOLS = Object.freeze(buildToolDefinitions());
const ALL_TOOL_NAMES = new Set(ALL_TOOLS.map((t) => t.name));
const ARENA_TOOL_ALIASES = Object.freeze({
  arena_health_and_manifest: "feraterra_health_and_manifest",
  arena_list_markets: "feraterra_list_markets",
  arena_get_orderbook: "feraterra_get_orderbook",
  arena_get_trades: "feraterra_get_trades",
  arena_get_candles: "feraterra_get_candles",
  arena_get_leaderboard: "feraterra_get_leaderboard",
  arena_verify_ledger_tip: "feraterra_verify_ledger_tip",
  arena_preview_order: "feraterra_preview_order",
  arena_get_account_portfolio: "feraterra_get_account",
  arena_place_order: "feraterra_place_order",
  arena_replace_two_sided_quote: "feraterra_replace_quote",
  arena_cancel_order: "feraterra_cancel_order",
  arena_cancel_all: "feraterra_cancel_all_orders",
});

export class FeraTerraMcpServer {
  constructor(options = {}) {
    this.client = options.client instanceof FeraTerraClient ? options.client : new FeraTerraClient(options);
    this.readOnly =
      options.readOnly !== undefined && options.readOnly !== null
        ? strictBool(options.readOnly, false)
        : resolveEnvBool(process.env.FERATERRA_READ_ONLY, false);
    this._secrets = [this.client._apiKey, this.client._apiSecret].filter((s) => Boolean(s));
  }

  listTools() {
    if (this.readOnly) {
      return ALL_TOOLS.filter((t) => READ_ONLY_TOOL_NAMES.has(t.name));
    }
    return [...ALL_TOOLS];
  }

  listResources() {
    return [
      {
        uri: "feraterra://markets/directory",
        name: "FeraTerra Live Market Directory",
        title: "FeraTerra Live Market Directory",
        description:
          "Active CLOB perpetual, spot, basis spread, and bounded claim markets with USD mark prices and BBOs.",
        mimeType: "application/json",
      },
      {
        uri: "feraterra://ledger/tip",
        name: "FeraTerra Verified WAL Ledger Tip",
        title: "FeraTerra Verified WAL Ledger Tip",
        description:
          "Cryptographically verified ARENA_LEDGER_TIP_V2_1 Keccak-256 state root and secp256k1 operator signature.",
        mimeType: "application/json",
      },
      {
        uri: "feraterra://protocol/terms",
        name: "FeraTerra Headless Protocol Terms",
        title: "FeraTerra Headless Protocol Terms & Risk Disclosures",
        description:
          "Machine-readable headless protocol Terms of Service, non-custodial L2 collateral vault escape guarantees, and risk disclosures via GET /terms.",
        mimeType: "application/json",
      },
      {
        uri: "feraterra://server/config",
        name: "FeraTerra MCP Gateway Configuration",
        title: "FeraTerra MCP Gateway Configuration",
        description: "Active gateway base URL, read-only posture, and remote Streamable HTTP MCP endpoint.",
        mimeType: "application/json",
      },
    ];
  }

  listResourceTemplates() {
    return [];
  }

  async readResource(uri) {
    let payload;
    if (uri === "feraterra://markets/directory") {
      payload = await this.client.listMarkets({ activeOnly: true });
    } else if (uri === "feraterra://ledger/tip") {
      payload = await this.client.verifySolvency({ includeHealth: true });
    } else if (uri === "feraterra://protocol/terms") {
      payload = await this.client.getTerms();
    } else if (uri === "feraterra://server/config") {
      payload = {
        server: SERVER_NAME,
        version: SERVER_VERSION,
        base_url: this.client.baseUrl,
        remote_mcp_url: REMOTE_FERATERRA_MCP_URL,
        account_id: this.client.accountId,
        authenticated: this.client.hasCredentials(),
        read_only: this.readOnly,
      };
    } else {
      const err = new Error(`Unknown resource URI: ${String(uri)}`);
      err.code = -32602;
      throw err;
    }
    const clean = scrubValue(payload, this._secrets);
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(clean, null, 2),
        },
      ],
    };
  }

  listPrompts() {
    const prompts = [
      {
        name: "audit_exchange_solvency",
        title: "Cryptographic Solvency & WAL Ledger-Tip Audit",
        description:
          "Verify FeraTerra double-entry conservation invariants and the Keccak-256 + secp256k1 operator-signed WAL ledger tip.",
        arguments: [
          {
            name: "expected_operator_address",
            description: "Optional pinned 0x... operator Ethereum address.",
            required: false,
          },
        ],
      },
      {
        name: "preview_and_execute_order",
        title: "Stateless Order Preview & Safe Execution Workflow",
        description:
          "Inspect live order book spread, simulate pre-trade fill and margin impact via feraterra_preview_order, and place a bounded order.",
        arguments: [
          {
            name: "symbol",
            description: "Target market symbol (e.g. BTC-USD-PERP).",
            required: true,
          },
          {
            name: "side",
            description: "Order side (buy or sell).",
            required: true,
          },
          {
            name: "amount_base",
            description: "Order quantity in base units (e.g. 0.05).",
            required: true,
          },
        ],
      },
      {
        name: "inspect_market_microstructure",
        title: "Inspect CLOB Microstructure & Liquidity",
        description:
          "Analyze L2 order book depth, spread, recent executions, and 1m OHLCV candles for a FeraTerra market.",
        arguments: [
          {
            name: "symbol",
            description: "Market symbol (e.g. BTC-USD-PERP or ETH-USD-SPOT).",
            required: true,
          },
        ],
      },
    ];
    if (this.readOnly) {
      return prompts.filter((p) => !MUTATING_PROMPT_NAMES.has(p.name));
    }
    return prompts;
  }

  getPrompt(name, args = {}) {
    if (this.readOnly && MUTATING_PROMPT_NAMES.has(name)) {
      const err = new Error(`read_only_mode_enabled: mutating prompt ${String(name)} is disabled`);
      err.code = -32602;
      throw err;
    }
    if (name === "audit_exchange_solvency") {
      const pinned = String(args?.expected_operator_address || this.client.expectedOperatorAddress || "").trim();
      const pinNote = pinned
        ? `passing expected_operator_address="${pinned}"`
        : "verifying the recovered secp256k1 operator signer";
      return {
        description: "Cryptographic FeraTerra solvency and WAL ledger-tip audit.",
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `Audit FeraTerra solvency by calling feraterra_verify_ledger_tip (${pinNote} and include_health=true). ` +
                "Confirm solvent=true, digest_verified=true, signature_verified=true, and conservation_ok=true, then report the WAL sequence, state_root, and recovered operator address.",
            },
          },
        ],
      };
    }
    if (name === "preview_and_execute_order") {
      const symbol = String(args?.symbol || "BTC-USD-PERP").trim();
      const side = String(args?.side || "buy").trim();
      const amountBase = String(args?.amount_base || "0.01").trim();
      return {
        description: `Safe pre-trade simulation and execution workflow for ${symbol}.`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `1. Call feraterra_get_orderbook for ${symbol} to inspect best bid, best ask, and spread.\n` +
                `2. Call feraterra_preview_order for ${side} ${amountBase} ${symbol} to verify would_accept, estimated fees, and post-trade margin.\n` +
                "3. Only if would_accept=true and HMAC credentials are configured, submit via feraterra_place_order.",
            },
          },
        ],
      };
    }
    if (name === "inspect_market_microstructure") {
      const symbol = String(args?.symbol || "BTC-USD-PERP").trim();
      return {
        description: `CLOB microstructure analysis for ${symbol}.`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `Inspect ${symbol} microstructure on FeraTerra by calling feraterra_get_orderbook (depth=20), ` +
                "feraterra_get_trades (limit=25), and feraterra_get_candles (interval='1m', limit=30). Summarize spread, top-of-book liquidity, and recent price action.",
            },
          },
        ],
      };
    }
    const err = new Error(`Unknown prompt: ${String(name)}`);
    err.code = -32602;
    throw err;
  }

  _okResult(data) {
    const clean = scrubValue(data, this._secrets);
    const structured =
      clean && typeof clean === "object" && !Array.isArray(clean) ? clean : { result: clean };
    return {
      content: [{ type: "text", text: JSON.stringify(clean, null, 2) }],
      structuredContent: structured,
      isError: false,
    };
  }

  _errorResult(err) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: scrubText(rawMsg, this._secrets) }],
      isError: true,
    };
  }

  async callTool(rawName, rawArgs = {}) {
    const args = rawArgs && typeof rawArgs === "object" ? rawArgs : {};
    let name = rawName;
    if (rawName === "arena_cancel_orders") {
      const oid = Number(args.order_id ?? 0);
      let cancelAllFlag;
      try {
        cancelAllFlag = strictBool(args.cancel_all, false);
      } catch (err) {
        return this._errorResult(err);
      }
      const doAll = cancelAllFlag || !(oid > 0);
      name = doAll ? "feraterra_cancel_all_orders" : "feraterra_cancel_order";
    } else if (Object.prototype.hasOwnProperty.call(ARENA_TOOL_ALIASES, rawName)) {
      name = ARENA_TOOL_ALIASES[rawName];
    }
    if (!ALL_TOOL_NAMES.has(name)) {
      const err = new Error(`Unknown tool: ${String(rawName)}`);
      err.code = -32602;
      throw err;
    }
    if (this.readOnly && !READ_ONLY_TOOL_NAMES.has(name)) {
      return this._errorResult(`read_only_mode_enabled: mutating tool ${name} is disabled`);
    }
    try {
      switch (name) {
        case "feraterra_health_and_manifest":
          return this._okResult(await this.client.getHealthAndManifest(args));
        case "feraterra_list_markets":
          return this._okResult(await this.client.listMarkets(args));
        case "feraterra_get_orderbook":
          return this._okResult(await this.client.getOrderbook(args));
        case "feraterra_get_trades":
          return this._okResult(await this.client.getTrades(args));
        case "feraterra_get_candles":
          return this._okResult(await this.client.getCandles(args));
        case "feraterra_get_leaderboard":
          return this._okResult(await this.client.getLeaderboard(args));
        case "feraterra_verify_ledger_tip": {
          const res = await this.client.verifySolvency(args);
          if (!res.solvent) {
            return {
              content: [{ type: "text", text: JSON.stringify(scrubValue(res, this._secrets), null, 2) }],
              structuredContent: scrubValue(res, this._secrets),
              isError: true,
            };
          }
          return this._okResult(res);
        }
        case "feraterra_preview_order": {
          const explicitAid = args.account_id ?? args.accountId;
          const isZeroKeyPreview =
            explicitAid === 0 ||
            explicitAid === "0" ||
            ((explicitAid === undefined || explicitAid === null) &&
              (!this.client.hasCredentials() || this.client.accountId <= 0));
          try {
            return this._okResult(await this.client.previewOrder(args));
          } catch (prevErr) {
            const errCodeLc = String(prevErr?.code || "").trim().toLowerCase();
            const errMsgLc = String(prevErr?.message || prevErr || "").toLowerCase();
            const httpStatus = Number(prevErr?.status || 0);
            const isLegacyAuthBlock =
              isZeroKeyPreview &&
              !this.client.hasCredentials() &&
              (httpStatus === 401 ||
                ["missing_auth_headers", "missing_auth", "unauthorized", "invalid_account_id", "account_id_required"].includes(
                  errCodeLc
                ) ||
                errMsgLc.includes("missing_auth_headers") ||
                errMsgLc.includes("invalid_account_id"));
            if (isLegacyAuthBlock) {
              return this._okResult({
                ok: false,
                preview: true,
                stateless_zero_key: true,
                account_id: 0,
                would_accept: false,
                auth_required: true,
                http_status: httpStatus || 401,
                error: errCodeLc || "missing_auth_headers",
                local_mcp_command: "npx -y feraterra-mcp",
                hint:
                  "This backend requires an authenticated account for POST /order/preview; configure FERATERRA_ACCOUNT_ID, FERATERRA_API_KEY, and FERATERRA_API_SECRET or target a v4.9.5+ gateway supporting stateless account_id=0 previews.",
              });
            }
            throw prevErr;
          }
        }
        case "feraterra_get_account":
          return this._okResult(await this.client.getAccount(args));
        case "feraterra_place_order":
          return this._okResult(await this.client.placeOrder(args));
        case "feraterra_replace_quote": {
          const effTif =
            args.tif !== undefined && args.tif !== null && String(args.tif).trim() !== ""
              ? args.tif
              : "post_only";
          return this._okResult(await this.client.replaceQuote({ ...args, tif: effTif }));
        }
        case "feraterra_cancel_order":
          return this._okResult(await this.client.cancelOrder(args));
        case "feraterra_cancel_all_orders":
          return this._okResult(await this.client.cancelAllOrders(args));
        case "feraterra_convert_units": {
          const out = { ok: true };
          if (args.usd !== undefined) {
            out.usd_to_ticks = usdToTicks(args.usd);
            out.usd_to_micro = usdToMicro(args.usd);
          }
          if (args.ticks !== undefined) {
            out.ticks_to_usd = ticksToUsd(args.ticks);
          }
          if (args.base !== undefined) {
            out.base_to_lots = baseToLots(args.base);
          }
          if (args.lots !== undefined) {
            out.lots_to_base = lotsToBase(args.lots);
          }
          if (args.micro_usd !== undefined) {
            out.micro_to_usd = microToUsd(args.micro_usd);
          }
          return this._okResult(out);
        }
        default:
          return this._errorResult(`Unhandled tool: ${name}`);
      }
    } catch (err) {
      return this._errorResult(err);
    }
  }

  async handleJsonRpcMessage(msg) {
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
      return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } };
    }
    const hasId = Object.prototype.hasOwnProperty.call(msg, "id");
    const reqId = hasId ? msg.id : null;
    if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
      if (!hasId) return null;
      return { jsonrpc: "2.0", id: reqId, error: { code: -32600, message: "Invalid Request" } };
    }
    const method = msg.method;
    const params = msg.params;
    if (params !== undefined && params !== null && (typeof params !== "object" || Array.isArray(params))) {
      if (!hasId) return null;
      return { jsonrpc: "2.0", id: reqId, error: { code: -32602, message: "Invalid params" } };
    }
    const p = params || {};

    if (!hasId) {
      return null;
    }

    if (method === "initialize") {
      const requested = typeof p.protocolVersion === "string" ? p.protocolVersion.trim() : "";
      const negotiated = SUPPORTED_MCP_PROTOCOL_VERSIONS.includes(requested)
        ? requested
        : DEFAULT_MCP_PROTOCOL_VERSION;
      return {
        jsonrpc: "2.0",
        id: reqId,
        result: {
          protocolVersion: negotiated,
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
            prompts: { listChanged: false },
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
          },
          instructions:
            "FeraTerra sovereign CLOB MCP server. Use feraterra_health_and_manifest, feraterra_list_markets, and feraterra_get_orderbook to inspect live gateway health and markets, feraterra_verify_ledger_tip to cryptographically verify ARENA_LEDGER_TIP_V2_1 solvency, feraterra://protocol/terms (GET /terms) for headless protocol disclosures, and feraterra_preview_order (or alias arena_preview_order with account_id=0) for zero-key, zero-mutation pre-trade order & Eigen-SPAN IMR simulations before placing orders.",
        },
      };
    }

    if (method === "ping") {
      return { jsonrpc: "2.0", id: reqId, result: {} };
    }

    if (method === "tools/list") {
      return { jsonrpc: "2.0", id: reqId, result: { tools: this.listTools() } };
    }

    if (method === "tools/call") {
      const toolName = p.name;
      const toolArgs = p.arguments;
      if (typeof toolName !== "string" || !toolName) {
        return { jsonrpc: "2.0", id: reqId, error: { code: -32602, message: "Missing tool name" } };
      }
      if (toolArgs !== undefined && toolArgs !== null && (typeof toolArgs !== "object" || Array.isArray(toolArgs))) {
        return {
          jsonrpc: "2.0",
          id: reqId,
          error: { code: -32602, message: "Tool arguments must be an object" },
        };
      }
      try {
        const result = await this.callTool(toolName, toolArgs || {});
        return { jsonrpc: "2.0", id: reqId, result };
      } catch (err) {
        const code = typeof err?.code === "number" ? err.code : -32603;
        return {
          jsonrpc: "2.0",
          id: reqId,
          error: { code, message: scrubText(err?.message || String(err), this._secrets) },
        };
      }
    }

    if (method === "resources/list") {
      return { jsonrpc: "2.0", id: reqId, result: { resources: this.listResources() } };
    }

    if (method === "resources/templates/list") {
      return { jsonrpc: "2.0", id: reqId, result: { resourceTemplates: this.listResourceTemplates() } };
    }

    if (method === "resources/read") {
      const uri = p.uri;
      if (typeof uri !== "string" || !uri) {
        return { jsonrpc: "2.0", id: reqId, error: { code: -32602, message: "Missing resource uri" } };
      }
      try {
        const result = await this.readResource(uri);
        return { jsonrpc: "2.0", id: reqId, result };
      } catch (err) {
        const code = typeof err?.code === "number" ? err.code : -32603;
        return {
          jsonrpc: "2.0",
          id: reqId,
          error: { code, message: scrubText(err?.message || String(err), this._secrets) },
        };
      }
    }

    if (method === "prompts/list") {
      return { jsonrpc: "2.0", id: reqId, result: { prompts: this.listPrompts() } };
    }

    if (method === "prompts/get") {
      const promptName = p.name;
      const promptArgs = p.arguments;
      if (typeof promptName !== "string" || !promptName) {
        return { jsonrpc: "2.0", id: reqId, error: { code: -32602, message: "Missing prompt name" } };
      }
      if (
        promptArgs !== undefined &&
        promptArgs !== null &&
        (typeof promptArgs !== "object" || Array.isArray(promptArgs))
      ) {
        return {
          jsonrpc: "2.0",
          id: reqId,
          error: { code: -32602, message: "Prompt arguments must be an object" },
        };
      }
      try {
        const result = this.getPrompt(promptName, promptArgs || {});
        return { jsonrpc: "2.0", id: reqId, result };
      } catch (err) {
        const code = typeof err?.code === "number" ? err.code : -32602;
        return {
          jsonrpc: "2.0",
          id: reqId,
          error: { code, message: scrubText(err?.message || String(err), this._secrets) },
        };
      }
    }

    return {
      jsonrpc: "2.0",
      id: reqId,
      error: { code: -32601, message: `Method not found: ${method}` },
    };
  }

  async dispatchRawPayload(rawUtf8) {
    let decoded;
    try {
      decoded = JSON.parse(rawUtf8);
    } catch {
      return { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } };
    }
    if (Array.isArray(decoded)) {
      if (decoded.length === 0) {
        return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } };
      }
      if (decoded.length > MAX_BATCH_REQUESTS) {
        return {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32600, message: `Batch exceeds ${MAX_BATCH_REQUESTS} requests` },
        };
      }
      const replies = [];
      for (const item of decoded) {
        const rep = await this.handleJsonRpcMessage(item);
        if (rep !== null) replies.push(rep);
      }
      return replies.length > 0 ? replies : null;
    }
    return this.handleJsonRpcMessage(decoded);
  }
}

function writeStdioFrame(stdoutStream, payloadObjOrJson, useContentLength) {
  const compactJson =
    typeof payloadObjOrJson === "string"
      ? JSON.stringify(JSON.parse(payloadObjOrJson))
      : JSON.stringify(payloadObjOrJson);
  const jsonBytes = Buffer.from(compactJson, "utf8");
  if (useContentLength) {
    const header = Buffer.from(`Content-Length: ${jsonBytes.length}\r\n\r\n`, "ascii");
    stdoutStream.write(Buffer.concat([header, jsonBytes]));
  } else {
    stdoutStream.write(Buffer.concat([jsonBytes, Buffer.from("\n", "utf8")]));
  }
}

function findHeaderBoundary(buf) {
  const crlfIdx = buf.indexOf("\r\n\r\n");
  const lfIdx = buf.indexOf("\n\n");
  if (crlfIdx !== -1 && (lfIdx === -1 || crlfIdx <= lfIdx)) {
    return { headerEnd: crlfIdx, sepLen: 4 };
  }
  if (lfIdx !== -1) {
    return { headerEnd: lfIdx, sepLen: 2 };
  }
  return null;
}

function parseContentLengthHeader(headerBlock) {
  let contentLength = -1;
  for (const hLine of headerBlock.split(/\r?\n/)) {
    const trimmed = hLine.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx === -1) {
      return { valid: false, contentLength: -1 };
    }
    const hk = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const hv = trimmed.slice(colonIdx + 1).trim();
    if (hk === "content-length") {
      if (!/^\d+$/.test(hv)) {
        return { valid: false, contentLength: -1 };
      }
      contentLength = Number.parseInt(hv, 10);
    }
  }
  if (
    !Number.isSafeInteger(contentLength) ||
    contentLength <= 0 ||
    contentLength > MAX_STDIO_MESSAGE_BYTES
  ) {
    return { valid: false, contentLength };
  }
  return { valid: true, contentLength };
}

export function serveMcpStdio(server, stdinStream = process.stdin, stdoutStream = process.stdout) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let queue = Promise.resolve();
    let ended = false;

    const enqueueFrame = (rawUtf8, useContentLength) => {
      queue = queue
        .then(async () => {
          const reply = await server.dispatchRawPayload(rawUtf8);
          if (reply !== null) {
            writeStdioFrame(stdoutStream, reply, useContentLength);
          }
        })
        .catch((err) => {
          writeStdioFrame(
            stdoutStream,
            {
              jsonrpc: "2.0",
              id: null,
              error: { code: -32603, message: scrubText(err?.message || String(err), server._secrets) },
            },
            useContentLength
          );
        });
    };

    const enqueueErrorFrame = (message, useContentLength) => {
      queue = queue.then(() => {
        writeStdioFrame(
          stdoutStream,
          { jsonrpc: "2.0", id: null, error: { code: -32700, message } },
          useContentLength
        );
      });
    };

    const drainBuffer = () => {
      while (buffer.length > 0) {
        // Trim leading CR/LF whitespace between frames
        let startIdx = 0;
        while (startIdx < buffer.length && (buffer[startIdx] === 0x0d || buffer[startIdx] === 0x0a)) {
          startIdx += 1;
        }
        if (startIdx > 0) {
          buffer = buffer.subarray(startIdx);
        }
        if (buffer.length === 0) break;

        // Skip leading horizontal whitespace (0x20 space / 0x09 tab) before JSONL vs Content-Length detection
        let firstNonWs = 0;
        while (
          firstNonWs < buffer.length &&
          (buffer[firstNonWs] === 0x20 || buffer[firstNonWs] === 0x09)
        ) {
          firstNonWs += 1;
        }
        if (firstNonWs >= buffer.length) {
          if (buffer.length > MAX_STDIO_MESSAGE_BYTES) {
            buffer = Buffer.alloc(0);
            enqueueErrorFrame("MCP frame exceeds 4 MiB safety limit", false);
          } else if (ended) {
            buffer = Buffer.alloc(0);
          }
          break;
        }

        const firstByte = buffer[firstNonWs];
        const isJsonLine = firstByte === 0x7b /* { */ || firstByte === 0x5b; /* [ */

        if (isJsonLine) {
          const nlIdx = buffer.indexOf(0x0a);
          if (nlIdx === -1) {
            if (buffer.length > MAX_STDIO_MESSAGE_BYTES) {
              buffer = Buffer.alloc(0);
              enqueueErrorFrame("MCP frame exceeds 4 MiB safety limit", false);
              break;
            }
            if (ended) {
              const trailing = buffer.toString("utf8").trim();
              buffer = Buffer.alloc(0);
              if (trailing) {
                enqueueFrame(trailing, false);
              }
            }
            break;
          }
          if (nlIdx > MAX_STDIO_MESSAGE_BYTES) {
            buffer = Buffer.alloc(0);
            enqueueErrorFrame("MCP frame exceeds 4 MiB safety limit", false);
            break;
          }
          const lineUtf8 = buffer.subarray(0, nlIdx).toString("utf8").trim();
          buffer = buffer.subarray(nlIdx + 1);
          if (lineUtf8) {
            enqueueFrame(lineUtf8, false);
          }
          continue;
        }

        // Content-Length LSP framing
        const boundary = findHeaderBoundary(buffer);
        if (!boundary) {
          if (buffer.length > MAX_HEADER_BLOCK_BYTES || ended) {
            buffer = Buffer.alloc(0);
            enqueueErrorFrame("Malformed or incomplete Content-Length header", true);
          }
          break;
        }
        if (boundary.headerEnd > MAX_HEADER_BLOCK_BYTES) {
          buffer = Buffer.alloc(0);
          enqueueErrorFrame("Content-Length header exceeds bounds", true);
          break;
        }
        const headerText = buffer.subarray(0, boundary.headerEnd).toString("ascii");
        const parsedHeader = parseContentLengthHeader(headerText);
        if (!parsedHeader.valid) {
          buffer = Buffer.alloc(0);
          enqueueErrorFrame(
            parsedHeader.contentLength > MAX_STDIO_MESSAGE_BYTES
              ? "Content-Length out of bounds"
              : "Invalid Content-Length header",
            true
          );
          break;
        }
        const bodyStart = boundary.headerEnd + boundary.sepLen;
        const totalNeeded = bodyStart + parsedHeader.contentLength;
        if (buffer.length < totalNeeded) {
          if (ended) {
            buffer = Buffer.alloc(0);
            enqueueErrorFrame("Incomplete Content-Length body at EOF", true);
          }
          break;
        }
        const bodyUtf8 = buffer.subarray(bodyStart, totalNeeded).toString("utf8");
        buffer = buffer.subarray(totalNeeded);
        enqueueFrame(bodyUtf8, true);
      }
    };

    stdinStream.on("data", (chunk) => {
      const bufChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      buffer = buffer.length === 0 ? bufChunk : Buffer.concat([buffer, bufChunk]);
      drainBuffer();
    });

    stdinStream.on("end", () => {
      if (ended) return;
      ended = true;
      drainBuffer();
      queue.then(() => resolve(0)).catch(reject);
    });

    stdinStream.on("error", (err) => {
      reject(err);
    });

    if (typeof stdinStream.resume === "function") {
      stdinStream.resume();
    }
  });
}

async function readSkillFrontmatterName(rawSkillText) {
  const memStream = Readable.from([rawSkillText]);
  const rl = readline.createInterface({
    input: memStream,
    crlfDelay: Infinity,
  });
  let inFrontmatter = false;
  let lineIndex = 0;
  try {
    for await (const line of rl) {
      const trimmed = line.trim();
      if (lineIndex === 0) {
        if (trimmed !== "---") {
          return "";
        }
        inFrontmatter = true;
        lineIndex += 1;
        continue;
      }
      if (inFrontmatter && trimmed === "---") {
        return "";
      }
      if (inFrontmatter && trimmed.startsWith("name:")) {
        return trimmed.slice("name:".length).trim();
      }
      lineIndex += 1;
    }
    return "";
  } finally {
    rl.close();
    memStream.destroy();
  }
}

export async function installSkillToDir(targetDir = process.cwd(), options = {}) {
  const opts =
    typeof options === "string"
      ? { bundledSkillPath: options }
      : options && typeof options === "object"
        ? options
        : {};
  const bundledSkillPath = opts.bundledSkillPath || BUNDLED_SKILL_PATH;
  if (!fs.existsSync(bundledSkillPath)) {
    throw new Error(`Bundled SKILL.md not found at ${bundledSkillPath}`);
  }
  const resolvedRoot = path.resolve(targetDir);
  const subdirs = [];
  if (strictBool(opts.claude, false)) {
    subdirs.push(".claude");
  }
  if (strictBool(opts.cursor, false)) {
    subdirs.push(".cursor");
  }
  if (strictBool(opts.codex, false)) {
    subdirs.push(".codex");
  }
  if (subdirs.length === 0) {
    subdirs.push(".agents");
  }

  const rawSkill = fs.readFileSync(bundledSkillPath, "utf8").replace(/\r\n/g, "\n");
  const skillName = await readSkillFrontmatterName(rawSkill);
  if (skillName !== "feraterra-trading") {
    throw new Error(`Bundled SKILL.md missing expected frontmatter name: ${skillName}`);
  }

  const installedPaths = [];
  for (const agentRoot of subdirs) {
    const destSkillPath = path.join(resolvedRoot, agentRoot, "skills", "feraterra-trading", "SKILL.md");
    fs.mkdirSync(path.dirname(destSkillPath), { recursive: true });
    fs.writeFileSync(destSkillPath, rawSkill, "utf8");
    installedPaths.push(destSkillPath);
  }

  return {
    ok: true,
    version: SERVER_VERSION,
    skill: skillName,
    installedPath: installedPaths[0],
    installedPaths,
    bytes: Buffer.byteLength(rawSkill, "utf8"),
  };
}

function inspectJsonRpcPayload(rawBytes) {
  const parsed = JSON.parse(rawBytes.toString("utf8"));
  if (Array.isArray(parsed)) {
    if (parsed.length === 0 || parsed.length > MAX_BATCH_REQUESTS) {
      throw new Error("Invalid JSON-RPC batch size");
    }
    const hasRequestId = parsed.some(
      (item) => item !== null && typeof item === "object" && Object.prototype.hasOwnProperty.call(item, "id")
    );
    return { valid: true, isNotificationOnly: !hasRequestId, requestId: null };
  }
  if (parsed !== null && typeof parsed === "object") {
    const hasId = Object.prototype.hasOwnProperty.call(parsed, "id");
    return {
      valid: true,
      isNotificationOnly: !hasId,
      requestId: hasId ? parsed.id : undefined,
    };
  }
  throw new Error("JSON-RPC payload must be a JSON object or batch array");
}

function extractSseJsonPayload(sseText) {
  const dataLines = [];
  for (const rawLine of sseText.split(/\r?\n/)) {
    if (rawLine.startsWith("data:")) {
      dataLines.push(rawLine.slice("data:".length).trim());
    }
  }
  for (let i = dataLines.length - 1; i >= 0; i -= 1) {
    if (dataLines[i].startsWith("{") || dataLines[i].startsWith("[")) {
      return dataLines[i];
    }
  }
  return "";
}

function postStreamableHttpMcp(targetUrlObj, bodyBuf, { bearerToken, sessionId, timeoutMs, agent }) {
  const isHttps = targetUrlObj.protocol === "https:";
  const transportMod = isHttps ? https : http;
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "Content-Length": String(bodyBuf.length),
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`,
  };
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }
  if (sessionId) {
    headers["Mcp-Session-Id"] = sessionId;
  }

  return new Promise((resolve, reject) => {
    const req = transportMod.request(
      targetUrlObj,
      {
        method: "POST",
        headers,
        timeout: timeoutMs,
        agent,
      },
      (res) => {
        const chunks = [];
        let total = 0;
        res.on("data", (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          total += buf.length;
          if (total > MAX_STDIO_MESSAGE_BYTES) {
            req.destroy(new Error("Upstream MCP HTTP response exceeded 4 MiB safety cap"));
            return;
          }
          chunks.push(buf);
        });
        res.on("end", () => {
          const respHeaderSession = res.headers["mcp-session-id"];
          const nextSessionId = Array.isArray(respHeaderSession)
            ? respHeaderSession[0]
            : respHeaderSession || "";
          resolve({
            statusCode: res.statusCode ?? 0,
            contentType: String(res.headers["content-type"] || "").toLowerCase(),
            sessionId: String(nextSessionId || "").trim(),
            bodyBuf: Buffer.concat(chunks),
          });
        });
        res.on("error", reject);
      }
    );
    req.on("timeout", () => {
      req.destroy(new Error(`Upstream MCP HTTP request timed out after ${timeoutMs} ms`));
    });
    req.on("error", reject);
    req.write(bodyBuf);
    req.end();
  });
}

export function bridgeMcpStdioToHttp({
  inputStream = process.stdin,
  outputStream = process.stdout,
  url = REMOTE_FERATERRA_MCP_URL,
  bearerToken = "",
  timeoutMs = DEFAULT_REMOTE_TIMEOUT_MS,
} = {}) {
  const validatedUrl = validateEndpointUrl(url, "mcpUrl");
  const targetUrlObj = new URL(validatedUrl);
  const httpAgent =
    targetUrlObj.protocol === "https:"
      ? new https.Agent({ keepAlive: true })
      : new http.Agent({ keepAlive: true });
  const secrets = bearerToken ? [bearerToken] : [];

  let recvBuf = Buffer.alloc(0);
  let inputEnded = false;
  let activeSessionId = "";
  let dispatchChain = Promise.resolve();

  const enqueueErrorFrame = (message, useContentLength) => {
    dispatchChain = dispatchChain.then(() => {
      writeStdioFrame(
        outputStream,
        { jsonrpc: "2.0", id: null, error: { code: -32700, message } },
        useContentLength
      );
    });
  };

  const enqueueFrame = (rawBodyBuf, useContentLength) => {
    dispatchChain = dispatchChain.then(async () => {
      let rpcMeta;
      try {
        rpcMeta = inspectJsonRpcPayload(rawBodyBuf);
      } catch (err) {
        writeStdioFrame(
          outputStream,
          {
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: `Invalid JSON-RPC frame: ${scrubText(err instanceof Error ? err.message : String(err), secrets)}`,
            },
          },
          useContentLength
        );
        return;
      }

      try {
        const upstream = await postStreamableHttpMcp(targetUrlObj, rawBodyBuf, {
          bearerToken,
          sessionId: activeSessionId,
          timeoutMs,
          agent: httpAgent,
        });
        if (upstream.sessionId) {
          activeSessionId = upstream.sessionId;
        }
        if (
          upstream.statusCode === 202 ||
          upstream.statusCode === 204 ||
          (rpcMeta.isNotificationOnly && upstream.bodyBuf.length === 0)
        ) {
          return;
        }

        const rawText = upstream.bodyBuf.toString("utf8").trim();
        if (upstream.statusCode === 200) {
          const jsonText = upstream.contentType.includes("text/event-stream")
            ? extractSseJsonPayload(rawText)
            : rawText;
          if (!jsonText && rpcMeta.isNotificationOnly) {
            return;
          }
          writeStdioFrame(outputStream, jsonText, useContentLength);
          return;
        }

        if (rpcMeta.isNotificationOnly) {
          return;
        }

        let upstreamErrObj = null;
        if (rawText.startsWith("{")) {
          try {
            const candidate = JSON.parse(rawText);
            if (candidate && typeof candidate === "object" && candidate.error) {
              if (candidate.id === null && rpcMeta.requestId !== undefined) {
                candidate.id = rpcMeta.requestId;
              }
              upstreamErrObj = candidate;
            }
          } catch {
            upstreamErrObj = null;
          }
        }
        writeStdioFrame(
          outputStream,
          upstreamErrObj || {
            jsonrpc: "2.0",
            id: rpcMeta.requestId ?? null,
            error: {
              code: -32000,
              message: `Upstream MCP HTTP ${upstream.statusCode}`,
            },
          },
          useContentLength
        );
      } catch (err) {
        if (!rpcMeta.isNotificationOnly) {
          writeStdioFrame(
            outputStream,
            {
              jsonrpc: "2.0",
              id: rpcMeta.requestId ?? null,
              error: {
                code: -32000,
                message: `MCP HTTP transport error: ${scrubText(err instanceof Error ? err.message : String(err), secrets)}`,
              },
            },
            useContentLength
          );
        }
      }
    });
  };

  const drainBuffer = () => {
    while (recvBuf.length > 0) {
      let lead = 0;
      while (lead < recvBuf.length && (recvBuf[lead] === 0x0d || recvBuf[lead] === 0x0a)) {
        lead += 1;
      }
      if (lead > 0) {
        recvBuf = recvBuf.subarray(lead);
      }
      if (recvBuf.length === 0) {
        return;
      }

      let firstNonWs = 0;
      while (
        firstNonWs < recvBuf.length &&
        (recvBuf[firstNonWs] === 0x20 || recvBuf[firstNonWs] === 0x09)
      ) {
        firstNonWs += 1;
      }
      if (firstNonWs >= recvBuf.length) {
        if (recvBuf.length > MAX_STDIO_MESSAGE_BYTES) {
          recvBuf = Buffer.alloc(0);
          enqueueErrorFrame("MCP stdio JSONL line exceeds 4 MiB limit", false);
        } else if (inputEnded) {
          recvBuf = Buffer.alloc(0);
        }
        return;
      }

      const firstByte = recvBuf[firstNonWs];
      const isJsonLine = firstByte === 0x7b /* { */ || firstByte === 0x5b; /* [ */

      if (isJsonLine) {
        const nlIdx = recvBuf.indexOf(0x0a);
        if (nlIdx === -1) {
          if (recvBuf.length > MAX_STDIO_MESSAGE_BYTES) {
            recvBuf = Buffer.alloc(0);
            enqueueErrorFrame("MCP stdio JSONL line exceeds 4 MiB limit", false);
            return;
          }
          if (!inputEnded) {
            return;
          }
          const finalLine = Buffer.from(recvBuf.toString("utf8").trim(), "utf8");
          recvBuf = Buffer.alloc(0);
          if (finalLine.length > 0) {
            enqueueFrame(finalLine, false);
          }
          return;
        }
        if (nlIdx > MAX_STDIO_MESSAGE_BYTES) {
          recvBuf = Buffer.alloc(0);
          enqueueErrorFrame("MCP stdio JSONL line exceeds 4 MiB limit", false);
          return;
        }
        const rawLine = recvBuf.subarray(0, nlIdx);
        recvBuf = recvBuf.subarray(nlIdx + 1);
        const trimmedStr = rawLine.toString("utf8").trim();
        if (trimmedStr.length > 0) {
          enqueueFrame(Buffer.from(trimmedStr, "utf8"), false);
        }
        continue;
      }

      const boundary = findHeaderBoundary(recvBuf);
      if (!boundary) {
        if (recvBuf.length > MAX_HEADER_BLOCK_BYTES || inputEnded) {
          recvBuf = Buffer.alloc(0);
          enqueueErrorFrame("Malformed or incomplete Content-Length header", true);
        }
        return;
      }
      if (boundary.headerEnd > MAX_HEADER_BLOCK_BYTES) {
        recvBuf = Buffer.alloc(0);
        enqueueErrorFrame("Content-Length header exceeds bounds", true);
        return;
      }

      const headerBlock = recvBuf.subarray(0, boundary.headerEnd).toString("ascii");
      const parsedHeader = parseContentLengthHeader(headerBlock);
      if (!parsedHeader.valid) {
        recvBuf = Buffer.alloc(0);
        enqueueErrorFrame(
          parsedHeader.contentLength > MAX_STDIO_MESSAGE_BYTES
            ? "Content-Length out of bounds"
            : "Invalid Content-Length header",
          true
        );
        return;
      }

      const bodyStart = boundary.headerEnd + boundary.sepLen;
      const frameEnd = bodyStart + parsedHeader.contentLength;
      if (recvBuf.length < frameEnd) {
        if (inputEnded) {
          recvBuf = Buffer.alloc(0);
          enqueueErrorFrame("Incomplete Content-Length body at EOF", true);
        }
        return;
      }

      const bodySlice = Buffer.from(recvBuf.subarray(bodyStart, frameEnd));
      recvBuf = recvBuf.subarray(frameEnd);
      enqueueFrame(bodySlice, true);
    }
  };

  return new Promise((resolve, reject) => {
    inputStream.on("data", (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      recvBuf = recvBuf.length === 0 ? buf : Buffer.concat([recvBuf, buf]);
      drainBuffer();
    });
    inputStream.on("end", () => {
      if (inputEnded) return;
      inputEnded = true;
      drainBuffer();
      dispatchChain
        .finally(() => {
          httpAgent.destroy();
        })
        .then(() => resolve(0))
        .catch(reject);
    });
    inputStream.on("error", (err) => {
      httpAgent.destroy();
      reject(err);
    });
    if (typeof inputStream.resume === "function") {
      inputStream.resume();
    }
  });
}

export async function createLoopbackExchangeServer(options = {}) {
  const apiKey = options.apiKey ?? "ft_key_loopback_01";
  const apiSecret = options.apiSecret ?? "ft_secret_loopback_material_99";
  const operatorPrivKey = options.operatorPrivKey ?? `0x${"22".repeat(32)}`;
  const operatorAddress = deriveEthAddress(operatorPrivKey);
  const chainId = options.chainId ?? 84532;
  const clearinghouseAddress =
    options.clearinghouseAddress ?? "0x1111111111111111111111111111111111111111";

  let walSeq = 100;
  let nextOrderId = 900;
  const restingOrders = new Map();
  const recordedRequests = [];

  const verifyHmacRequest = (req, pathAndQuery, rawBody) => {
    const gotKey = String(req.headers["x-arena-api-key"] || "");
    const gotTs = String(req.headers["x-arena-timestamp"] || "");
    const gotNonce = String(req.headers["x-arena-nonce"] || "");
    const gotSig = String(req.headers["x-arena-signature"] || "");
    if (!gotKey || !gotTs || !gotNonce || !gotSig) {
      return { ok: false, error: "missing_auth_headers" };
    }
    if (gotKey !== apiKey) {
      return { ok: false, error: "unknown_api_key" };
    }
    const expectedSig = computeHmacSignature(apiSecret, gotTs, req.method || "GET", pathAndQuery, rawBody);
    const a = Buffer.from(gotSig, "utf8");
    const b = Buffer.from(expectedSig, "utf8");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { ok: false, error: "invalid_hmac_signature" };
    }
    return { ok: true };
  };

  const sendJson = (res, statusCode, payload) => {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(statusCode, {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": String(body.length),
      Connection: "close",
    });
    res.end(body);
  };

  const httpServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const rawBody = Buffer.concat(chunks).toString("utf8");
      const method = String(req.method || "GET").toUpperCase();
      const pathAndQuery = String(req.url || "/");
      const parsedUrl = new URL(pathAndQuery, "http://127.0.0.1");
      const pathname = parsedUrl.pathname;
      let bodyJson = null;
      if (rawBody) {
        try {
          bodyJson = JSON.parse(rawBody);
        } catch {
          sendJson(res, 400, { ok: false, error: "invalid_json" });
          return;
        }
      }

      recordedRequests.push({
        method,
        pathAndQuery,
        pathname,
        query: Object.fromEntries(parsedUrl.searchParams.entries()),
        headers: { ...req.headers },
        body: bodyJson,
      });

      if (method === "GET" && pathname === "/") {
        sendJson(res, 200, {
          ok: true,
          protocol: "FeraTerra Sovereign CLOB Engine",
          posture: "headless",
          website_ui: false,
          chain_id: chainId,
          clearinghouse_address: clearinghouseAddress,
          terms_endpoint: "/terms",
          stateless_preview_endpoint: "/order/preview",
        });
        return;
      }

      if (method === "GET" && pathname === "/terms") {
        sendJson(res, 200, {
          ok: true,
          endpoint: "/terms",
          posture: "headless_sovereign_clob",
          website_ui: false,
          non_custodial_l2_escape: true,
          stateless_zero_key_preview: true,
          ledger_tip_domain: "ARENA_LEDGER_TIP_V2_1",
          chain_id: chainId,
          clearinghouse_address: clearinghouseAddress,
          summary:
            "FeraTerra operates as a headless, programmatic CLOB protocol with client-side Keccak-256 + secp256k1 solvency verification and non-custodial L2 collateral vault Merkle emergency escape.",
        });
        return;
      }

      if (method === "GET" && pathname === "/health") {
        sendJson(res, 200, {
          ok: true,
          status: "healthy",
          wal_seq: walSeq,
          conservation_ok: true,
          double_entry_ok: true,
        });
        return;
      }

      if (method === "GET" && pathname === "/markets") {
        sendJson(res, 200, {
          ok: true,
          wal_seq: walSeq,
          markets: [
            {
              market_id: 1,
              symbol: "BTC-USD-PERP",
              kind: "linear_perpetual",
              trading_status: "live",
              mark_price_ticks: 7_000_000,
              best_bid_ticks: 6_999_500,
              best_ask_ticks: 7_000_500,
            },
            {
              market_id: 2,
              symbol: "ETH-USD-SPOT",
              kind: "spot",
              trading_status: "live",
              mark_price_ticks: 350_000,
              best_bid_ticks: 349_950,
              best_ask_ticks: 350_050,
            },
            {
              market_id: 99,
              symbol: "LEGACY-USD-PERP",
              kind: "linear_perpetual",
              trading_status: "halted",
              mark_price_ticks: 10_000,
              best_bid_ticks: 0,
              best_ask_ticks: 0,
            },
          ],
        });
        return;
      }

      if (method === "GET" && pathname === "/book") {
        const mid = Number(parsedUrl.searchParams.get("market_id") || "1");
        const depth = Number(parsedUrl.searchParams.get("depth") || "20");
        sendJson(res, 200, {
          ok: true,
          wal_seq: walSeq,
          market_id: mid,
          symbol: mid === 2 ? "ETH-USD-SPOT" : "BTC-USD-PERP",
          depth,
          bids: [
            [6_999_500, 15_000, 2],
            [6_999_000, 25_000, 3],
          ].slice(0, depth),
          asks: [
            [7_000_500, 12_500, 1],
            [7_001_000, 30_000, 4],
          ].slice(0, depth),
        });
        return;
      }

      if (method === "GET" && pathname === "/trades") {
        const mid = Number(parsedUrl.searchParams.get("market_id") || "1");
        const limit = Number(parsedUrl.searchParams.get("limit") || "50");
        sendJson(res, 200, {
          ok: true,
          wal_seq: walSeq,
          market_id: mid,
          symbol: mid === 2 ? "ETH-USD-SPOT" : "BTC-USD-PERP",
          trades: [
            { trade_id: 501, price_ticks: 7_000_000, qty_lots: 2_500, side: "bid", wal_seq: walSeq - 1 },
            { trade_id: 502, price_ticks: 7_000_500, qty_lots: 1_000, side: "ask", wal_seq: walSeq },
          ].slice(0, limit),
        });
        return;
      }

      if (method === "GET" && pathname === "/candles") {
        const mid = Number(parsedUrl.searchParams.get("market_id") || "1");
        const interval = parsedUrl.searchParams.get("interval") || "1m";
        const limit = Number(parsedUrl.searchParams.get("limit") || "120");
        sendJson(res, 200, {
          ok: true,
          wal_seq: walSeq,
          market_id: mid,
          symbol: mid === 2 ? "ETH-USD-SPOT" : "BTC-USD-PERP",
          interval,
          candles: [
            {
              open_ticks: 6_995_000,
              high_ticks: 7_010_000,
              low_ticks: 6_990_000,
              close_ticks: 7_000_000,
              volume_lots: 45_000,
              start_ts_ms: 1_700_000_000_000,
            },
          ].slice(0, limit),
        });
        return;
      }

      if (method === "GET" && pathname === "/leaderboard") {
        const sort = parsedUrl.searchParams.get("sort") || "equity";
        const limit = Number(parsedUrl.searchParams.get("limit") || "25");
        sendJson(res, 200, {
          ok: true,
          wal_seq: walSeq,
          sort_by: sort,
          entries: [
            { rank: 1, account_id: 77, equity_usd: "25000.00", pnl_usd: "5000.00" },
            { rank: 2, account_id: 88, equity_usd: "18400.50", pnl_usd: "1400.50" },
          ].slice(0, limit),
        });
        return;
      }

      if (method === "GET" && pathname === "/ledger/tip") {
        const chainHashHex = `0x${Buffer.from(keccak256(`chain:${walSeq}`)).toString("hex")}`;
        const stateRootHex = `0x${Buffer.from(keccak256(`state:${walSeq}`)).toString("hex")}`;
        const digestBytes = computeLedgerTipDigest({
          walSeq,
          ledgerChainHash: chainHashHex,
          stateRoot: stateRootHex,
          chainId,
          clearinghouseAddress,
        });
        const sigHex = signDigestSecp256k1(digestBytes, operatorPrivKey);
        sendJson(res, 200, {
          ok: true,
          tip_domain: "ARENA_LEDGER_TIP_V2_1",
          chain_id: chainId,
          clearinghouse_address: clearinghouseAddress,
          wal_seq: walSeq,
          ledger_chain_hash: chainHashHex,
          state_root: stateRootHex,
          tip_digest: `0x${Buffer.from(digestBytes).toString("hex")}`,
          operator_eth_address: operatorAddress,
          operator_signature: sigHex,
        });
        return;
      }

      if (method === "POST" && pathname === "/order/preview") {
        const aid = Number(bodyJson?.account_id ?? -1);
        const mid = Number(bodyJson?.market_id ?? 0);
        const qty = Number(bodyJson?.qty_lots ?? 0);
        if (!Number.isInteger(aid) || aid < 0 || mid <= 0 || qty <= 0) {
          sendJson(res, 400, { ok: false, error: "missing_order_fields" });
          return;
        }
        const effPx = Number(bodyJson?.price_ticks || 7_000_000);
        sendJson(res, 200, {
          ok: true,
          preview: true,
          stateless: true,
          account_id: aid,
          market_id: mid,
          would_accept: true,
          status: "Ok",
          effective_price_ticks: effPx,
          estimated_filled_lots: 0,
          estimated_resting_lots: qty,
          estimated_avg_price_ticks: 0,
          estimated_fee_micro: 0,
          estimated_net_fee_micro: 0,
          pre_imr_micro: 0,
          post_imr_micro: 70_000_000,
          post_mmr_micro: 35_000_000,
          post_free_margin_micro: 9_930_000_000,
          wal_seq: walSeq,
        });
        return;
      }

      // Authenticated HMAC-SHA256 endpoints
      if (
        (method === "GET" && pathname === "/account") ||
        (method === "POST" && ["/order", "/quote", "/cancel", "/cancel_all"].includes(pathname))
      ) {
        const authCheck = verifyHmacRequest(req, pathAndQuery, rawBody);
        if (!authCheck.ok) {
          sendJson(res, 401, { ok: false, error: authCheck.error });
          return;
        }

        if (method === "GET" && pathname === "/account") {
          const aid = Number(parsedUrl.searchParams.get("account_id") || "0");
          if (aid <= 0) {
            sendJson(res, 400, { ok: false, error: "invalid_account_id" });
            return;
          }
          sendJson(res, 200, {
            ok: true,
            wal_seq: walSeq,
            account_id: aid,
            total_equity_micro: 10_000_000_000,
            free_usd_micro: 9_500_000_000,
            withdrawable_usd_micro: 9_500_000_000,
            imr_micro: 500_000_000,
            mmr_micro: 250_000_000,
            open_orders: [...restingOrders.values()].filter((o) => o.account_id === aid),
          });
          return;
        }

        if (method === "POST" && pathname === "/order") {
          walSeq += 1;
          nextOrderId += 1;
          const orderRecord = {
            order_id: nextOrderId,
            account_id: Number(bodyJson.account_id),
            market_id: Number(bodyJson.market_id),
            side: String(bodyJson.side),
            price_ticks: Number(bodyJson.price_ticks),
            qty_lots: Number(bodyJson.qty_lots),
            tif: String(bodyJson.tif || "gtc"),
          };
          restingOrders.set(orderRecord.order_id, orderRecord);
          sendJson(res, 200, {
            ok: true,
            status: "Ok",
            order_status: "Resting",
            wal_seq: walSeq,
            order_id: orderRecord.order_id,
            account_id: orderRecord.account_id,
            market_id: orderRecord.market_id,
            filled_lots: 0,
            resting_lots: orderRecord.qty_lots,
          });
          return;
        }

        if (method === "POST" && pathname === "/quote") {
          walSeq += 1;
          const bidOrderId = ++nextOrderId;
          const askOrderId = ++nextOrderId;
          const aid = Number(bodyJson.account_id);
          const mid = Number(bodyJson.market_id);
          if (Number(bodyJson.bid_qty_lots) > 0) {
            restingOrders.set(bidOrderId, {
              order_id: bidOrderId,
              account_id: aid,
              market_id: mid,
              side: "bid",
              price_ticks: Number(bodyJson.bid_price_ticks),
              qty_lots: Number(bodyJson.bid_qty_lots),
            });
          }
          if (Number(bodyJson.ask_qty_lots) > 0) {
            restingOrders.set(askOrderId, {
              order_id: askOrderId,
              account_id: aid,
              market_id: mid,
              side: "ask",
              price_ticks: Number(bodyJson.ask_price_ticks),
              qty_lots: Number(bodyJson.ask_qty_lots),
            });
          }
          sendJson(res, 200, {
            ok: true,
            status: "Ok",
            wal_seq: walSeq,
            account_id: aid,
            market_id: mid,
            bid_order_id: bidOrderId,
            ask_order_id: askOrderId,
          });
          return;
        }

        if (method === "POST" && pathname === "/cancel") {
          const oid = Number(bodyJson?.order_id ?? 0);
          if (!restingOrders.has(oid)) {
            sendJson(res, 404, { ok: false, error: "order_not_found" });
            return;
          }
          restingOrders.delete(oid);
          walSeq += 1;
          sendJson(res, 200, {
            ok: true,
            status: "Ok",
            wal_seq: walSeq,
            account_id: Number(bodyJson.account_id),
            market_id: Number(bodyJson.market_id),
            order_id: oid,
          });
          return;
        }

        if (method === "POST" && pathname === "/cancel_all") {
          const aid = Number(bodyJson?.account_id ?? 0);
          const mid = Number(bodyJson?.market_id ?? 0);
          const sideFilter = String(bodyJson?.side || "");
          let canceledCount = 0;
          for (const [oid, ord] of restingOrders.entries()) {
            if (ord.account_id !== aid) continue;
            if (mid > 0 && ord.market_id !== mid) continue;
            if (sideFilter && ord.side !== sideFilter) continue;
            restingOrders.delete(oid);
            canceledCount += 1;
          }
          walSeq += 1;
          sendJson(res, 200, {
            ok: true,
            status: "Ok",
            wal_seq: walSeq,
            account_id: aid,
            market_id: mid,
            canceled_count: canceledCount,
          });
          return;
        }
      }

      sendJson(res, 404, { ok: false, error: `not_found:${method}:${pathname}` });
    });
  });

  await new Promise((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    port,
    apiKey,
    apiSecret,
    operatorAddress,
    chainId,
    clearinghouseAddress,
    recordedRequests,
    async close() {
      await new Promise((resolve) => httpServer.close(() => resolve()));
    },
  };
}

export async function runSelfTest() {
  // 1. Verify LF shebang on bin/feraterra-mcp.mjs
  const binBytes = fs.readFileSync(__filename);
  const expectedPrefix = Buffer.from("#!/usr/bin/env node\n", "utf8");
  assert.deepEqual(
    binBytes.subarray(0, expectedPrefix.length),
    expectedPrefix,
    "bin/feraterra-mcp.mjs must begin with LF shebang #!/usr/bin/env node\\n"
  );
  assert.equal(binBytes.includes(0x0d), false, "bin/feraterra-mcp.mjs must use strict LF line endings");

  // 1.5. Verify 100/100 HOL scanner schema standard (0 missing property descriptions)
  assert.equal(SERVER_VERSION, "4.9.5");
  assert.equal(PACKAGE_VERSION, "4.9.5");
  assert.equal(ALL_TOOLS.length, 14);
  let totalProps = 0;
  let missingPropDescriptions = 0;
  for (const tool of ALL_TOOLS) {
    assert.equal(typeof tool.title, "string", `${tool.name} missing top-level title`);
    assert.ok(tool.title.trim().length > 0, `${tool.name} empty top-level title`);
    assert.equal(tool.annotations?.title, tool.title, `${tool.name} annotations.title mismatch`);
    assert.ok(
      typeof tool.description === "string" && tool.description.trim().length >= 120,
      `${tool.name} description too short`
    );
    const props = tool.inputSchema?.properties ?? {};
    for (const [propName, propSpec] of Object.entries(props)) {
      totalProps += 1;
      if (typeof propSpec?.description !== "string" || propSpec.description.trim().length < 25) {
        missingPropDescriptions += 1;
        assert.fail(`${tool.name}.${propName} missing rich description`);
      }
    }
  }
  assert.equal(missingPropDescriptions, 0);
  assert.equal(totalProps, 85);
  assert.equal(strictBool("false", true), false);
  assert.equal(strictBool("true", false), true);
  assert.throws(() => strictBool("invalid_bool"));

  // 1.6. Verify bundled SKILL.md (zero smart contract mentions) and install-skill targets
  const skillRaw = fs.readFileSync(BUNDLED_SKILL_PATH, "utf8");
  assert.ok(skillRaw.includes("v4.9.5"));
  assert.equal(skillRaw.toLowerCase().includes("smart contract"), false);
  const tmpSkillDir = fs.mkdtempSync(path.join(os.tmpdir(), "feraterra-mcp-skill-"));
  try {
    const defSkill = await installSkillToDir(tmpSkillDir);
    assert.equal(fs.existsSync(defSkill.installedPath), true);
    const multiSkill = await installSkillToDir(tmpSkillDir, { claude: true, cursor: true, codex: true });
    assert.equal(multiSkill.installedPaths.length, 3);
    for (const p of multiSkill.installedPaths) {
      assert.equal(fs.existsSync(p), true);
    }
  } finally {
    fs.rmSync(tmpSkillDir, { recursive: true, force: true });
  }

  // 2. Fixed-point helpers
  assert.equal(usdToTicks("70000.25"), 7_000_025);
  assert.equal(ticksToUsd(7_000_025), "70000.25");
  assert.equal(baseToLots("1.25"), 12_500);
  assert.equal(lotsToBase(12_500), "1.2500");
  assert.equal(usdToMicro("35.5"), 35_500_000);
  assert.equal(microToUsd(35_500_000), "35.500000");

  // 3. Keccak-256 + secp256k1 canonical vector
  assert.equal(
    Buffer.from(keccak256(new Uint8Array(0))).toString("hex"),
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
  );
  const canonicalTip = {
    tip_domain: "ARENA_LEDGER_TIP_V2_1",
    chain_id: 84532,
    clearinghouse_address: "0x1111111111111111111111111111111111111111",
    wal_seq: 42,
    ledger_chain_hash: `0x${"aa".repeat(32)}`,
    state_root: `0x${"bb".repeat(32)}`,
    tip_digest: "0xec757ea855551c62ed323c60ff67aa688ca79b4aaa98145bebb05ca954ba15b7",
    operator_eth_address: "0x1563915e194D8CfBA1943570603F7606A3115508",
    operator_signature:
      "0x02ee8a47063e396fcbcdbe42cb706a07fa5ca7264ca92545040de0e95f050d4a5f6775f16ea824807ba79982d63ccb901830a8b467359797d6c6690116d294ee1c",
  };
  const verifiedTip = verifyLedgerTip(canonicalTip, {
    expectedOperatorAddress: canonicalTip.operator_eth_address,
  });
  assert.equal(verifiedTip.valid, true);
  assert.equal(verifiedTip.signature_verified, true);
  assert.equal(
    verifyLedgerTip({ ...canonicalTip, state_root: `0x${"cc".repeat(32)}` }).valid,
    false
  );

  // 4. Real loopback http.createServer integration across SDK + MCP stdio
  const harness = await createLoopbackExchangeServer();
  try {
    // Unauthenticated client: read-only + stateless previewOrder with account_id: 0
    const publicClient = new FeraTerraClient({
      baseUrl: harness.baseUrl,
      expectedOperatorAddress: harness.operatorAddress,
    });
    assert.equal(publicClient.accountId, 0);

    const manifest = await publicClient.getManifest();
    assert.equal(manifest.ok, true);
    assert.equal(manifest.terms_endpoint, "/terms");

    const terms = await publicClient.getTerms();
    assert.equal(terms.ok, true);
    assert.equal(terms.endpoint, "/terms");
    assert.equal(terms.non_custodial_l2_escape, true);

    const markets = await publicClient.listMarkets({ activeOnly: true });
    assert.equal(markets.count, 2);
    assert.equal(markets.markets[0].unified_symbol, "BTC/USD:USD");

    const book = await publicClient.getOrderbook({ symbol: "BTC-USD-PERP", depth: 5 });
    assert.equal(book.spread_usd, "10.00");

    const trades = await publicClient.getTrades({ symbol: "BTC-USD-PERP", limit: 5 });
    assert.equal(trades.count, 2);
    assert.equal(trades.trades[0].price_usd, "70000.00");

    const candles = await publicClient.getCandles({ symbol: "BTC-USD-PERP", interval: "1m", limit: 5 });
    assert.equal(candles.count, 1);
    assert.equal(candles.candles[0].close_usd, "70000.00");

    const lb = await publicClient.getLeaderboard({ limit: 5, sort: "pnl" });
    assert.equal(lb.sort_by, "pnl");
    assert.equal(lb.entries[0].account_id, 77);

    const solvency = await publicClient.verifySolvency();
    assert.equal(solvency.solvent, true);
    assert.equal(solvency.recovered_operator_address, harness.operatorAddress);

    const statelessPreview = await publicClient.previewOrder({
      symbol: "BTC-USD-PERP",
      side: "buy",
      price: "70000.00",
      amount: "0.1",
    });
    assert.equal(statelessPreview.would_accept, true);
    assert.equal(statelessPreview.account_id, 0);
    assert.equal(statelessPreview.stateless_zero_key, true);
    assert.equal(statelessPreview.imr_delta_usd, "70.000000");
    assert.equal(statelessPreview.post_mmr_usd, "35.000000");
    const previewReq = harness.recordedRequests.find((r) => r.pathname === "/order/preview");
    assert.equal(previewReq.body.account_id, 0);
    assert.equal(previewReq.headers["x-arena-api-key"], undefined);

    // Authenticated HMAC-SHA256 client: /account, /order, /quote, /cancel, /cancel_all
    const authClient = new FeraTerraClient({
      baseUrl: harness.baseUrl,
      apiKey: harness.apiKey,
      apiSecret: harness.apiSecret,
      accountId: 77,
      expectedOperatorAddress: harness.operatorAddress,
    });

    const acctBefore = await authClient.getAccount();
    assert.equal(acctBefore.account_id, 77);
    assert.equal(acctBefore.total_equity_usd, "10000.000000");

    const placed = await authClient.placeOrder({
      symbol: "BTC-USD-PERP",
      side: "buy",
      price: "69950.00",
      amount: "0.25",
      postOnly: true,
    });
    assert.equal(placed.ok, true);
    assert.ok(placed.order_id > 0);

    const canceled = await authClient.cancelOrder({
      symbol: "BTC-USD-PERP",
      orderId: placed.order_id,
    });
    assert.equal(canceled.order_id, placed.order_id);

    const quoted = await authClient.replaceQuote({
      symbol: "BTC-USD-PERP",
      bidPrice: "69980.00",
      bidAmount: "0.2",
      askPrice: "70020.00",
      askAmount: "0.2",
      tif: "post_only",
    });
    assert.equal(quoted.ok, true);

    const canceledAll = await authClient.cancelAllOrders({ symbol: "BTC-USD-PERP" });
    assert.equal(canceledAll.canceled_count, 2);

    // Wrong HMAC secret must be rejected with HTTP 401
    const badAuthClient = new FeraTerraClient({
      baseUrl: harness.baseUrl,
      apiKey: harness.apiKey,
      apiSecret: "wrong_secret_value_000",
      accountId: 77,
    });
    await assert.rejects(() => badAuthClient.getAccount(), /invalid_hmac_signature/);

    // 5. In-memory MCP stdio stream test (2025-11-25 & 2025-06-18 + Content-Length)
    const mcpServer = new FeraTerraMcpServer({ client: authClient });
    const inStream = new PassThrough();
    const outStream = new PassThrough();
    const outChunks = [];
    outStream.on("data", (c) => outChunks.push(c));

    const servePromise = serveMcpStdio(mcpServer, inStream, outStream);
    const requests = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2025-06-18" } },
      { jsonrpc: "2.0", id: 3, method: "tools/list" },
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "arena_preview_order",
          arguments: { account_id: 0, symbol: "BTC-USD-PERP", side: "buy", price_usd: "70000", amount_base: "0.05" },
        },
      },
      {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "feraterra_verify_ledger_tip",
          arguments: { expected_operator_address: harness.operatorAddress },
        },
      },
      {
        jsonrpc: "2.0",
        id: 6,
        method: "resources/read",
        params: { uri: "feraterra://protocol/terms" },
      },
    ];
    for (const reqObj of requests) {
      inStream.write(`${JSON.stringify(reqObj)}\n`);
    }
    inStream.end();
    await servePromise;

    const outLines = Buffer.concat(outChunks)
      .toString("utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    assert.equal(outLines.length, 6);
    assert.equal(outLines[0].result.protocolVersion, "2025-11-25");
    assert.equal(outLines[1].result.protocolVersion, "2025-06-18");
    assert.equal(outLines[2].result.tools.length, 14);
    assert.equal(outLines[3].result.isError, false);
    assert.equal(outLines[3].result.structuredContent.account_id, 0);
    assert.equal(outLines[3].result.structuredContent.stateless_zero_key, true);
    assert.equal(outLines[4].result.isError, false);
    assert.equal(outLines[4].result.structuredContent.solvent, true);
    assert.equal(JSON.parse(outLines[5].result.contents[0].text).endpoint, "/terms");

    // 5.5. Streamable HTTP --remote proxy test with Bearer token & Mcp-Session-Id propagation
    const expectedBearer = "ft_remote_proxy_token_495";
    const remoteHttpServer = http.createServer(async (req, res) => {
      if (req.method !== "POST" || req.url !== "/mcp") {
        res.writeHead(404).end();
        return;
      }
      if (req.headers.authorization !== `Bearer ${expectedBearer}`) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "Unauthorized" } }));
        return;
      }
      const reqChunks = [];
      req.on("data", (c) => reqChunks.push(c));
      req.on("end", async () => {
        const rawUtf8 = Buffer.concat(reqChunks).toString("utf8");
        const reply = await mcpServer.dispatchRawPayload(rawUtf8);
        if (reply === null) {
          res.writeHead(202).end();
          return;
        }
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Mcp-Session-Id": "session-ft-495",
        });
        res.end(JSON.stringify(reply));
      });
    });
    await new Promise((resolve) => remoteHttpServer.listen(0, "127.0.0.1", resolve));
    const remotePort = remoteHttpServer.address().port;
    try {
      const proxyIn = new PassThrough();
      const proxyOut = new PassThrough();
      const proxyChunks = [];
      proxyOut.on("data", (c) => proxyChunks.push(c));
      const proxyDone = bridgeMcpStdioToHttp({
        inputStream: proxyIn,
        outputStream: proxyOut,
        url: `http://127.0.0.1:${remotePort}/mcp`,
        bearerToken: expectedBearer,
      });
      proxyIn.write(`  ${JSON.stringify({ jsonrpc: "2.0", id: 91, method: "resources/templates/list" })}\n`);
      proxyIn.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      proxyIn.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 92, method: "tools/call", params: { name: "feraterra_health_and_manifest", arguments: { include_terms: true } } })}\n`
      );
      proxyIn.end();
      await proxyDone;
      const proxyFrames = Buffer.concat(proxyChunks)
        .toString("utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l));
      assert.equal(proxyFrames.length, 2);
      assert.deepEqual(proxyFrames[0].result.resourceTemplates, []);
      assert.equal(proxyFrames[1].result.structuredContent.healthy, true);
      assert.equal(proxyFrames[1].result.structuredContent.terms.endpoint, "/terms");
    } finally {
      await new Promise((resolve) => remoteHttpServer.close(resolve));
    }

    // 6. Real child-process stdio purity check (stdout strictly JSON-RPC!)
    const childStdout = await new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [__filename, "--base-url", harness.baseUrl, "--expected-operator", harness.operatorAddress],
        { stdio: ["pipe", "pipe", "pipe"] }
      );
      const stdoutBufs = [];
      child.stdout.on("data", (d) => stdoutBufs.push(d));
      child.on("error", reject);
      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error(`Child MCP process exited with code ${code}`));
          return;
        }
        resolve(Buffer.concat(stdoutBufs).toString("utf8"));
      });
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 10, method: "initialize", params: { protocolVersion: "2025-11-25" } })}\n`
      );
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "feraterra_list_markets", arguments: {} } })}\n`
      );
      child.stdin.end();
    });

    const childFrames = childStdout
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l));
    assert.equal(childFrames.length, 2);
    assert.equal(childFrames[0].id, 10);
    assert.equal(childFrames[0].result.protocolVersion, "2025-11-25");
    assert.equal(childFrames[1].id, 11);
    assert.equal(childFrames[1].result.structuredContent.count, 2);
  } finally {
    await harness.close();
  }

  writeStderrLine(`[PASS] ${SERVER_NAME} v${SERVER_VERSION} self-test passed`);
  return 0;
}

export function parseCliArgs(argv = process.argv.slice(2)) {
  const opts = {
    subcommand: "stdio",
    selfTest: false,
    help: false,
    version: false,
    readOnly: resolveEnvBool(process.env.FERATERRA_READ_ONLY, false),
    remote: resolveEnvBool(process.env.FERATERRA_REMOTE_MCP, false),
    mcpUrl: undefined,
    bearerToken: String(
      process.env.FERATERRA_BEARER_TOKEN ?? process.env.ARENA_MCP_HTTP_BEARER_TOKEN ?? ""
    ).trim(),
    claude: false,
    cursor: false,
    codex: false,
    targetDir: process.cwd(),
    baseUrl: undefined,
    apiKey: undefined,
    apiSecret: undefined,
    accountId: undefined,
    expectedOperatorAddress: undefined,
    timeoutMs: undefined,
  };

  const requireNextValue = (index, flagName) => {
    if (!(index + 1 < argv.length)) {
      throw new Error(`Missing value for ${flagName}`);
    }
    return String(argv[index + 1]);
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = String(argv[i] ?? "");
    if (i === 0 && arg === "install-skill") {
      opts.subcommand = "install-skill";
    } else if (arg === "--self-test") {
      opts.selfTest = true;
    } else if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg === "--version" || arg === "-v") {
      opts.version = true;
    } else if (arg === "--read-only") {
      opts.readOnly = true;
    } else if (arg.startsWith("--read-only=")) {
      opts.readOnly = strictBool(arg.slice("--read-only=".length), false);
    } else if (arg === "--remote") {
      opts.remote = true;
    } else if (arg.startsWith("--remote=")) {
      opts.remote = strictBool(arg.slice("--remote=".length), false);
    } else if (arg === "--mcp-url") {
      opts.mcpUrl = requireNextValue(i, arg).trim();
      opts.remote = true;
      i += 1;
    } else if (arg.startsWith("--mcp-url=")) {
      opts.mcpUrl = arg.slice("--mcp-url=".length).trim();
      opts.remote = true;
    } else if (arg === "--bearer-token") {
      opts.bearerToken = requireNextValue(i, arg).trim();
      i += 1;
    } else if (arg.startsWith("--bearer-token=")) {
      opts.bearerToken = arg.slice("--bearer-token=".length).trim();
    } else if (arg === "--claude") {
      opts.claude = true;
    } else if (arg === "--cursor") {
      opts.cursor = true;
    } else if (arg === "--codex") {
      opts.codex = true;
    } else if (arg === "--dir" || arg === "-d") {
      opts.targetDir = requireNextValue(i, arg);
      i += 1;
    } else if (arg.startsWith("--dir=")) {
      opts.targetDir = arg.slice("--dir=".length);
    } else if (arg === "--testnet") {
      opts.baseUrl = DEFAULT_FERATERRA_API_URL;
    } else if (arg === "--base-url" || arg === "--url" || arg === "--arena-url") {
      opts.baseUrl = requireNextValue(i, arg).trim();
      i += 1;
    } else if (arg.startsWith("--base-url=")) {
      opts.baseUrl = arg.slice("--base-url=".length).trim();
    } else if (arg.startsWith("--url=")) {
      opts.baseUrl = arg.slice("--url=".length).trim();
    } else if (arg.startsWith("--arena-url=")) {
      opts.baseUrl = arg.slice("--arena-url=".length).trim();
    } else if (arg === "--api-key") {
      opts.apiKey = requireNextValue(i, arg);
      i += 1;
    } else if (arg.startsWith("--api-key=")) {
      opts.apiKey = arg.slice("--api-key=".length);
    } else if (arg === "--api-secret") {
      opts.apiSecret = requireNextValue(i, arg);
      i += 1;
    } else if (arg.startsWith("--api-secret=")) {
      opts.apiSecret = arg.slice("--api-secret=".length);
    } else if (arg === "--account-id") {
      const raw = requireNextValue(i, arg).trim();
      i += 1;
      const parsed = Number.parseInt(raw, 10);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(parsed) || parsed < 0) {
        throw new Error(`Invalid --account-id: ${raw}`);
      }
      opts.accountId = parsed;
    } else if (arg.startsWith("--account-id=")) {
      const raw = arg.slice("--account-id=".length).trim();
      const parsed = Number.parseInt(raw, 10);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(parsed) || parsed < 0) {
        throw new Error(`Invalid --account-id: ${raw}`);
      }
      opts.accountId = parsed;
    } else if (arg === "--expected-operator") {
      opts.expectedOperatorAddress = requireNextValue(i, arg).trim();
      i += 1;
    } else if (arg.startsWith("--expected-operator=")) {
      opts.expectedOperatorAddress = arg.slice("--expected-operator=".length).trim();
    } else if (arg === "--timeout-ms") {
      const raw = requireNextValue(i, arg).trim();
      i += 1;
      const parsed = Number.parseInt(raw, 10);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout-ms: ${raw}`);
      }
      opts.timeoutMs = parsed;
    } else if (arg.startsWith("--timeout-ms=")) {
      const raw = arg.slice("--timeout-ms=".length).trim();
      const parsed = Number.parseInt(raw, 10);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout-ms: ${raw}`);
      }
      opts.timeoutMs = parsed;
    } else {
      throw new Error(`Unknown CLI argument: ${arg}`);
    }
  }
  return opts;
}

export async function main(argv = process.argv.slice(2)) {
  // Redirect console.log to stderr so stdout remains strictly reserved for JSON-RPC frames
  console.log = (...args) => {
    writeStderrLine(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  };

  const opts = parseCliArgs(argv);
  if (opts.version) {
    writeStderrLine(`${SERVER_NAME} ${SERVER_VERSION}`);
    return 0;
  }
  if (opts.help) {
    writeStderrLine(
      [
        `${SERVER_NAME} v${SERVER_VERSION} — Zero-Dependency FeraTerra MCP Server, Streamable HTTP Proxy & Skill Installer`,
        "",
        "Usage:",
        "  feraterra-mcp [options]                                   Local stdio MCP REST server",
        "  feraterra-mcp --remote [--mcp-url <url>]                  Streamable HTTP MCP proxy",
        "  feraterra-mcp install-skill [--claude|--cursor|--codex] [--dir <path>]",
        "",
        "Options:",
        "  --self-test                  Run loopback HTTP + MCP stdio + proxy + skill verification suite",
        "  --base-url <url>             FeraTerra gateway URL (default: https://testnet.feraterra.app)",
        "  --remote                     Proxy stdio JSON-RPC to Streamable HTTP MCP endpoint",
        "  --mcp-url <url>              Streamable HTTP MCP URL (default: https://mcp.feraterra.app/mcp)",
        "  --bearer-token <token>       Optional Bearer token for --remote (or FERATERRA_BEARER_TOKEN)",
        "  --account-id <id>            Default numeric trader account ID (0 for stateless preview)",
        "  --api-key <key>              HMAC API key (or FERATERRA_API_KEY)",
        "  --api-secret <secret>        HMAC API secret (or FERATERRA_API_SECRET)",
        "  --expected-operator <0x...>  Optional pinned operator address for /ledger/tip",
        "  --read-only                  Disable mutating order/quote/cancel tools and prompts",
        "  --timeout-ms <ms>            HTTP request timeout in milliseconds",
        "  --claude|--cursor|--codex    Target agent skill folder(s) for install-skill",
        "  --dir, -d <path>             Target workspace directory for install-skill",
        "  --version, -v                Print version to stderr",
        "  --help, -h                   Print help to stderr",
      ].join("\n")
    );
    return 0;
  }
  if (opts.selfTest) {
    return runSelfTest();
  }
  if (opts.subcommand === "install-skill") {
    const res = await installSkillToDir(opts.targetDir, {
      claude: opts.claude,
      cursor: opts.cursor,
      codex: opts.codex,
    });
    process.stdout.write(`${JSON.stringify(res)}\n`);
    return 0;
  }
  if (opts.remote) {
    const remoteUrl = String(
      opts.mcpUrl ||
        opts.baseUrl ||
        process.env.FERATERRA_MCP_URL ||
        process.env.ARENA_MCP_URL ||
        REMOTE_FERATERRA_MCP_URL
    ).trim();
    const timeoutMs = opts.timeoutMs ?? DEFAULT_REMOTE_TIMEOUT_MS;
    if (process.stdin.isTTY && process.stderr.isTTY) {
      writeStderrLine(`[${SERVER_NAME}] Remote Streamable HTTP proxy on stdio -> ${remoteUrl}`);
    }
    return bridgeMcpStdioToHttp({
      inputStream: process.stdin,
      outputStream: process.stdout,
      url: remoteUrl,
      bearerToken: opts.bearerToken,
      timeoutMs,
    });
  }

  const server = new FeraTerraMcpServer(opts);
  if (process.stdin.isTTY && process.stderr.isTTY) {
    writeStderrLine(`[${SERVER_NAME}] Ready on stdio (${server.client.baseUrl})`);
  }
  return serveMcpStdio(server, process.stdin, process.stdout);
}

function isDirectCliInvocation() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return fs.realpathSync(entry) === fs.realpathSync(__filename);
  } catch {
    return path.resolve(entry) === path.resolve(__filename);
  }
}

if (isDirectCliInvocation()) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      writeStderrLine(`[${SERVER_NAME}] Fatal: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
  );
}
