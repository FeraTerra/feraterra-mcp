import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  BUNDLED_SKILL_PATH,
  DEFAULT_MCP_PROTOCOL_VERSION,
  FeraTerraMcpServer,
  SERVER_NAME,
  SERVER_VERSION,
  SUPPORTED_MCP_PROTOCOL_VERSIONS,
  bridgeMcpStdioToHttp,
  createLoopbackExchangeServer,
  installSkillToDir,
  parseCliArgs,
  serveMcpStdio,
} from "../bin/feraterra-mcp.mjs";
import defaultClientExport, {
  DEFAULT_FERATERRA_API_URL,
  FeraTerraClient,
  FeraTerraError,
  LOTS_PER_BASE_UNIT,
  MAINNET_FERATERRA_API_URL,
  MAX_RESPONSE_BYTES,
  MICRO_USD_PER_DOLLAR,
  PACKAGE_VERSION,
  PRICE_TICKS_PER_USD,
  REMOTE_FERATERRA_MCP_URL,
  SDK_VERSION,
  baseToLots,
  buildHmacHeaders,
  computeHmacSignature,
  computeLedgerTipDigest,
  deriveEthAddress,
  keccak256,
  lotsToBase,
  microToUsd,
  recoverLedgerTipSigner,
  signDigestSecp256k1,
  strictBool,
  ticksToUsd,
  usdToMicro,
  usdToTicks,
  validateEndpointUrl,
  verifyLedgerTip,
} from "../src/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const VALID_OPERATOR_ADDRESS = "0x1563915e194D8CfBA1943570603F7606A3115508";
const VALID_CLEARINGHOUSE = "0x1111111111111111111111111111111111111111";
const VALID_CHAIN_HASH = `0x${"aa".repeat(32)}`;
const VALID_STATE_ROOT = `0x${"bb".repeat(32)}`;
const VALID_TIP_DIGEST = "0xec757ea855551c62ed323c60ff67aa688ca79b4aaa98145bebb05ca954ba15b7";
const VALID_TIP_SIGNATURE =
  "0x02ee8a47063e396fcbcdbe42cb706a07fa5ca7264ca92545040de0e95f050d4a5f6775f16ea824807ba79982d63ccb901830a8b467359797d6c6690116d294ee1c";

describe("feraterra-mcp v4.9.5 package guardrails, zero-smart-contract scrub & workflows", () => {
  it("enforces v4.9.5 unification, zero dependencies, LF shebang, clean SKILL.md, and workflow pins", () => {
    assert.equal(defaultClientExport, FeraTerraClient);
    assert.equal(PACKAGE_VERSION, "4.9.5");
    assert.equal(SDK_VERSION, "4.9.5");
    assert.equal(SERVER_VERSION, "4.9.5");
    assert.equal(DEFAULT_FERATERRA_API_URL, "https://testnet.feraterra.app");
    assert.equal(MAINNET_FERATERRA_API_URL, "https://api.feraterra.app");
    assert.equal(REMOTE_FERATERRA_MCP_URL, "https://mcp.feraterra.app/mcp");
    assert.equal(PRICE_TICKS_PER_USD, 100);
    assert.equal(LOTS_PER_BASE_UNIT, 10_000);
    assert.equal(MICRO_USD_PER_DOLLAR, 1_000_000);
    assert.equal(MAX_RESPONSE_BYTES, 4 * 1024 * 1024);

    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));
    assert.equal(pkg.name, "feraterra-mcp");
    assert.equal(pkg.version, "4.9.5");
    assert.equal(pkg.mcpName, "io.github.FeraTerra/feraterra-mcp");
    assert.equal(pkg.type, "module");
    assert.deepEqual(pkg.bin, { "feraterra-mcp": "bin/feraterra-mcp.mjs" });
    assert.deepEqual(pkg.files, ["bin/", "src/", "skills/", "README.md", "LICENSE"]);
    assert.deepEqual(pkg.dependencies, {});
    assert.equal(Object.keys(pkg.devDependencies ?? {}).length, 0);
    assert.deepEqual(pkg.engines, { node: ">=20.0.0" });
    assert.deepEqual(pkg.publishConfig, { access: "public", provenance: true });
    assert.deepEqual(pkg.exports, {
      ".": {
        types: "./src/index.d.ts",
        import: "./src/index.mjs",
        default: "./src/index.mjs",
      },
    });

    // Ensure npm/pacote git-install lifecycle scripts are strictly omitted
    for (const forbiddenScript of [
      "build",
      "prepare",
      "prepack",
      "preinstall",
      "install",
      "postinstall",
    ]) {
      assert.equal(
        Object.prototype.hasOwnProperty.call(pkg.scripts ?? {}, forbiddenScript),
        false,
        `package.json scripts must omit ${forbiddenScript}`
      );
    }
    assert.deepEqual(Object.keys(pkg.scripts).sort(), ["self-test", "test"]);

    const binBuf = fs.readFileSync(path.join(REPO_ROOT, "bin", "feraterra-mcp.mjs"));
    assert.equal(binBuf.includes(0x0d), false, "bin/feraterra-mcp.mjs must not contain CR bytes");
    assert.equal(
      binBuf.subarray(0, 20).toString("utf8"),
      "#!/usr/bin/env node\n",
      "bin/feraterra-mcp.mjs must start with LF shebang"
    );

    // Zero-smart-contract prose scrub check across bin/feraterra-mcp.mjs, README.md, and SKILL.md
    const binText = binBuf.toString("utf8");
    const readmeText = fs.readFileSync(path.join(REPO_ROOT, "README.md"), "utf8");
    const skillText = fs.readFileSync(BUNDLED_SKILL_PATH, "utf8");
    assert.ok(binText.includes("L2 collateral vault"));
    assert.ok(readmeText.includes("L2 collateral vault"));
    assert.ok(binText.includes("clearinghouse_address"), "wire key clearinghouse_address must remain intact");

    assert.equal(skillText.includes("\r"), false, "SKILL.md must use LF line endings");
    assert.ok(skillText.includes("v4.9.5"), "SKILL.md must reference v4.9.5");
    assert.equal(skillText.toLowerCase().includes("smart contract"), false);

    // Verify CI, publish-npm, and Dependabot workflows
    const ciYml = fs.readFileSync(path.join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8");
    assert.ok(ciYml.includes('"20"') && ciYml.includes('"22"'), "ci.yml must test Node 20 and 22");
    assert.equal(ciYml.includes("github:FeraTerra/feraterra-mcp"), false, "ci.yml must not depend on remote main");

    const pubYml = fs.readFileSync(path.join(REPO_ROOT, ".github", "workflows", "publish-npm.yml"), "utf8");
    assert.ok(pubYml.includes("registry-url: 'https://registry.npmjs.org'"));
    assert.ok(pubYml.includes("npm@11.2.0"));
    assert.ok(pubYml.includes("EXPECTED_TAG"));

    const dependabotYml = fs.readFileSync(path.join(REPO_ROOT, ".github", "dependabot.yml"), "utf8");
    assert.ok(dependabotYml.includes("github-actions"));
    assert.ok(dependabotYml.includes("npm"));

    const gitattributes = fs.readFileSync(path.join(REPO_ROOT, ".gitattributes"), "utf8");
    assert.match(gitattributes, /\*\s+text=auto\s+eol=lf/);

    const dts = fs.readFileSync(path.join(REPO_ROOT, "src", "index.d.ts"), "utf8");
    for (const sym of [
      "PACKAGE_VERSION",
      "SDK_VERSION",
      "MAX_RESPONSE_BYTES",
      "FeraTerraClient",
      "FeraTerraError",
      "strictBool",
      "validateEndpointUrl",
      "getHealthAndManifest",
      "ticksToUsd",
      "usdToTicks",
      "lotsToBase",
      "baseToLots",
      "microToUsd",
      "usdToMicro",
      "keccak256",
      "computeLedgerTipDigest",
      "recoverLedgerTipSigner",
      "verifyLedgerTip",
      "computeHmacSignature",
      "buildHmacHeaders",
    ]) {
      assert.ok(dts.includes(sym), `src/index.d.ts missing ${sym}`);
    }
  });
});

describe("fixed-point helpers, strictBool, URL validation & pure-BigInt cryptography", () => {
  it("converts USD/ticks, base/lots, and USD/micro accurately without drift", () => {
    assert.equal(ticksToUsd(7_000_000), "70000.00");
    assert.equal(ticksToUsd(-500), "-5.00");
    assert.equal(usdToTicks("70000.25"), 7_000_025);
    assert.equal(usdToTicks(70000.25), 7_000_025);
    assert.equal(lotsToBase(12_500), "1.2500");
    assert.equal(baseToLots("0.1"), 1_000);
    assert.equal(baseToLots("2.3456"), 23_456);
    assert.equal(microToUsd(35_000_000), "35.000000");
    assert.equal(usdToMicro("12.5"), 12_500_000);

    assert.throws(() => usdToTicks("not-a-number"), TypeError);
    assert.throws(() => baseToLots(""), TypeError);
  });

  it("enforces strictBool parsing and rejects non-boolean strings/types", () => {
    assert.equal(strictBool(undefined, true), true);
    assert.equal(strictBool(null, false), false);
    assert.equal(strictBool(true, false), true);
    assert.equal(strictBool(false, true), false);
    assert.equal(strictBool("true", false), true);
    assert.equal(strictBool(" TRUE ", false), true);
    assert.equal(strictBool("false", true), false);
    assert.equal(strictBool(" FALSE ", true), false);

    assert.throws(() => strictBool("yes"), FeraTerraError);
    assert.throws(() => strictBool("0"), FeraTerraError);
    assert.throws(() => strictBool(1), FeraTerraError);
    assert.throws(() => strictBool({}), FeraTerraError);
  });

  it("validates baseUrl protocol, loopback http:, and forbids userinfo/query/hash", () => {
    assert.equal(validateEndpointUrl("https://testnet.feraterra.app/"), "https://testnet.feraterra.app");
    assert.equal(validateEndpointUrl("http://127.0.0.1:8080/"), "http://127.0.0.1:8080");
    assert.equal(validateEndpointUrl("http://localhost:9000"), "http://localhost:9000");
    assert.equal(validateEndpointUrl("http://[::1]:9000"), "http://[::1]:9000");

    assert.throws(() => new FeraTerraClient({ baseUrl: "http://api.feraterra.app" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "http://192.168.1.50:8080" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "https://user:pass@testnet.feraterra.app" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "https://user@testnet.feraterra.app" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "https://testnet.feraterra.app?foo=bar" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "https://testnet.feraterra.app?" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "https://testnet.feraterra.app#frag" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "https://testnet.feraterra.app#" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "ftp://testnet.feraterra.app" }), FeraTerraError);
    assert.throws(() => new FeraTerraClient({ baseUrl: "not-a-valid-url" }), FeraTerraError);
  });

  it("verifies Keccak-256 vectors, secp256k1 signatures, and adversarial ledger tips", () => {
    assert.equal(
      Buffer.from(keccak256(new Uint8Array(0))).toString("hex"),
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert.equal(
      Buffer.from(keccak256("abc")).toString("hex"),
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );

    const digest = computeLedgerTipDigest({
      walSeq: 42,
      ledgerChainHash: VALID_CHAIN_HASH,
      stateRoot: VALID_STATE_ROOT,
      chainId: 84532,
      clearinghouseAddress: VALID_CLEARINGHOUSE,
    });
    assert.equal(`0x${Buffer.from(digest).toString("hex")}`, VALID_TIP_DIGEST);
    assert.equal(recoverLedgerTipSigner(digest, VALID_TIP_SIGNATURE), VALID_OPERATOR_ADDRESS);

    const okRes = verifyLedgerTip(
      {
        tip_domain: "ARENA_LEDGER_TIP_V2_1",
        chain_id: 84532,
        clearinghouse_address: VALID_CLEARINGHOUSE,
        wal_seq: 42,
        ledger_chain_hash: VALID_CHAIN_HASH,
        state_root: VALID_STATE_ROOT,
        tip_digest: VALID_TIP_DIGEST,
        operator_eth_address: VALID_OPERATOR_ADDRESS,
        operator_signature: VALID_TIP_SIGNATURE,
      },
      { expectedOperatorAddress: VALID_OPERATOR_ADDRESS, expectedChainId: 84532 }
    );
    assert.equal(okRes.valid, true);
    assert.equal(okRes.digest_verified, true);
    assert.equal(okRes.signature_verified, true);
    assert.equal(okRes.pinned_operator_checked, true);

    // allowSelfAssertedSigner: "false" must disallow unpinned self-asserted signer
    const disallowedSelf = verifyLedgerTip(
      {
        tip_domain: "ARENA_LEDGER_TIP_V2_1",
        chain_id: 84532,
        clearinghouse_address: VALID_CLEARINGHOUSE,
        wal_seq: 42,
        ledger_chain_hash: VALID_CHAIN_HASH,
        state_root: VALID_STATE_ROOT,
        tip_digest: VALID_TIP_DIGEST,
        operator_eth_address: VALID_OPERATOR_ADDRESS,
        operator_signature: VALID_TIP_SIGNATURE,
      },
      { allowSelfAssertedSigner: "false" }
    );
    assert.equal(disallowedSelf.valid, false);
    assert.equal(disallowedSelf.reason, "self_asserted_signer_disallowed");

    // Roundtrip signDigestSecp256k1 + recoverLedgerTipSigner
    const priv = `0x${"33".repeat(32)}`;
    const expectedAddr = deriveEthAddress(priv);
    const customSig = signDigestSecp256k1(digest, priv);
    assert.equal(recoverLedgerTipSigner(digest, customSig), expectedAddr);

    // Tampered state_root must fail closed
    const badState = verifyLedgerTip({
      tip_domain: "ARENA_LEDGER_TIP_V2_1",
      chain_id: 84532,
      clearinghouse_address: VALID_CLEARINGHOUSE,
      wal_seq: 42,
      ledger_chain_hash: VALID_CHAIN_HASH,
      state_root: `0x${"dd".repeat(32)}`,
      tip_digest: VALID_TIP_DIGEST,
      operator_eth_address: VALID_OPERATOR_ADDRESS,
      operator_signature: VALID_TIP_SIGNATURE,
    });
    assert.equal(badState.valid, false);
    assert.equal(badState.digest_verified, false);
    assert.equal(badState.reason, "tip_digest_mismatch");

    // Wrong pinned operator address must fail closed
    const badOperator = verifyLedgerTip(
      {
        tip_domain: "ARENA_LEDGER_TIP_V2_1",
        chain_id: 84532,
        clearinghouse_address: VALID_CLEARINGHOUSE,
        wal_seq: 42,
        ledger_chain_hash: VALID_CHAIN_HASH,
        state_root: VALID_STATE_ROOT,
        tip_digest: VALID_TIP_DIGEST,
        operator_eth_address: VALID_OPERATOR_ADDRESS,
        operator_signature: VALID_TIP_SIGNATURE,
      },
      { expectedOperatorAddress: "0x2222222222222222222222222222222222222222" }
    );
    assert.equal(badOperator.valid, false);
    assert.equal(badOperator.signature_verified, false);
  });

  it("produces deterministic HMAC-SHA256 X-Arena-* headers with monotonic timestamps", () => {
    const sig = computeHmacSignature("secret123", "1700000000000", "POST", "/order", '{"a":1}');
    assert.equal(sig.length, 64);

    const h1 = buildHmacHeaders({
      apiKey: "key1",
      apiSecret: "secret123",
      method: "GET",
      pathAndQuery: "/account?account_id=77",
    });
    const h2 = buildHmacHeaders({
      apiKey: "key1",
      apiSecret: "secret123",
      method: "GET",
      pathAndQuery: "/account?account_id=77",
    });
    assert.equal(h1["X-Arena-API-Key"], "key1");
    assert.ok(Number(h2["X-Arena-Timestamp"]) > Number(h1["X-Arena-Timestamp"]));
    assert.notEqual(h1["X-Arena-Nonce"], h2["X-Arena-Nonce"]);
  });
});

describe("FeraTerraClient & FeraTerraMcpServer over real loopback HTTP + stdio + remote proxy", () => {
  let harness;
  const savedEnv = {};

  beforeEach(async () => {
    for (const k of [
      "FERATERRA_API_URL",
      "FERATERRA_API_KEY",
      "FERATERRA_API_SECRET",
      "FERATERRA_ACCOUNT_ID",
      "FERATERRA_EXPECTED_OPERATOR",
      "FERATERRA_READ_ONLY",
      "FERATERRA_REMOTE_MCP",
      "FERATERRA_MCP_URL",
      "FERATERRA_BEARER_TOKEN",
      "ARENA_URL",
      "ARENA_API_KEY",
      "ARENA_API_SECRET",
      "ARENA_ACCOUNT_ID",
    ]) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
    harness = await createLoopbackExchangeServer();
  });

  afterEach(async () => {
    if (harness) {
      await harness.close();
      harness = null;
    }
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it("exercises read-only endpoints, getHealthAndManifest, strictBool('false'), and stateless previewOrder", async () => {
    const client = new FeraTerraClient({
      baseUrl: harness.baseUrl,
      expectedOperatorAddress: harness.operatorAddress,
    });
    assert.equal(client.accountId, 0);
    assert.equal(client.hasCredentials(), false);

    const hm = await client.getHealthAndManifest({ include_terms: true });
    assert.equal(hm.ok, true);
    assert.equal(hm.healthy, true);
    assert.equal(hm.terms.endpoint, "/terms");

    const hmNoTerms = await client.getHealthAndManifest({ include_terms: "false" });
    assert.equal(hmNoTerms.terms, undefined);

    const mkts = await client.listMarkets({ activeOnly: true });
    assert.equal(mkts.count, 2);
    assert.equal(mkts.markets[0].symbol, "BTC-USD-PERP");
    assert.equal(mkts.markets[0].unified_symbol, "BTC/USD:USD");
    assert.equal(mkts.markets[0].mark_price_usd, "70000.00");

    // Passing string "false" must NOT coerce to true via Boolean("false")
    const allMktsStrFalse = await client.listMarkets({ active_only: "false" });
    assert.equal(allMktsStrFalse.count, 3);

    const book = await client.getOrderbook({ symbol: "BTC/USD:USD", depth: 2 });
    assert.equal(book.best_bid_usd, "69995.00");
    assert.equal(book.best_ask_usd, "70005.00");
    assert.equal(book.spread_usd, "10.00");
    assert.equal(book.formatted_bids[0].qty_base, "1.5000");

    const trades = await client.getTrades({ symbol: "BTC-USD-PERP", limit: 2 });
    assert.equal(trades.count, 2);
    assert.equal(trades.trades[0].qty_base, "0.2500");

    const candles = await client.getCandles({ symbol: "BTC-USD-PERP", interval: "1m", limit: 1 });
    assert.equal(candles.count, 1);
    assert.equal(candles.candles[0].high_usd, "70100.00");
    assert.equal(candles.candles[0].volume_base, "4.5000");

    const lb = await client.getLeaderboard({ limit: 1, sort: "equity" });
    assert.equal(lb.entries.length, 1);
    assert.equal(lb.entries[0].account_id, 77);

    const tip = await client.getLedgerTip();
    assert.equal(tip.valid, true);
    assert.equal(tip.signature_verified, true);
    assert.equal(tip.recovered_operator_address, harness.operatorAddress);

    const solvencyNoHealth = await client.verifySolvency({ include_health: "false" });
    assert.equal(solvencyNoHealth.solvent, true);
    assert.equal(solvencyNoHealth.health, null);

    const preview = await client.previewOrder({
      symbol: "BTC-USD-PERP",
      side: "buy",
      price: "70000.00",
      amount: "0.05",
      postOnly: true,
    });
    assert.equal(preview.ok, true);
    assert.equal(preview.account_id, 0);
    assert.equal(preview.would_accept, true);
    assert.equal(preview.qty_lots, 500);
    assert.equal(preview.post_imr_usd, "70.000000");

    // Unauthenticated client rejects mutating calls locally before network
    await assert.rejects(() => client.getAccount({ accountId: 77 }), FeraTerraError);
    await assert.rejects(
      () => client.placeOrder({ accountId: 77, symbol: "BTC-USD-PERP", side: "buy", price: "70000", amount: "0.1" }),
      FeraTerraError
    );
  });

  it("blocks cross-origin HTTP redirects (never leaking X-Arena-* headers) and enforces 4 MiB body cap", async () => {
    let leakedRequests = 0;
    const redirectTarget = http.createServer((req, res) => {
      if (req.headers["x-arena-api-key"] || req.headers["x-arena-signature"]) {
        leakedRequests += 1;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise((resolve) => redirectTarget.listen(0, "127.0.0.1", resolve));
    const targetPort = redirectTarget.address().port;

    const redirector = http.createServer((req, res) => {
      if (req.url === "/oversized-chunked") {
        res.writeHead(200, { "Content-Type": "application/json" });
        const chunk = Buffer.alloc(1024 * 1024, 0x61);
        for (let i = 0; i < 5; i += 1) {
          res.write(chunk);
        }
        res.end();
        return;
      }
      res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/steal` });
      res.end();
    });
    await new Promise((resolve) => redirector.listen(0, "127.0.0.1", resolve));
    const redirectPort = redirector.address().port;

    try {
      const client = new FeraTerraClient({
        baseUrl: `http://127.0.0.1:${redirectPort}`,
        apiKey: "ft_key_sensitive",
        apiSecret: "ft_secret_sensitive_material",
        accountId: 77,
      });
      await assert.rejects(() => client.getAccount(), FeraTerraError);
      assert.equal(leakedRequests, 0, "X-Arena-* HMAC headers must never follow HTTP redirects");

      await assert.rejects(
        () => client._requestJson("GET", "/oversized-chunked", { skipAuth: true }),
        (err) => err instanceof FeraTerraError && err.code === "response_too_large"
      );
    } finally {
      await new Promise((resolve) => redirector.close(resolve));
      await new Promise((resolve) => redirectTarget.close(resolve));
    }
  });

  it("signs HMAC-SHA256 X-Arena-* requests, defaults feraterra_replace_quote tif to post_only, and honors cancel_all='false'", async () => {
    const client = new FeraTerraClient({
      baseUrl: harness.baseUrl,
      apiKey: harness.apiKey,
      apiSecret: harness.apiSecret,
      accountId: 77,
    });
    const server = new FeraTerraMcpServer({ client, readOnly: "false" });
    assert.equal(server.readOnly, false);

    // Place order with string "false" flags to verify no truthy coercion
    const beforeOrdIdx = harness.recordedRequests.length;
    const ord = await client.placeOrder({
      symbol: "BTC-USD-PERP",
      side: "buy",
      price: "69900.00",
      amount: "0.5",
      post_only: "false",
      reduce_only: "false",
      is_market: "false",
      post_only_slide: "false",
      mark_peg: "false",
      clientTag: 12,
    });
    assert.equal(ord.ok, true);
    const ordReq = harness.recordedRequests.slice(beforeOrdIdx).find((r) => r.pathname === "/order");
    assert.equal(ordReq.body.tif, "gtc");
    assert.equal(ordReq.body.reduce_only, false);
    assert.equal(ordReq.body.is_market, false);
    assert.equal(ordReq.body.post_only_slide, undefined);
    assert.equal(ordReq.body.mark_peg, undefined);

    // arena_cancel_orders with cancel_all: "false" must dispatch single-order POST /cancel, NOT /cancel_all
    const beforeCancelIdx = harness.recordedRequests.length;
    const singleCancel = await server.callTool("arena_cancel_orders", {
      symbol: "BTC-USD-PERP",
      order_id: ord.order_id,
      cancel_all: "false",
    });
    assert.equal(singleCancel.isError, false);
    const cancelReq = harness.recordedRequests.slice(beforeCancelIdx).find((r) => r.pathname === "/cancel");
    assert.ok(cancelReq, "expected single-order /cancel request");
    assert.equal(cancelReq.body.order_id, ord.order_id);

    // feraterra_replace_quote with omitted tif must default to "post_only" (matching inputSchema)
    const beforeQuoteIdx = harness.recordedRequests.length;
    const mcpQuote = await server.callTool("feraterra_replace_quote", {
      symbol: "BTC-USD-PERP",
      bid_price_usd: "69950.00",
      bid_amount_base: "0.25",
      ask_price_usd: "70050.00",
      ask_amount_base: "0.25",
    });
    assert.equal(mcpQuote.isError, false);
    const quoteReq = harness.recordedRequests.slice(beforeQuoteIdx).find((r) => r.pathname === "/quote");
    assert.equal(quoteReq.body.tif, "post_only");

    const cancelAll = await client.cancelAllOrders({ symbol: "BTC-USD-PERP" });
    assert.equal(cancelAll.ok, true);
    assert.equal(cancelAll.canceled_count, 2);

    const acctAfter = await client.getAccount();
    assert.equal(acctAfter.open_orders.length, 0);
  });

  it("handles MCP JSON-RPC 2.0, 14 HOL tools, resources/templates/list, read-only prompt hiding, and stdio edge cases", async () => {
    assert.equal(SERVER_NAME, "feraterra-mcp");
    assert.equal(SERVER_VERSION, "4.9.5");
    assert.equal(DEFAULT_MCP_PROTOCOL_VERSION, "2025-11-25");
    assert.ok(SUPPORTED_MCP_PROTOCOL_VERSIONS.includes("2025-11-25"));
    assert.ok(SUPPORTED_MCP_PROTOCOL_VERSIONS.includes("2025-06-18"));

    const client = new FeraTerraClient({
      baseUrl: harness.baseUrl,
      apiKey: harness.apiKey,
      apiSecret: harness.apiSecret,
      accountId: 77,
      expectedOperatorAddress: harness.operatorAddress,
    });
    const server = new FeraTerraMcpServer({ client });

    // Enforce 100/100 HOL scanner standard: 0 missing inputSchema property descriptions across all 14 tools
    const listedTools = server.listTools();
    assert.equal(listedTools.length, 14);
    let propCount = 0;
    for (const tool of listedTools) {
      assert.ok(typeof tool.title === "string" && tool.title.length > 0, `missing title on ${tool.name}`);
      assert.equal(tool.annotations.title, tool.title);
      assert.ok(typeof tool.description === "string" && tool.description.length >= 120, `short description on ${tool.name}`);
      for (const [propKey, propSchema] of Object.entries(tool.inputSchema.properties)) {
        propCount += 1;
        assert.ok(
          typeof propSchema.description === "string" && propSchema.description.trim().length >= 25,
          `missing or terse description on ${tool.name}.${propKey}`
        );
      }
    }
    assert.equal(propCount, 85);

    // Verify feraterra_health_and_manifest and arena_health_and_manifest alias
    const healthManifestRes = await server.callTool("arena_health_and_manifest", { include_terms: true });
    assert.equal(healthManifestRes.isError, false);
    assert.equal(healthManifestRes.structuredContent.healthy, true);
    assert.equal(healthManifestRes.structuredContent.terms.endpoint, "/terms");

    // Verify resources/list and resources/templates/list
    const resList = await server.handleJsonRpcMessage({ jsonrpc: "2.0", id: 3, method: "resources/list" });
    assert.equal(resList.result.resources.length, 4);
    const tmplList = await server.handleJsonRpcMessage({
      jsonrpc: "2.0",
      id: 30,
      method: "resources/templates/list",
    });
    assert.deepEqual(tmplList.result, { resourceTemplates: [] });

    // Verify prompts/list & readOnly mutating prompt hiding
    const promptList = await server.handleJsonRpcMessage({ jsonrpc: "2.0", id: 5, method: "prompts/list" });
    assert.equal(promptList.result.prompts.length, 3);

    const roServer = new FeraTerraMcpServer({ client, readOnly: true });
    assert.equal(roServer.listTools().length, 10);
    const roPrompts = await roServer.handleJsonRpcMessage({ jsonrpc: "2.0", id: 51, method: "prompts/list" });
    assert.equal(roPrompts.result.prompts.length, 2);
    assert.equal(
      roPrompts.result.prompts.some((p) => p.name === "preview_and_execute_order"),
      false
    );
    const blockedPromptGet = await roServer.handleJsonRpcMessage({
      jsonrpc: "2.0",
      id: 52,
      method: "prompts/get",
      params: { name: "preview_and_execute_order", arguments: { symbol: "BTC-USD-PERP", side: "buy", amount_base: "0.1" } },
    });
    assert.equal(blockedPromptGet.error.code, -32602);
    assert.match(blockedPromptGet.error.message, /read_only_mode_enabled/);

    // 1) Leading 0x20/0x09 whitespace before JSONL in serveMcpStdio
    {
      const inS = new PassThrough();
      const outS = new PassThrough();
      const bufs = [];
      outS.on("data", (d) => bufs.push(d));
      const done = serveMcpStdio(server, inS, outS);
      inS.write(`  \t${JSON.stringify({ jsonrpc: "2.0", id: 77, method: "ping" })}\n`);
      inS.end();
      await done;
      const parsed = JSON.parse(Buffer.concat(bufs).toString("utf8").trim());
      assert.equal(parsed.id, 77);
      assert.deepEqual(parsed.result, {});
    }

    // 2) Malformed Content-Length resets buffer cleanly
    {
      const inS = new PassThrough();
      const outS = new PassThrough();
      const bufs = [];
      outS.on("data", (d) => bufs.push(d));
      const done = serveMcpStdio(server, inS, outS);
      inS.write('Content-Length: notanumber\r\n\r\n{"jsonrpc":"2.0","id":88,"method":"ping"}');
      inS.end();
      await done;
      const raw = Buffer.concat(bufs).toString("utf8");
      assert.match(raw, /^Content-Length:\s*\d+\r\n\r\n/);
      const errObj = JSON.parse(raw.split("\r\n\r\n")[1]);
      assert.equal(errObj.error.code, -32700);
    }

    // 3) Incomplete Content-Length body at EOF rejects with -32700 instead of JSONL fallback
    {
      const inS = new PassThrough();
      const outS = new PassThrough();
      const bufs = [];
      outS.on("data", (d) => bufs.push(d));
      const done = serveMcpStdio(server, inS, outS);
      inS.write('Content-Length: 200\r\n\r\n{"jsonrpc":"2.0"');
      inS.end();
      await done;
      const raw = Buffer.concat(bufs).toString("utf8");
      assert.match(raw, /^Content-Length:\s*\d+\r\n\r\n/);
      const errObj = JSON.parse(raw.split("\r\n\r\n")[1]);
      assert.equal(errObj.error.code, -32700);
      assert.match(errObj.error.message, /Incomplete Content-Length/i);
    }
  });

  it("validates CLI argument bounds, installs skills (--claude/--cursor/--codex/--dir), and proxies --remote Streamable HTTP", async () => {
    for (const badArgs of [
      ["--base-url"],
      ["--mcp-url"],
      ["--bearer-token"],
      ["--dir"],
      ["--api-key"],
      ["--api-secret"],
      ["--account-id"],
      ["--expected-operator"],
      ["--timeout-ms"],
      ["--timeout-ms", "abc"],
      ["--account-id", "-1"],
      ["--unknown-flag"],
    ]) {
      assert.throws(() => parseCliArgs(badArgs), Error, `Expected parseCliArgs(${JSON.stringify(badArgs)}) to throw`);
    }

    const parsedInstall = parseCliArgs(["install-skill", "--claude", "--cursor", "--codex", "--dir", "/tmp/ws"]);
    assert.equal(parsedInstall.subcommand, "install-skill");
    assert.equal(parsedInstall.claude, true);
    assert.equal(parsedInstall.cursor, true);
    assert.equal(parsedInstall.codex, true);
    assert.equal(parsedInstall.targetDir, "/tmp/ws");

    // Verify installSkillToDir across default and agent-specific directories
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "feraterra-mcp-test-"));
    try {
      const defInstall = await installSkillToDir(tmpDir);
      assert.ok(defInstall.installedPath.endsWith(path.join(".agents", "skills", "feraterra-trading", "SKILL.md")));
      assert.equal(fs.existsSync(defInstall.installedPath), true);

      const agentInstall = await installSkillToDir(tmpDir, { claude: true, cursor: true, codex: true });
      assert.equal(agentInstall.installedPaths.length, 3);
      for (const expectedSub of [".claude", ".cursor", ".codex"]) {
        const expectedFile = path.join(tmpDir, expectedSub, "skills", "feraterra-trading", "SKILL.md");
        assert.equal(fs.existsSync(expectedFile), true);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    // Verify --remote Streamable HTTP proxy mode over child CLI process with FERATERRA_BEARER_TOKEN
    const expectedBearer = "ft_cli_remote_bearer_token";
    const seenSessionHeaders = [];
    const upstreamMcp = new FeraTerraMcpServer({
      client: new FeraTerraClient({
        baseUrl: harness.baseUrl,
        expectedOperatorAddress: harness.operatorAddress,
      }),
    });
    const remoteHttp = http.createServer((req, res) => {
      if (req.method !== "POST" || req.url !== "/mcp") {
        res.writeHead(404).end();
        return;
      }
      if (req.headers.authorization !== `Bearer ${expectedBearer}`) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "Unauthorized" } }));
        return;
      }
      seenSessionHeaders.push(String(req.headers["mcp-session-id"] || ""));
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        const reply = await upstreamMcp.dispatchRawPayload(Buffer.concat(chunks).toString("utf8"));
        if (reply === null) {
          res.writeHead(202).end();
          return;
        }
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Mcp-Session-Id": "mcp-sess-v495",
        });
        res.end(JSON.stringify(reply));
      });
    });
    await new Promise((resolve) => remoteHttp.listen(0, "127.0.0.1", resolve));
    const remotePort = remoteHttp.address().port;

    try {
      const binPath = path.join(REPO_ROOT, "bin", "feraterra-mcp.mjs");
      const { stdout, code } = await new Promise((resolve, reject) => {
        const child = spawn(
          process.execPath,
          [binPath, "--remote", "--mcp-url", `http://127.0.0.1:${remotePort}/mcp`],
          {
            stdio: ["pipe", "pipe", "pipe"],
            env: { ...process.env, FERATERRA_BEARER_TOKEN: expectedBearer },
          }
        );
        const outChunks = [];
        child.stdout.on("data", (c) => outChunks.push(c));
        child.on("error", reject);
        child.on("close", (exitCode) =>
          resolve({ stdout: Buffer.concat(outChunks).toString("utf8"), code: exitCode })
        );
        child.stdin.write(
          `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } })}\n`
        );
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
        child.stdin.write(
          `${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "feraterra_list_markets", arguments: {} } })}\n`
        );
        child.stdin.end();
      });

      assert.equal(code, 0);
      const lines = stdout.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
      assert.equal(lines.length, 2);
      assert.equal(lines[0].result.serverInfo.version, "4.9.5");
      assert.equal(lines[1].result.structuredContent.count, 2);
      assert.equal(seenSessionHeaders[0], "");
      assert.equal(seenSessionHeaders[1], "mcp-sess-v495");
      assert.equal(seenSessionHeaders[2], "mcp-sess-v495");

      // Non-loopback http:// mcpUrl must be rejected by bridgeMcpStdioToHttp
      assert.throws(() => bridgeMcpStdioToHttp({ url: "http://mcp.feraterra.app/mcp" }), FeraTerraError);
    } finally {
      await new Promise((resolve) => remoteHttp.close(resolve));
    }
  });

  it("keeps child-process stdout strictly JSON-RPC when invoked via local stdio CLI", async () => {
    const binPath = path.join(REPO_ROOT, "bin", "feraterra-mcp.mjs");
    const { stdout, code } = await new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [
          binPath,
          "--base-url",
          harness.baseUrl,
          "--api-key",
          harness.apiKey,
          "--api-secret",
          harness.apiSecret,
          "--account-id",
          "77",
        ],
        { stdio: ["pipe", "pipe", "pipe"] }
      );
      const outChunks = [];
      child.stdout.on("data", (c) => outChunks.push(c));
      child.on("error", reject);
      child.on("close", (exitCode) =>
        resolve({ stdout: Buffer.concat(outChunks).toString("utf8"), code: exitCode })
      );
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } })}\n`
      );
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "feraterra_get_account", arguments: {} } })}\n`
      );
      child.stdin.end();
    });

    assert.equal(code, 0);
    const lines = stdout.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 2);
    const frame1 = JSON.parse(lines[0]);
    const frame2 = JSON.parse(lines[1]);
    assert.equal(frame1.result.protocolVersion, "2025-06-18");
    assert.equal(frame2.result.structuredContent.account_id, 77);
  });
});
