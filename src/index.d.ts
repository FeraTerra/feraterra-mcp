export declare const PACKAGE_VERSION = "4.9.5";
export declare const SDK_VERSION = "4.9.5";
export declare const DEFAULT_FERATERRA_API_URL = "https://testnet.feraterra.app";
export declare const MAINNET_FERATERRA_API_URL = "https://api.feraterra.app";
export declare const REMOTE_FERATERRA_MCP_URL = "https://mcp.feraterra.app/mcp";
export declare const PRICE_TICKS_PER_USD = 100;
export declare const LOTS_PER_BASE_UNIT = 10000;
export declare const MICRO_USD_PER_DOLLAR = 1000000;
export declare const MAX_RESPONSE_BYTES = 4194304;

export declare class FeraTerraError extends Error {
  status?: number;
  code?: string;
  constructor(message: string, options?: { status?: number; code?: string });
}

export type FetchLike = (
  input: string | URL,
  init?: RequestInit
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json?(): Promise<unknown>;
}>;

export interface FeraTerraClientOptions {
  baseUrl?: string;
  apiKey?: string;
  apiSecret?: string;
  accountId?: number;
  expectedOperatorAddress?: string;
  timeoutMs?: number;
  allowUnauthenticated?: boolean;
  fetch?: FetchLike;
}

export interface BuildHmacHeadersParams {
  apiKey: string;
  apiSecret: string;
  method: string;
  pathAndQuery: string;
  body?: string;
  timestampMs?: number | string;
  nonce?: string;
}

export interface HmacHeaders {
  "X-Arena-API-Key": string;
  "X-Arena-Timestamp": string;
  "X-Arena-Nonce": string;
  "X-Arena-Signature": string;
}

export interface FeraTerraMarket {
  market_id: number;
  symbol: string;
  unified_symbol: string;
  kind: string;
  trading_status: string;
  mark_price_ticks: number;
  best_bid_ticks: number;
  best_ask_ticks: number;
  mark_price_usd: string;
  best_bid_usd: string;
  best_ask_usd: string;
  [key: string]: unknown;
}

export interface ListMarketsParams {
  kind?: string;
  symbol?: string;
  activeOnly?: boolean;
  active_only?: boolean;
}

export interface ListMarketsResponse {
  ok: boolean;
  wal_seq: number;
  count: number;
  markets: FeraTerraMarket[];
}

export interface OrderbookLevel {
  price_ticks: number;
  price_usd: string;
  qty_lots: number;
  qty_base: string;
  order_count: number;
}

export interface GetOrderbookParams {
  marketId?: number;
  market_id?: number;
  symbol?: string;
  depth?: number;
}

export interface GetOrderbookResponse {
  ok: boolean;
  wal_seq: number;
  market_id: number;
  symbol: string;
  unified_symbol: string;
  depth: number;
  best_bid_usd: string | null;
  best_ask_usd: string | null;
  spread_usd: string | null;
  bids: unknown[];
  asks: unknown[];
  formatted_bids: OrderbookLevel[];
  formatted_asks: OrderbookLevel[];
  [key: string]: unknown;
}

export interface GetTradesParams {
  marketId?: number;
  market_id?: number;
  symbol?: string;
  limit?: number;
}

export interface FeraTerraTrade {
  price_ticks: number;
  price_usd: string;
  qty_lots: number;
  qty_base: string;
  [key: string]: unknown;
}

export interface GetTradesResponse {
  ok: boolean;
  market_id: number;
  symbol: string;
  unified_symbol: string;
  count: number;
  trades: FeraTerraTrade[];
  [key: string]: unknown;
}

export type CandleInterval = "tick" | "1s" | "1m";

export interface GetCandlesParams {
  marketId?: number;
  market_id?: number;
  symbol?: string;
  interval?: CandleInterval;
  limit?: number;
}

export interface FeraTerraCandle {
  open_ticks: number;
  high_ticks: number;
  low_ticks: number;
  close_ticks: number;
  volume_lots: number;
  open_usd: string;
  high_usd: string;
  low_usd: string;
  close_usd: string;
  volume_base: string;
  [key: string]: unknown;
}

export interface GetCandlesResponse {
  ok: boolean;
  market_id: number;
  symbol: string;
  unified_symbol: string;
  interval: string;
  count: number;
  candles: FeraTerraCandle[];
  [key: string]: unknown;
}

export type LeaderboardSort = "equity" | "pnl" | "streak" | "volume" | "roi" | string;

export interface GetLeaderboardParams {
  limit?: number;
  sort?: LeaderboardSort;
}

export interface LeaderboardEntry {
  rank: number;
  account_id: number;
  equity_usd?: string;
  [key: string]: unknown;
}

export interface GetLeaderboardResponse {
  ok: boolean;
  wal_seq: number;
  sort_by: string;
  entries: LeaderboardEntry[];
  [key: string]: unknown;
}

export interface LedgerTipDigestParams {
  walSeq: number | bigint;
  ledgerChainHash: string;
  stateRoot: string;
  chainId?: number | bigint;
  clearinghouseAddress?: string;
}

export interface VerifyLedgerTipOptions {
  expectedOperatorAddress?: string;
  expected_operator_address?: string;
  expectedChainId?: number;
  expected_chain_id?: number;
  expectedClearinghouseAddress?: string;
  expected_clearinghouse_address?: string;
  allowSelfAssertedSigner?: boolean;
}

export interface LedgerTipVerification {
  valid: boolean;
  digest_verified: boolean;
  signature_verified: boolean;
  pinned_operator_checked: boolean;
  computed_digest: string | null;
  recovered_operator_address: string | null;
  reason?: string;
}

export interface GetLedgerTipResponse extends LedgerTipVerification {
  ok: boolean;
  verification: LedgerTipVerification;
  wal_seq?: number;
  state_root?: string;
  ledger_chain_hash?: string;
  tip_digest?: string;
  operator_eth_address?: string;
  operator_signature?: string;
  chain_id?: number;
  clearinghouse_address?: string;
  [key: string]: unknown;
}

export interface VerifySolvencyParams extends VerifyLedgerTipOptions {
  includeHealth?: boolean;
  include_health?: boolean;
}

export interface VerifySolvencyResponse {
  ok: boolean;
  solvent: boolean;
  signature_verified: boolean;
  digest_verified: boolean;
  conservation_ok: boolean;
  pinned_operator_checked: boolean;
  recovered_operator_address: string | null;
  operator_eth_address: string | null;
  wal_seq: number;
  state_root: string;
  ledger_chain_hash: string;
  tip_digest: string | null;
  chain_id: number;
  clearinghouse_address: string;
  reason?: string;
  health: Record<string, unknown> | null;
  tip: Record<string, unknown>;
}

export interface OrderParams {
  accountId?: number;
  account_id?: number;
  marketId?: number;
  market_id?: number;
  symbol?: string;
  side?: "buy" | "sell" | "bid" | "ask";
  orderType?: "limit" | "market";
  order_type?: "limit" | "market";
  isMarket?: boolean;
  is_market?: boolean;
  amount?: number | string;
  amountBase?: number | string;
  amount_base?: number | string;
  qtyLots?: number;
  qty_lots?: number;
  price?: number | string;
  priceUsd?: number | string;
  price_usd?: number | string;
  priceTicks?: number;
  price_ticks?: number;
  differentialUsd?: number | string;
  differential_usd?: number | string;
  tif?: "gtc" | "ioc" | "fok" | "post_only";
  stp?: string;
  reduceOnly?: boolean;
  reduce_only?: boolean;
  postOnly?: boolean;
  post_only?: boolean;
  postOnlySlide?: boolean;
  post_only_slide?: boolean;
  marginSpot?: boolean;
  margin_spot?: boolean;
  primaryPeg?: boolean;
  primary_peg?: boolean;
  midpointPeg?: boolean;
  midpoint_peg?: boolean;
  markPeg?: boolean;
  mark_peg?: boolean;
  trailingPeg?: boolean;
  trailing_peg?: boolean;
  darkMidpoint?: boolean;
  dark_midpoint?: boolean;
  ocoLinked?: boolean;
  oco_linked?: boolean;
  stpDecrementAndCancel?: boolean;
  stp_decrement_and_cancel?: boolean;
  clientTag?: number;
  client_tag?: number;
  minQtyLots?: number;
  min_qty_lots?: number;
  displayQtyLots?: number;
  display_qty_lots?: number;
  autoSkewTicks?: number;
  auto_skew_ticks?: number;
  autoFlipTicks?: number;
  auto_flip_ticks?: number;
  pegOffsetTicks?: number;
  peg_offset_ticks?: number;
  maxLifetimeWalSeqs?: number;
  max_lifetime_wal_seqs?: number;
  jitElasticMult?: number;
  jit_elastic_mult?: number;
  priorityFeePpm?: number;
  priority_fee_ppm?: number;
}

export type PreviewOrderParams = OrderParams;

export interface PreviewOrderResponse {
  ok: boolean;
  preview: boolean;
  stateless_zero_key: boolean;
  account_id: number;
  would_accept: boolean;
  status: string;
  market_id: number;
  symbol: string;
  unified_symbol: string;
  side: "bid" | "ask";
  qty_lots: number;
  qty_base: string;
  effective_price_ticks: number;
  effective_price_usd: string;
  estimated_filled_lots: number;
  estimated_filled_base: string;
  estimated_resting_lots: number;
  estimated_resting_base: string;
  estimated_avg_price_ticks: number;
  estimated_avg_price_usd: string;
  estimated_fee_micro: number;
  estimated_net_fee_micro: number;
  estimated_fee_usd: string;
  pre_imr_micro: number;
  pre_imr_usd: string;
  post_imr_micro: number;
  post_imr_usd: string;
  imr_delta_micro: number;
  imr_delta_usd: string;
  post_mmr_micro: number;
  post_mmr_usd: string;
  post_free_margin_micro: number;
  post_free_margin_usd: string;
  wal_seq: number;
  [key: string]: unknown;
}

export interface GetAccountParams {
  accountId?: number;
  account_id?: number;
}

export interface GetAccountResponse {
  ok: boolean;
  account_id: number;
  total_equity_usd: string;
  free_usd: string;
  withdrawable_usd: string;
  imr_usd: string;
  mmr_usd: string;
  [key: string]: unknown;
}

export interface PlaceOrderResponse {
  ok: boolean;
  account_id: number;
  market_id: number;
  symbol: string;
  unified_symbol: string;
  side: "bid" | "ask";
  price_ticks: number;
  price_usd: string;
  qty_lots: number;
  qty_base: string;
  filled_lots: number;
  filled_base: string;
  resting_lots: number;
  resting_base: string;
  order_id?: number;
  wal_seq?: number;
  [key: string]: unknown;
}

export interface ReplaceQuoteParams {
  accountId?: number;
  account_id?: number;
  marketId?: number;
  market_id?: number;
  symbol?: string;
  bidPrice?: number | string;
  bidPriceUsd?: number | string;
  bid_price_usd?: number | string;
  bidPriceTicks?: number;
  bid_price_ticks?: number;
  bidAmount?: number | string;
  bidAmountBase?: number | string;
  bid_amount_base?: number | string;
  bidQtyLots?: number;
  bid_qty_lots?: number;
  askPrice?: number | string;
  askPriceUsd?: number | string;
  ask_price_usd?: number | string;
  askPriceTicks?: number;
  ask_price_ticks?: number;
  askAmount?: number | string;
  askAmountBase?: number | string;
  ask_amount_base?: number | string;
  askQtyLots?: number;
  ask_qty_lots?: number;
  tif?: "gtc" | "ioc" | "fok" | "post_only";
  stp?: string;
  postOnlySlide?: boolean;
  post_only_slide?: boolean;
  marginSpot?: boolean;
  margin_spot?: boolean;
  ocoLinked?: boolean;
  oco_linked?: boolean;
  ladderByTag?: boolean;
  ladder_by_tag?: boolean;
  clientTag?: number;
  client_tag?: number;
  autoSkewTicks?: number;
  auto_skew_ticks?: number;
  autoFlipTicks?: number;
  auto_flip_ticks?: number;
  quotePegMode?: number;
  quote_peg_mode?: number;
  pegOffsetTicks?: number;
  peg_offset_ticks?: number;
  maxLifetimeWalSeqs?: number;
  max_lifetime_wal_seqs?: number;
  jitElasticMult?: number;
  jit_elastic_mult?: number;
}

export interface ReplaceQuoteResponse {
  ok: boolean;
  account_id: number;
  market_id: number;
  symbol: string;
  unified_symbol: string;
  bid_price_ticks: number;
  bid_price_usd: string;
  bid_qty_lots: number;
  bid_qty_base: string;
  ask_price_ticks: number;
  ask_price_usd: string;
  ask_qty_lots: number;
  ask_qty_base: string;
  [key: string]: unknown;
}

export interface CancelOrderParams {
  accountId?: number;
  account_id?: number;
  marketId?: number;
  market_id?: number;
  symbol?: string;
  orderId: number;
  order_id?: number;
}

export interface CancelOrderResponse {
  ok: boolean;
  account_id: number;
  market_id: number;
  order_id: number;
  [key: string]: unknown;
}

export interface CancelAllOrdersParams {
  accountId?: number;
  account_id?: number;
  marketId?: number;
  market_id?: number;
  symbol?: string;
  side?: "buy" | "sell" | "bid" | "ask" | "";
  clientTagFilter?: number;
  client_tag_filter?: number;
  marketBitmask?: number;
  market_bitmask?: number;
}

export interface CancelAllOrdersResponse {
  ok: boolean;
  account_id: number;
  market_id: number;
  canceled_count: number;
  [key: string]: unknown;
}

export interface GetHealthAndManifestParams {
  includeTerms?: boolean;
  include_terms?: boolean;
}

export interface GetHealthAndManifestResponse {
  ok: boolean;
  healthy: boolean;
  wal_seq: number;
  chain_id: number;
  clearinghouse_address: string;
  health: Record<string, unknown>;
  manifest: Record<string, unknown>;
  terms?: Record<string, unknown>;
}

export declare function strictBool(val: unknown, defaultVal?: boolean): boolean;
export declare function isLoopbackHostname(hostname: string): boolean;
export declare function validateEndpointUrl(rawUrl: string, label?: string): string;
export declare function ticksToUsd(ticks: number | bigint | string): string;
export declare function usdToTicks(usd: number | bigint | string): number;
export declare function lotsToBase(lots: number | bigint | string): string;
export declare function baseToLots(base: number | bigint | string): number;
export declare function microToUsd(micro: number | bigint | string): string;
export declare function usdToMicro(usd: number | bigint | string): number;

export declare function keccak256(input: Uint8Array | string): Uint8Array;
export declare function deriveEthAddress(privateKeyHex: string): string;
export declare function signDigestSecp256k1(digestBytes: Uint8Array, privateKeyHex: string): string;
export declare function computeLedgerTipDigest(params: LedgerTipDigestParams): Uint8Array;
export declare function recoverLedgerTipSigner(digestBytes: Uint8Array, signatureHex: string): string;
export declare function verifyLedgerTip(
  tip: Record<string, unknown>,
  options?: VerifyLedgerTipOptions
): LedgerTipVerification;
export declare function computeHmacSignature(
  apiSecret: string,
  timestampMs: number | string,
  method: string,
  pathAndQuery: string,
  body?: string
): string;
export declare function buildHmacHeaders(params: BuildHmacHeadersParams): HmacHeaders;

export declare class FeraTerraClient {
  readonly baseUrl: string;
  readonly accountId: number;
  readonly expectedOperatorAddress: string;
  readonly timeoutMs: number;
  readonly allowUnauthenticated: boolean;

  constructor(options?: FeraTerraClientOptions);

  hasCredentials(): boolean;
  getHealth(): Promise<Record<string, unknown>>;
  getManifest(): Promise<Record<string, unknown>>;
  getTerms(): Promise<Record<string, unknown>>;
  getHealthAndManifest(params?: GetHealthAndManifestParams): Promise<GetHealthAndManifestResponse>;
  listMarkets(params?: ListMarketsParams): Promise<ListMarketsResponse>;
  getOrderbook(params?: GetOrderbookParams): Promise<GetOrderbookResponse>;
  getTrades(params?: GetTradesParams): Promise<GetTradesResponse>;
  getCandles(params?: GetCandlesParams): Promise<GetCandlesResponse>;
  getLeaderboard(params?: GetLeaderboardParams): Promise<GetLeaderboardResponse>;
  getLedgerTip(options?: VerifyLedgerTipOptions): Promise<GetLedgerTipResponse>;
  verifySolvency(params?: VerifySolvencyParams): Promise<VerifySolvencyResponse>;
  previewOrder(params?: PreviewOrderParams): Promise<PreviewOrderResponse>;
  getAccount(params?: GetAccountParams): Promise<GetAccountResponse>;
  placeOrder(params: OrderParams): Promise<PlaceOrderResponse>;
  submitOrder(params: OrderParams): Promise<PlaceOrderResponse>;
  replaceQuote(params: ReplaceQuoteParams): Promise<ReplaceQuoteResponse>;
  replaceTwoSidedQuote(params: ReplaceQuoteParams): Promise<ReplaceQuoteResponse>;
  cancelOrder(params: CancelOrderParams): Promise<CancelOrderResponse>;
  cancelAllOrders(params?: CancelAllOrdersParams): Promise<CancelAllOrdersResponse>;
  cancelAll(params?: CancelAllOrdersParams): Promise<CancelAllOrdersResponse>;
}

export default FeraTerraClient;
