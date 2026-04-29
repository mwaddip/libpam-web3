/**
 * Shared HTTP/HTTPS server for libpam-web3 chain auth-svcs.
 *
 * Each chain plugin (cardano, opnet, ergo, evm) gets its own auth-svc binary,
 * but the HTTP boilerplate is identical: serve the signing page, return session
 * data, accept signature callbacks. The chain-specific bit is only the
 * "verify and write .sig" callback. This module owns everything else.
 *
 * Transport: HTTPS by default. When PAM's config sets `auth.use_tls = false`
 * (Tor onion mode, mesh VPN, etc.), the server binds plain HTTP — encryption
 * is the network transport's responsibility in that mode.
 *
 * Plugin entry point pattern (see plugins/<chain>/auth-svc-src/index.ts):
 *
 *   import { runServer } from "../../../auth-svc-common/server";
 *   import { chainPort } from "./chain-port";
 *
 *   runServer({
 *     chain: "cardano",
 *     defaultPort: chainPort("cardano"),
 *     maxBodySize: 1500,
 *     requireJson: true,
 *     requestTimeoutMs: 5000,
 *     handleCallback: (sessionId, body, pendingDir) => { ... },
 *   });
 *
 * SPECIAL profile: S8 P9 E8 C5 I7 A7 L7
 *   P9: Auth boundary — every chain auth-svc is internet-facing.
 *   E8: Long-running daemon — must not crash, must not leak.
 */

import * as https from "node:https";
import * as http from "node:http";
import * as fs from "node:fs";
import * as path from "node:path";

const DEFAULT_PENDING_DIR = "/run/libpam-web3/pending";
const DEFAULT_CERT = "/etc/libpam-web3/tls/cert.pem";
const DEFAULT_KEY = "/etc/libpam-web3/tls/key.pem";
const DEFAULT_PAGES_DIR = "/usr/share/blockhost/signing-pages";
const PAM_CONFIG_PATH = "/etc/pam_web3/config.toml";

const SESSION_ID_RE = /^[0-9a-f]{32}$/;

// ── Public types ─────────────────────────────────────────────────────────

export interface ServerConfig {
  port: number;
  pending_dir: string;
  cert: string;
  key: string;
  pages_dir: string;
  /**
   * Whether to bind HTTPS (default) or plain HTTP. Mirrors PAM's
   * `auth.use_tls` in /etc/pam_web3/config.toml — the URL scheme PAM
   * advertises and the protocol auth-svc binds must agree, so they
   * read from the same source. Set to `false` only when the network
   * transport already provides encryption (Tor onion, mesh VPN, etc.).
   */
  use_tls: boolean;
}

/**
 * Categorized error returned by a chain's handleCallback. The shared server
 * maps these to HTTP status codes; plugins don't write status codes directly.
 */
export type CallbackError =
  | { kind: "conflict"; message?: string }    // 409 — session already processed
  | { kind: "not-found"; message?: string }   // 404 — no such session
  | { kind: "invalid"; message?: string };    // 400 — bad input / verification failed

/**
 * Plugin-supplied options. Only the chain-specific parts vary; everything
 * else (routes, TLS, body size enforcement, slowloris timeout, signal
 * handling, signing page) is owned by the shared server.
 */
export interface ChainOptions {
  /** Chain identifier ("cardano", "opnet", "ergo", "evm"). */
  chain: string;
  /** Default port — pass `chainPort(chain)` from the plugin's chain-port.ts. */
  defaultPort: number;
  /**
   * Max accepted body bytes. Tighten per chain — `slowloris` defense:
   *   cardano  ~1500   (CIP-30 COSE_Sign1 + COSE_Key, hex)
   *   ergo     ~1500   (Schnorr proof)
   *   opnet    ~9000   (ML-DSA-87 base64)
   *   evm      256     (raw hex sig)
   */
  maxBodySize: number;
  /** If true, reject callbacks without `Content-Type: application/json`. */
  requireJson: boolean;
  /** Per-request idle timeout (ms). Defends against slow-drip body uploads. */
  requestTimeoutMs: number;
  /**
   * Verify the request body and atomically write the .sig file.
   * Body is already trimmed of whitespace.
   * Return null on success, or a CallbackError mapped to HTTP status.
   */
  handleCallback(
    sessionId: string,
    body: string,
    pendingDir: string,
  ): CallbackError | null;
}

// ── TOML loader ─────────────────────────────────────────────────────────

function parseToml(content: string): Record<string, Record<string, unknown>> {
  const result: Record<string, Record<string, unknown>> = {};
  let section = "";

  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;

    const secMatch = line.match(/^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$/);
    if (secMatch?.[1]) {
      section = secMatch[1];
      result[section] = result[section] || {};
      continue;
    }

    const kvMatch = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$/);
    if (!kvMatch?.[1] || !kvMatch[2] || !section) continue;

    const key = kvMatch[1];
    const val = kvMatch[2].trim();

    if (val.startsWith('"') && val.endsWith('"')) {
      result[section]![key] = val.slice(1, -1);
    } else {
      const num = Number(val);
      result[section]![key] = Number.isNaN(num) ? val : num;
    }
  }

  return result;
}

/**
 * Read `auth.use_tls` from PAM's config (/etc/pam_web3/config.toml).
 *
 * The PAM module owns this flag — it picks the URL scheme shown to the
 * user, and auth-svc must bind a matching protocol. Single source of
 * truth avoids the failure mode where PAM advertises `https://` while
 * auth-svc binds plain HTTP (or vice versa).
 *
 * Defaults to `true` (HTTPS) on any read or parse failure: the existing
 * deployment behaviour, fail-secure, and matches the Rust default in
 * `src/config.rs::default_use_tls`.
 */
export function loadUseTls(pamConfigPath: string = PAM_CONFIG_PATH): boolean {
  let content: string;
  try {
    content = fs.readFileSync(pamConfigPath, "utf8");
  } catch {
    return true;
  }

  const toml = parseToml(content);
  const auth = toml["auth"];
  if (!auth) return true;

  const value = auth["use_tls"];
  if (typeof value === "boolean") return value;
  // TOML true/false are parsed as strings by the minimal parser above
  // (it doesn't recognise booleans). Treat the literal strings here.
  if (value === "true") return true;
  if (value === "false") return false;
  return true;
}

export function loadConfig(
  configPath: string,
  chain: string,
  defaultPort: number,
  pamConfigPath: string = PAM_CONFIG_PATH,
): ServerConfig {
  const defaults: ServerConfig = {
    port: defaultPort,
    pending_dir: DEFAULT_PENDING_DIR,
    cert: DEFAULT_CERT,
    key: DEFAULT_KEY,
    pages_dir: path.join(DEFAULT_PAGES_DIR, chain),
    use_tls: loadUseTls(pamConfigPath),
  };

  let content: string;
  try {
    content = fs.readFileSync(configPath, "utf8");
  } catch {
    return defaults;
  }

  const toml = parseToml(content);
  const sec = toml["server"] || {};

  return {
    port: typeof sec.port === "number" ? sec.port : defaults.port,
    pending_dir: String(sec.pending_dir || defaults.pending_dir),
    cert: String(sec.cert || defaults.cert),
    key: String(sec.key || defaults.key),
    pages_dir: String(sec.pages_dir || defaults.pages_dir),
    use_tls: defaults.use_tls,
  };
}

// ── HTTP helpers ────────────────────────────────────────────────────────

function isValidSessionId(id: string): boolean {
  return SESSION_ID_RE.test(id);
}

function sendResponse(
  res: http.ServerResponse,
  statusCode: number,
  body: string,
  contentType = "text/plain",
): void {
  res.writeHead(statusCode, { "Content-Type": contentType });
  res.end(body);
}

function statusForError(err: CallbackError): number {
  switch (err.kind) {
    case "conflict": return 409;
    case "not-found": return 404;
    case "invalid":  return 400;
  }
}

// ── Route handlers ──────────────────────────────────────────────────────

function handleGetPending(
  sessionId: string,
  pendingDir: string,
  res: http.ServerResponse,
): void {
  if (!isValidSessionId(sessionId)) {
    sendResponse(res, 404, "Not Found");
    return;
  }

  const jsonPath = path.join(pendingDir, `${sessionId}.json`);
  let contents: string;
  try {
    contents = fs.readFileSync(jsonPath, "utf8");
  } catch {
    sendResponse(res, 404, "Not Found");
    return;
  }

  sendResponse(res, 200, contents, "application/json");
}

function handlePostCallback(
  sessionId: string,
  pendingDir: string,
  options: ChainOptions,
  req: http.IncomingMessage,
  res: http.ServerResponse,
): void {
  if (!isValidSessionId(sessionId)) {
    sendResponse(res, 404, "Not Found");
    return;
  }

  if (options.requireJson) {
    const ct = req.headers["content-type"] || "";
    if (!ct.includes("application/json")) {
      sendResponse(res, 400, "Content-Type must be application/json");
      return;
    }
  }

  // Slowloris defense: bound how long the client can dribble bytes.
  req.setTimeout(options.requestTimeoutMs, () => {
    if (!res.headersSent) {
      sendResponse(res, 408, "Request Timeout");
    }
    req.destroy();
  });

  const chunks: Buffer[] = [];
  let bodySize = 0;
  let aborted = false;

  req.on("data", (chunk: Buffer) => {
    bodySize += chunk.length;
    if (bodySize > options.maxBodySize) {
      if (!aborted) {
        aborted = true;
        sendResponse(res, 413, "body too large");
        req.destroy();
      }
      return;
    }
    chunks.push(chunk);
  });

  req.on("end", () => {
    if (aborted) return;

    const body = Buffer.concat(chunks).toString("utf8").trim();
    const result = options.handleCallback(sessionId, body, pendingDir);

    if (result === null) {
      sendResponse(res, 200, "OK");
      return;
    }

    const status = statusForError(result);
    const text = result.message ?? defaultMessageFor(status);
    if (status >= 500 || status === 400) {
      console.error(`[AUTH] Callback rejected for session ${sessionId}: ${result.kind}${result.message ? `: ${result.message}` : ""}`);
    }
    sendResponse(res, status, text);
  });

  req.on("error", () => { /* client closed connection */ });
}

function defaultMessageFor(status: number): string {
  switch (status) {
    case 400: return "verification failed";
    case 404: return "Not Found";
    case 409: return "Conflict";
    default:  return "Error";
  }
}

// ── Static file serving ─────────────────────────────────────────────────

function serveFile(
  res: http.ServerResponse,
  filePath: string,
  contentType: string,
): void {
  let data: Buffer;
  try {
    data = fs.readFileSync(filePath);
  } catch {
    sendResponse(res, 404, "Not Found");
    return;
  }
  res.writeHead(200, {
    "Content-Type": contentType,
    "Content-Length": data.length,
  });
  res.end(data);
}

// ── Server entry point ──────────────────────────────────────────────────

/**
 * Build the request handler shared by both HTTP and HTTPS server variants.
 * Extracted so the server type (http.Server vs https.Server) can be
 * decided once based on `use_tls` without duplicating the routing logic.
 */
function buildRequestHandler(
  config: ServerConfig,
  options: ChainOptions,
): http.RequestListener {
  return (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");

    const url = new URL(req.url || "/", "https://localhost");
    const pathname = url.pathname;

    // Signing page
    if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
      serveFile(res, path.join(config.pages_dir, "index.html"), "text/html; charset=utf-8");
      return;
    }
    if (req.method === "GET" && pathname === "/engine.js") {
      serveFile(res, path.join(config.pages_dir, "engine.js"), "application/javascript; charset=utf-8");
      return;
    }

    // Auth API
    const pendingMatch = pathname.match(/^\/auth\/pending\/([^/]+)$/);
    if (req.method === "GET" && pendingMatch?.[1]) {
      handleGetPending(pendingMatch[1], config.pending_dir, res);
      return;
    }

    const callbackMatch = pathname.match(/^\/auth\/callback\/([^/]+)$/);
    if (req.method === "POST" && callbackMatch?.[1]) {
      handlePostCallback(callbackMatch[1], config.pending_dir, options, req, res);
      return;
    }

    sendResponse(res, 404, "Not Found");
  };
}

/**
 * Build either an HTTPS or plain HTTP server based on `config.use_tls`.
 *
 * When `use_tls` is true (the default), the TLS cert/key are read from
 * disk; missing files cause this function to throw. When `use_tls` is
 * false the cert/key files are NOT touched — the network transport
 * (Tor, mesh VPN, etc.) is responsible for encryption.
 *
 * Exported so tests can verify the right server variant is built without
 * actually starting a listener.
 */
export function buildAuthServer(
  config: ServerConfig,
  options: ChainOptions,
): http.Server {
  const handler = buildRequestHandler(config, options);

  if (!config.use_tls) {
    return http.createServer(handler);
  }

  const tlsOpts = {
    cert: fs.readFileSync(config.cert),
    key: fs.readFileSync(config.key),
  };
  return https.createServer(tlsOpts, handler);
}

/**
 * Boot the auth-svc server (HTTPS by default, HTTP when use_tls=false).
 *
 * Loads config from /etc/web3-auth/<chain>.toml (overridable via argv[2])
 * and `auth.use_tls` from /etc/pam_web3/config.toml. Plugins supply only
 * the chain-specific verify-and-write-sig callback in `options`.
 */
export function runServer(options: ChainOptions): void {
  const configPath = process.argv[2] || `/etc/web3-auth/${options.chain}.toml`;
  const config = loadConfig(configPath, options.chain, options.defaultPort);

  let server: http.Server;
  try {
    server = buildAuthServer(config, options);
  } catch (err) {
    // Only reachable via the use_tls=true branch (TLS file read failure).
    console.error(`[AUTH] TLS cert/key load failed: ${err}`);
    process.exit(1);
  }

  // Bind to all interfaces (dual-stack IPv6).
  server.listen(config.port, "::", () => {
    const proto = config.use_tls ? "https" : "http";
    console.log(`[AUTH] web3-auth-svc (${options.chain}) on ${proto}://[::]:${config.port}`);
    console.log(`[AUTH] Pending dir: ${config.pending_dir}`);
    console.log(`[AUTH] Pages: ${config.pages_dir}`);
  });

  server.on("error", (err) => {
    console.error(`[AUTH] Server error: ${err}`);
    process.exit(1);
  });

  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      console.log("[AUTH] Shutting down...");
      server.close(() => process.exit(0));
    });
  }
}
