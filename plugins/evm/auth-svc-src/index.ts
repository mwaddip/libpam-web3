/**
 * web3-auth-svc — EVM auth service for libpam-web3.
 *
 * Self-contained HTTPS server: HTTP boilerplate (routes, TLS, body limits,
 * slowloris timeout, signal handling) is in auth-svc-common; this file
 * provides only the EVM-specific signature normalization + .sig writer.
 *
 * The auth-svc does NOT verify the EVM signature — PAM's built-in ecrecover
 * handles that. This server only validates the format and writes the
 * canonicalized hex.
 *
 * SPECIAL profile: S7 P9 E8 C5 I7 A7 L7
 *   P9: Auth boundary — validate every input, trust nothing from the network.
 *   E8: Long-running daemon — must not crash, must not leak.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  runServer,
  type CallbackError,
} from "../../../auth-svc-common/server";
import { chainPort } from "./chain-port";

const CHAIN_NAME = "evm";

// EVM signature: optional 0x prefix + 130 hex chars (65 bytes secp256k1)
const EVM_SIG_RE = /^(0x)?[0-9a-fA-F]{130}$/;

/**
 * Validate and normalize an EVM signature for the .sig file.
 *
 * Accepts: 130 hex chars, with or without 0x prefix, any case.
 * Returns: canonical `0x` + 130 lowercase hex chars, or null if invalid.
 *
 * Why normalize: PAM detects EVM .sig by `starts_with("0x") && len == 132`.
 * A no-prefix or uppercase signature would slip past auth-svc validation
 * but fail PAM detection, falling through to a JSON-parse error path that
 * masks the real cause. Canonicalize on write so the .sig file always
 * matches the PAM detection contract.
 */
export function normalizeSignature(sig: string): string | null {
  if (!EVM_SIG_RE.test(sig)) return null;
  const stripped = sig.startsWith("0x") ? sig.slice(2) : sig;
  return "0x" + stripped.toLowerCase();
}

function handleCallback(
  sessionId: string,
  body: string,
  pendingDir: string,
): CallbackError | null {
  const jsonPath = path.join(pendingDir, `${sessionId}.json`);
  const sigPath = path.join(pendingDir, `${sessionId}.sig`);
  const tmpPath = path.join(pendingDir, `${sessionId}.sig.tmp`);

  if (!fs.existsSync(jsonPath)) {
    return { kind: "not-found" };
  }
  if (fs.existsSync(sigPath)) {
    return { kind: "conflict" };
  }

  const normalized = normalizeSignature(body);
  if (!normalized) {
    return { kind: "invalid", message: "invalid signature format" };
  }

  try {
    fs.writeFileSync(tmpPath, normalized);
    fs.renameSync(tmpPath, sigPath);
  } catch (err) {
    console.error(`Failed to write sig for session ${sessionId}: ${err}`);
    try { fs.unlinkSync(tmpPath); } catch { /* tmp may not exist */ }
    return { kind: "invalid", message: "Internal Server Error" };
  }

  console.log(`[AUTH] Callback signature received for session ${sessionId}`);
  return null;
}

// Only run as a server when invoked as the entry point. Test imports skip.
if (process.argv[1]?.match(/\/(auth-svc\.js|index\.ts)$/)) {
  runServer({
    chain: CHAIN_NAME,
    defaultPort: chainPort(CHAIN_NAME),
    maxBodySize: 256,
    requireJson: false,
    requestTimeoutMs: 5000,
    handleCallback,
  });
}
