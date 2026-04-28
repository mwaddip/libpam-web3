import { test } from "node:test";
import assert from "node:assert/strict";
import { chainPort } from "./chain-port";

/**
 * Golden chain→port table — must agree with libpam-web3/docs/specs/
 * chain-port-table.json and with PAM core's `chain_port()` (Rust). Five
 * implementations of the same CRC32 must produce these exact values; if
 * any one of them drifts by a byte, auth-routing breaks. This test is
 * the local guard rail against that.
 */
const EXPECTED: Record<string, number> = {
  cardano: 34206,
  ergo: 22898,
  evm: 63108,
  opnet: 32448,
};

test("chainPort matches the golden table", () => {
  for (const [chain, port] of Object.entries(EXPECTED)) {
    assert.equal(
      chainPort(chain),
      port,
      `chainPort(${JSON.stringify(chain)}) drifted: expected ${port}, got ${chainPort(chain)}`
    );
  }
});
