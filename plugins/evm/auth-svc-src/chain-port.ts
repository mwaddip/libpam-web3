/**
 * Derive a deterministic port from a chain name.
 * Convention: port = 1024 + (crc32(chain_name) % 64511)
 *
 * This MUST agree byte-for-byte with PAM core's `chain_port()` (Rust)
 * and every other auth-svc's `chainPort` — see the golden table in
 * libpam-web3/docs/specs/chain-port-table.json. The chainPort.test.ts
 * here asserts against that table.
 */
export function chainPort(chain: string): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < chain.length; i++) {
    crc ^= chain.charCodeAt(i);
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
    }
  }
  return 1024 + ((crc ^ 0xFFFFFFFF) >>> 0) % 64511;
}
