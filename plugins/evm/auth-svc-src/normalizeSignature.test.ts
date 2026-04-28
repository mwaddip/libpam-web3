import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeSignature } from "./index";

test("accepts canonical 0x + 130 lowercase hex", () => {
  const sig = "0x" + "ab".repeat(64) + "1b";
  assert.equal(normalizeSignature(sig), sig);
});

test("uppercases get lowercased", () => {
  const sig = "0x" + "AB".repeat(64) + "1B";
  assert.equal(normalizeSignature(sig), sig.toLowerCase());
});

test("no-prefix gets 0x prepended", () => {
  const body = "ab".repeat(64) + "1b";
  assert.equal(normalizeSignature(body), "0x" + body);
});

test("mixed-case no-prefix is normalized to 0x + lowercase", () => {
  const body = "Ab".repeat(64) + "1B";
  assert.equal(normalizeSignature(body), "0x" + body.toLowerCase());
});

test("rejects wrong length", () => {
  assert.equal(normalizeSignature("0x" + "ab".repeat(64)), null);
  assert.equal(normalizeSignature("0xdead"), null);
});

test("rejects non-hex characters", () => {
  assert.equal(normalizeSignature("0x" + "zz".repeat(64) + "1b"), null);
});

test("rejects empty string", () => {
  assert.equal(normalizeSignature(""), null);
});
