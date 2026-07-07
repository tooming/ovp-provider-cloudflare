// Fixtures under test/fixtures/ are copied from
// openvehiclepassport/conformance/fixtures -- shared, language-agnostic
// test vectors, not an implementation to vendor. Re-copy if that repo's
// fixtures change.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ovpf from "../src/ovpf-core.js";

const dir = fileURLToPath(new URL("./fixtures/", import.meta.url));

test("canonicalization matches the shared cross-language fixtures", () => {
  const cases = JSON.parse(readFileSync(dir + "canonicalization.json", "utf8"));
  for (const { input, canonical } of cases) {
    const got = new TextDecoder().decode(ovpf.canonicalize(input));
    assert.equal(got, canonical, `canonicalize(${JSON.stringify(input)})`);
  }
});

test("whole-number floats canonicalize without a trailing .0", () => {
  assert.equal(new TextDecoder().decode(ovpf.canonicalize(45.0)), "45");
});

test("reduce() on the shared e39 fixture matches the Python reference's derived state", async () => {
  const ndjson = readFileSync(dir + "e39-passport.input.ndjson", "utf8");
  const events = ndjson.trim().split("\n").map(l => JSON.parse(l));
  const expected = JSON.parse(readFileSync(dir + "e39-passport.expected-state.json", "utf8"));

  const problems = await ovpf.verifyChain(events);
  assert.deepEqual(problems, [], "hash chain must verify");

  const state = ovpf.reduce(events);
  assert.deepEqual(state, expected, "derived state must match the Python reference byte-for-byte (after JSON parse)");
});

test("seal/verify round-trip", async () => {
  const events = [
    ovpf.envelope("urn:ovpf:x", "PassportOpened", { vehicle: { vin: "ABC" } }, { type: "Manual", name: "t" }),
    ovpf.envelope("urn:ovpf:x", "OdometerReading", { value: 100, unit: "KMT" }, { type: "Manual", name: "t" }),
  ];
  await ovpf.seal(events);
  assert.deepEqual(await ovpf.verifyChain(events), []);
  events[1].data.value = 999; // tamper after sealing
  const problems = await ovpf.verifyChain(events);
  assert.ok(problems.some(p => p.includes("hash mismatch")));
});

test("merge unions by id and flags real conflicts", () => {
  const a = [{ id: "1", occurredAt: "2026-01-01T00:00:00Z", type: "X", data: {} }];
  const b = [{ id: "1", occurredAt: "2026-01-01T00:00:00Z", type: "X", data: { changed: true } }];
  const [merged, conflicts] = ovpf.merge(a, b);
  assert.equal(merged.length, 1);
  assert.deepEqual(conflicts, ["1"]);
});
