// Exercises worker.js's HTTP routes end-to-end against fakes for its two
// Cloudflare dependencies (KV and the PassportSequencer Durable Object),
// rather than mocking worker.js's own internals -- the fakes are just
// plain JS objects with the same get/put/delete/list (KV) and
// fetch/idFromName (DO namespace) shapes wrangler provides at runtime, so
// these tests run under plain `node --test`, no wrangler/workerd needed.
import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { PassportSequencer } from "../src/worker.js";

function makeEnv() {
  const kv = new Map();
  const PASSPORTS = {
    async get(key) {
      return kv.has(key) ? kv.get(key) : null;
    },
    async put(key, value) {
      kv.set(key, value);
    },
    async delete(key) {
      kv.delete(key);
    },
    async list({ prefix, cursor } = {}) {
      const keys = [...kv.keys()]
        .filter((k) => !prefix || k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys, cursor: undefined };
    },
  };

  const doInstances = new Map();
  const PASSPORT_SEQUENCER = {
    idFromName: (name) => name,
    get: (id) => ({
      async fetch(_url, opts) {
        if (!doInstances.has(id)) {
          const storage = new Map();
          doInstances.set(
            id,
            new PassportSequencer(
              {
                storage: {
                  get: async (k) => (storage.has(k) ? storage.get(k) : undefined),
                  put: async (k, v) => {
                    storage.set(k, v);
                  },
                },
              },
              env,
            ),
          );
        }
        return doInstances.get(id).fetch({ json: async () => JSON.parse(opts.body) });
      },
    }),
  };

  const env = {
    PASSPORTS,
    PASSPORT_SEQUENCER,
    SESSION_SIGNING_KEY: "test-signing-key",
    POSTMARK_API_TOKEN: "test-postmark-token",
    POSTMARK_FROM: "noreply@test.example",
  };
  return env;
}

function req(method, path, { token, body } = {}) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = "Bearer " + token;
  return new Request(`http://provider.test${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function call(env, method, path, opts) {
  const resp = await worker.fetch(req(method, path, opts), env);
  const text = await resp.text();
  return { status: resp.status, body: text ? JSON.parse(text) : null };
}

// Postmark is the only outbound network call this touches (OTP emails) --
// stubbed so tests never hit the real network, and the OTP code itself is
// made deterministic by stubbing Math.random for the duration of the
// request (the same trick used elsewhere below).
async function signUpUser(env, email) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("{}", { status: 200 });
  const realRandom = Math.random;
  Math.random = () => 0; // -> code "100000"
  try {
    const sent = await call(env, "POST", "/v1/auth/otp/request", { body: { email } });
    assert.equal(sent.status, 200);
  } finally {
    Math.random = realRandom;
    globalThis.fetch = realFetch;
  }
  const verified = await call(env, "POST", "/v1/auth/otp/verify", { body: { email, code: "100000" } });
  assert.equal(verified.status, 200, JSON.stringify(verified.body));
  return verified.body.token;
}

test("passport creation records the creator as owner", async () => {
  const env = makeEnv();
  const ownerToken = await signUpUser(env, "owner@example.com");

  const created = await call(env, "POST", "/v1/passports", { token: ownerToken, body: {} });
  assert.equal(created.status, 201);
  assert.equal(created.body.owner, "owner@example.com");

  const read = await call(env, "GET", `/v1/passports/${created.body.id}`);
  assert.equal(read.status, 200);
  assert.equal(read.body.owner, "owner@example.com");
  assert.equal(read.body.event_count, 1); // the AccessGranted{role:"owner"} event
});

test("owner appends land directly; a non-owner's append becomes a pending contribution", async () => {
  const env = makeEnv();
  const ownerToken = await signUpUser(env, "owner@example.com");
  const otherToken = await signUpUser(env, "someone-else@example.com");

  const created = await call(env, "POST", "/v1/passports", { token: ownerToken, body: {} });
  const id = created.body.id;

  const ownEvent = {
    "@context": "https://openvehiclepassport.org/ns/v0.1",
    id: "urn:uuid:00000000-0000-7000-8000-000000000001",
    type: "OdometerReading",
    specVersion: "0.1",
    vehicle: `urn:ovpf:${id}`,
    occurredAt: "2026-01-01T00:00:00Z",
    recordedAt: "2026-01-01T00:00:00Z",
    producer: { type: "Manual", name: "owner-app" },
    data: { value: 1000, unit: "KMT" },
  };
  const ownAppend = await call(env, "POST", `/v1/passports/${id}/events`, { token: ownerToken, body: ownEvent });
  assert.equal(ownAppend.status, 201, JSON.stringify(ownAppend.body));

  const otherEvent = { ...ownEvent, id: "urn:uuid:00000000-0000-7000-8000-000000000002", data: { value: 1500, unit: "KMT" } };
  const otherAppend = await call(env, "POST", `/v1/passports/${id}/events`, { token: otherToken, body: otherEvent });
  assert.equal(otherAppend.status, 202);
  assert.equal(otherAppend.body.pending, true);
  const pendingId = otherAppend.body.pendingId;

  // Not yet in the log.
  const readBefore = await call(env, "GET", `/v1/passports/${id}`);
  assert.equal(readBefore.body.event_count, 2); // AccessGranted + the owner's own append

  // Only the owner can list/decide it.
  const listForbidden = await call(env, "GET", `/v1/passports/${id}/pending`, { token: otherToken });
  assert.equal(listForbidden.status, 403);

  const list = await call(env, "GET", `/v1/passports/${id}/pending`, { token: ownerToken });
  assert.equal(list.status, 200);
  assert.equal(list.body.pending.length, 1);
  assert.equal(list.body.pending[0].submitter, "someone-else@example.com");

  const denied = await call(env, "POST", `/v1/passports/${id}/pending/${pendingId}`, {
    token: ownerToken, body: { decision: "deny" },
  });
  assert.equal(denied.status, 200);
  assert.equal(denied.body.decision, "deny");

  const readAfterDeny = await call(env, "GET", `/v1/passports/${id}`);
  assert.equal(readAfterDeny.body.event_count, 2); // unchanged -- denial leaves no trace in the log

  const listAfterDeny = await call(env, "GET", `/v1/passports/${id}/pending`, { token: ownerToken });
  assert.equal(listAfterDeny.body.pending.length, 0);
});

test("always_allow grants auto-accept future appends from the same submitter", async () => {
  const env = makeEnv();
  const ownerToken = await signUpUser(env, "owner@example.com");
  const otherToken = await signUpUser(env, "contributor@example.com");
  const created = await call(env, "POST", "/v1/passports", { token: ownerToken, body: {} });
  const id = created.body.id;

  const baseEvent = {
    "@context": "https://openvehiclepassport.org/ns/v0.1",
    type: "OdometerReading",
    specVersion: "0.1",
    vehicle: `urn:ovpf:${id}`,
    occurredAt: "2026-01-01T00:00:00Z",
    recordedAt: "2026-01-01T00:00:00Z",
    producer: { type: "Manual", name: "contributor-app" },
    data: { value: 1000, unit: "KMT" },
  };

  const first = await call(env, "POST", `/v1/passports/${id}/events`, {
    token: otherToken, body: { ...baseEvent, id: "urn:uuid:00000000-0000-7000-8000-000000000010" },
  });
  assert.equal(first.status, 202);

  const decided = await call(env, "POST", `/v1/passports/${id}/pending/${first.body.pendingId}`, {
    token: ownerToken, body: { decision: "always_allow" },
  });
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(decided.body.event.data.value, 1000);

  const second = await call(env, "POST", `/v1/passports/${id}/events`, {
    token: otherToken,
    body: { ...baseEvent, id: "urn:uuid:00000000-0000-7000-8000-000000000011", recordedAt: "2026-01-02T00:00:00Z", data: { value: 2000, unit: "KMT" } },
  });
  assert.equal(second.status, 201, JSON.stringify(second.body)); // lands directly now, no prompt

  const state = await call(env, "GET", `/v1/passports/${id}`);
  assert.equal(state.body.event_count, 3); // AccessGranted + the two contributor events
});

test("ownership transfer requires the proposed new owner's explicit acceptance, resets grants", async () => {
  const env = makeEnv();
  const ownerToken = await signUpUser(env, "owner@example.com");
  const newOwnerToken = await signUpUser(env, "new-owner@example.com");
  const contributorToken = await signUpUser(env, "contributor@example.com");
  const created = await call(env, "POST", "/v1/passports", { token: ownerToken, body: {} });
  const id = created.body.id;

  // Give contributor an always-allow grant before the transfer.
  const contribEvent = {
    "@context": "https://openvehiclepassport.org/ns/v0.1",
    id: "urn:uuid:00000000-0000-7000-8000-000000000020",
    type: "OdometerReading",
    specVersion: "0.1",
    vehicle: `urn:ovpf:${id}`,
    occurredAt: "2026-01-01T00:00:00Z",
    recordedAt: "2026-01-01T00:00:00Z",
    producer: { type: "Manual", name: "contributor-app" },
    data: { value: 1000, unit: "KMT" },
  };
  const pendingResp = await call(env, "POST", `/v1/passports/${id}/events`, { token: contributorToken, body: contribEvent });
  await call(env, "POST", `/v1/passports/${id}/pending/${pendingResp.body.pendingId}`, {
    token: ownerToken, body: { decision: "always_allow" },
  });

  // A non-owner cannot initiate a transfer.
  const forbidden = await call(env, "POST", `/v1/passports/${id}/transfer`, {
    token: contributorToken, body: { email: "new-owner@example.com" },
  });
  assert.equal(forbidden.status, 403);

  const initiated = await call(env, "POST", `/v1/passports/${id}/transfer`, {
    token: ownerToken, body: { email: "new-owner@example.com" },
  });
  assert.equal(initiated.status, 200);

  // The old owner still controls the passport until acceptance.
  const stillOwner = await call(env, "GET", `/v1/passports/${id}`);
  assert.equal(stillOwner.body.owner, "owner@example.com");

  // Only the proposed new owner may accept.
  const wrongAccept = await call(env, "POST", `/v1/passports/${id}/transfer/accept`, { token: ownerToken });
  assert.equal(wrongAccept.status, 403);

  const accepted = await call(env, "POST", `/v1/passports/${id}/transfer/accept`, { token: newOwnerToken });
  assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
  assert.equal(accepted.body.transferred, true);

  const afterTransfer = await call(env, "GET", `/v1/passports/${id}`);
  assert.equal(afterTransfer.body.owner, "new-owner@example.com");

  // The old owner is now just another non-owner submitter.
  const oldOwnerAppend = await call(env, "POST", `/v1/passports/${id}/events`, {
    token: ownerToken,
    body: { ...contribEvent, id: "urn:uuid:00000000-0000-7000-8000-000000000021", recordedAt: "2026-01-03T00:00:00Z" },
  });
  assert.equal(oldOwnerAppend.status, 202);

  // The contributor's previous always-allow grant did not carry over.
  const contributorAppend = await call(env, "POST", `/v1/passports/${id}/events`, {
    token: contributorToken,
    body: { ...contribEvent, id: "urn:uuid:00000000-0000-7000-8000-000000000022", recordedAt: "2026-01-04T00:00:00Z" },
  });
  assert.equal(contributorAppend.status, 202);
});

test("a pending transfer can be cancelled by the current owner", async () => {
  const env = makeEnv();
  const ownerToken = await signUpUser(env, "owner@example.com");
  const created = await call(env, "POST", "/v1/passports", { token: ownerToken, body: {} });
  const id = created.body.id;

  await call(env, "POST", `/v1/passports/${id}/transfer`, { token: ownerToken, body: { email: "someone@example.com" } });
  const cancelled = await call(env, "POST", `/v1/passports/${id}/transfer/cancel`, { token: ownerToken });
  assert.equal(cancelled.status, 200);
  assert.equal(cancelled.body.cancelled, true);

  const otherToken = await signUpUser(env, "someone@example.com");
  const acceptAfterCancel = await call(env, "POST", `/v1/passports/${id}/transfer/accept`, { token: otherToken });
  assert.equal(acceptAfterCancel.status, 404);
});
