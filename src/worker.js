/**
 * OVP reference provider (Cloudflare). One Worker, one KV namespace.
 *
 * Same contract as ovp-provider-aws/src/app.py -- same routes, same
 * storage key shape (conceptually: DynamoDB's pk/sk maps onto a single
 * KV key `PASSPORT#<id>#<sk>`, and KV's list({prefix}) returns keys in
 * sorted order for free, same as a DynamoDB Query). Two independently-
 * built providers speaking the same protocol -- that's the point.
 *
 * POC MODE: there is currently no write access control at all -- anyone
 * who knows a passport id (as guessable as the QR code, i.e. not
 * guessable: a UUIDv7 with 62 random bits) can both read and append to
 * it. This was a deliberate simplification for easier POCing (a
 * writeToken model existed and was removed, not just left unenforced --
 * see git history if it needs to come back).
 */
import * as ovpf from "./ovpf-core.js";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function metaKey(id) {
  return `PASSPORT#${id}#META`;
}

function eventKeyPrefix(id) {
  return `PASSPORT#${id}#EVENT#`;
}

function eventKey(id, ev) {
  return `${eventKeyPrefix(id)}${ev.recordedAt}#${ev.id}`;
}

async function loadEvents(env, id) {
  const events = [];
  let cursor;
  do {
    const page = await env.PASSPORTS.list({ prefix: eventKeyPrefix(id), cursor });
    for (const k of page.keys) {
      const v = await env.PASSPORTS.get(k.name);
      if (v) events.push(JSON.parse(v));
    }
    cursor = page.cursor;
  } while (cursor);
  events.sort((a, b) => (a.recordedAt || "").localeCompare(b.recordedAt || "") || (a.id || "").localeCompare(b.id || ""));
  return events;
}

async function getMeta(env, id) {
  const v = await env.PASSPORTS.get(metaKey(id));
  return v ? JSON.parse(v) : null;
}

async function createPassport(request, env) {
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }

  const id = body.id || ovpf.uuid7();
  if (await getMeta(env, id)) {
    return json({ error: "passport already registered with this provider" }, 409);
  }

  await env.PASSPORTS.put(metaKey(id), JSON.stringify({
    createdAt: new Date().toISOString(),
  }));

  return json({ id, readUrl: `/v1/passports/${id}` }, 201);
}

// --- Workshops are event-sourced too, same discipline as vehicle passports:
// an append-only log (key WORKSHOP#<domain>#EVENT#<recordedAt>#<id>),
// hash-chained with the same ovpf-core.js primitives, current state always
// a replay, never a mutated row. WorkshopRegistered / WorkshopDomainVerified
// / WorkshopSecretReset / WorkshopMechanicAdded / WorkshopMechanicRemoved.

function workshopDomain(domain) {
  return (domain || "").trim().toLowerCase().replace(/\.+$/, "");
}

function workshopEventKeyPrefix(domain) {
  return `WORKSHOP#${workshopDomain(domain)}#EVENT#`;
}

function workshopEventKey(domain, ev) {
  return `${workshopEventKeyPrefix(domain)}${ev.recordedAt}#${ev.id}`;
}

function newWorkshopEvent(type, data) {
  const now = new Date().toISOString();
  return { id: "urn:uuid:" + crypto.randomUUID(), type, occurredAt: now, recordedAt: now, data };
}

async function loadWorkshopEvents(env, domain) {
  const events = [];
  let cursor;
  do {
    const page = await env.PASSPORTS.list({ prefix: workshopEventKeyPrefix(domain), cursor });
    for (const k of page.keys) {
      const v = await env.PASSPORTS.get(k.name);
      if (v) events.push(JSON.parse(v));
    }
    cursor = page.cursor;
  } while (cursor);
  events.sort((a, b) => (a.recordedAt || "").localeCompare(b.recordedAt || "") || (a.id || "").localeCompare(b.id || ""));
  return events;
}

async function appendWorkshopEvent(env, domain, ev) {
  const existing = await loadWorkshopEvents(env, domain);
  const prevHash = existing.length ? existing[existing.length - 1].hash : null;
  delete ev.hash;
  if (prevHash) ev.prevHash = prevHash; else delete ev.prevHash;
  ev.hash = await ovpf.eventHash(ev);
  await env.PASSPORTS.put(workshopEventKey(domain, ev), JSON.stringify(ev));
  return ev;
}

function reduceWorkshop(events) {
  const state = { domain: null, name: null, verified: false, verifiedAt: null,
                   verificationToken: null, secretHash: null, mechanicsRaw: new Map() };
  for (const ev of events) {
    const t = ev.type, d = ev.data || {};
    if (t === "WorkshopRegistered") {
      state.domain = d.domain; state.name = d.name;
      state.verificationToken = d.verificationToken; state.secretHash = d.secretHash;
    } else if (t === "WorkshopDomainVerified") {
      state.verified = true; state.verifiedAt = ev.occurredAt;
    } else if (t === "WorkshopSecretReset") {
      state.secretHash = d.secretHash;
    } else if (t === "WorkshopMechanicAdded") {
      state.mechanicsRaw.set(d.mechanicId, { name: d.name, secretHash: d.secretHash });
    } else if (t === "WorkshopMechanicRemoved") {
      state.mechanicsRaw.delete(d.mechanicId);
    }
  }
  // Sanitized list for anything that goes out over the wire -- secretHash
  // never leaves this process. mechanicsRaw (with secretHash) stays only
  // for matchProducerSecret to check against.
  state.mechanics = [...state.mechanicsRaw].map(([mechanicId, m]) => ({ mechanicId, name: m.name }));
  return state;
}

async function getWorkshop(env, domain) {
  const events = await loadWorkshopEvents(env, workshopDomain(domain));
  return events.length ? reduceWorkshop(events) : null;
}

function workshopView(state) {
  return {
    domain: state.domain,
    name: state.name,
    verified: !!state.verified,
    verifiedAt: state.verifiedAt || null,
    verificationToken: state.verificationToken,
    mechanics: state.mechanics,
    dnsRecord: {
      type: "TXT",
      name: `_ovp-verify.${state.domain}`,
      value: `ovp-verify=${state.verificationToken}`,
    },
  };
}

function randomToken(bytesLen = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(bytesLen));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function secretHash(secret) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function bearerToken(request) {
  const auth = request.headers.get("authorization") || "";
  return auth.toLowerCase().startsWith("bearer ") ? auth.slice(7) : "";
}

async function checkSecret(state, request) {
  // Bearer <workshopSecret> -- proves this request holds the workshop
  // identity, not just that it knows a verified domain name exists.
  // Without this, anyone could claim producer.domain: "skoor.ee" and get
  // the checkmark -- found and fixed live, this was a real gap. Only the
  // master secret passes this -- admin actions (add/remove a mechanic,
  // reset this secret) are deliberately not delegable to a mechanic's own
  // secret, see matchProducerSecret.
  const token = bearerToken(request);
  return !!token && state.secretHash === (await secretHash(token));
}

async function matchProducerSecret(workshop, token) {
  // Whoever holds a secret this workshop recognizes IS that identity --
  // there's no separate id to send. Returns {role:"workshop"} for the
  // master secret, {role:"mechanic", mechanicId} for a specific
  // mechanic's own secret, or null. Deliberately the *only* thing a
  // mechanic secret can do (get attributed on a logged event) -- never
  // checked by checkSecret, so it can't add/remove mechanics or reset
  // the master secret.
  if (!token) return null;
  const tokenHash = await secretHash(token);
  if (workshop.secretHash === tokenHash) return { role: "workshop" };
  for (const [mechanicId, mech] of workshop.mechanicsRaw || []) {
    if (mech.secretHash === tokenHash) return { role: "mechanic", mechanicId };
  }
  return null;
}

async function dnsTxtLookup(name) {
  // DNS-over-HTTPS (Cloudflare's own public resolver) -- same approach as
  // app.py's urllib version, just via fetch() here. No DNS library needed
  // on either provider.
  const resp = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
    { headers: { accept: "application/dns-json" } });
  const data = await resp.json();
  const answers = data.Answer || [];
  return answers.filter(a => a.type === 16).map(a => a.data.replace(/^"|"$/g, ""));
}

async function registerWorkshop(request, env) {
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }

  const domain = workshopDomain(body.domain);
  if (!domain || !domain.includes(".")) {
    return json({ error: 'domain required, e.g. "skoor.ee"' }, 400);
  }

  const existing = await getWorkshop(env, domain);
  if (existing) return json(workshopView(existing), 200);

  const workshopSecret = randomSecret();
  await appendWorkshopEvent(env, domain, newWorkshopEvent("WorkshopRegistered", {
    domain, name: body.name || domain,
    verificationToken: randomToken(),
    secretHash: await secretHash(workshopSecret),
  }));

  const view = workshopView(await getWorkshop(env, domain));
  view.workshopSecret = workshopSecret;
  view.note = "Save workshopSecret now -- it authenticates you as this " +
    "workshop (logging verified events, managing mechanics) and won't be " +
    "shown again. Lost it? POST /v1/workshops/{domain}/secret/reset " +
    "while you still control the domain's DNS.";
  return json(view, 201);
}

async function readWorkshop(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  return json(workshopView(state));
}

async function verifyWorkshop(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  if (state.verified) return json(workshopView(state));

  const expected = `ovp-verify=${state.verificationToken}`;
  let found;
  try {
    found = await dnsTxtLookup(`_ovp-verify.${state.domain}`);
  } catch (e) {
    return json({ ...workshopView(state), checkError: String(e) });
  }

  if (!found.includes(expected)) {
    return json({ ...workshopView(state), found });
  }

  await appendWorkshopEvent(env, domain, newWorkshopEvent("WorkshopDomainVerified", {}));
  return json(workshopView(await getWorkshop(env, domain)));
}

async function resetWorkshopSecret(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);

  const expected = `ovp-verify=${state.verificationToken}`;
  let found;
  try {
    found = await dnsTxtLookup(`_ovp-verify.${state.domain}`);
  } catch (e) {
    return json({ error: `DNS check failed: ${e}` });
  }
  if (!found.includes(expected)) {
    return json({ error: "domain does not currently have the expected TXT " +
                          "record -- cannot reset without proving control" }, 403);
  }

  const newSecret = randomSecret();
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopSecretReset", { secretHash: await secretHash(newSecret) }));
  return json({ workshopSecret: newSecret, note: "Save this now -- it won't be shown again." });
}

async function addMechanic(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  if (!(await checkSecret(state, request))) {
    return json({ error: "missing or invalid workshop secret" }, 403);
  }
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const name = (body.name || "").trim();
  if (!name) return json({ error: "name required" }, 400);

  const mechanicId = randomToken(6);
  const mechanicSecret = randomSecret();
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopMechanicAdded", { mechanicId, name, secretHash: await secretHash(mechanicSecret) }));
  const view = workshopView(await getWorkshop(env, domain));
  view.mechanicId = mechanicId;
  view.mechanicSecret = mechanicSecret;
  view.note = "Save mechanicSecret now and hand it to the mechanic -- it " +
    "lets them sign in (same sign-in box as the workshop secret) and log " +
    "events attributed to themself. Won't be shown again; if lost, " +
    "remove and re-add them.";
  return json(view, 201);
}

async function whoamiWorkshop(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  const match = await matchProducerSecret(state, bearerToken(request));
  if (!match) return json({ error: "invalid secret" }, 403);
  if (match.role === "workshop") {
    return json({ role: "workshop", domain, name: state.name });
  }
  const mech = state.mechanicsRaw.get(match.mechanicId);
  return json({ role: "mechanic", domain, mechanicId: match.mechanicId, name: mech.name });
}

async function removeMechanic(request, env, domain, mechanicId) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  if (!(await checkSecret(state, request))) {
    return json({ error: "missing or invalid workshop secret" }, 403);
  }
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopMechanicRemoved", { mechanicId }));
  return json(workshopView(await getWorkshop(env, domain)));
}

async function appendEvent(request, env, id) {
  const meta = await getMeta(env, id);
  if (!meta) return json({ error: "no such passport" }, 404);

  // POC MODE: no write access control at all right now -- see module
  // docstring. Anyone who can reach this passport id can append to it.

  let ev;
  try {
    ev = JSON.parse(await request.text());
  } catch {
    return json({ error: "body must be a single OVPF event envelope" }, 400);
  }

  const required = ["@context", "id", "type", "specVersion", "vehicle", "occurredAt", "recordedAt", "producer", "data"];
  const missing = required.filter(k => !(k in ev));
  if (missing.length) return json({ error: `missing required field(s): ${missing}` }, 400);

  // Server-side provenance stamping (see docs/TRUST.md) -- matches app.py
  // exactly: a client's producer.verified claim is stripped, and only
  // re-added here if this request also proves it holds a secret this
  // workshop recognizes (see matchProducerSecret). Knowing a domain is
  // verified is not the same as being its holder -- found and fixed
  // live, this was a real gap in the first version. Baked into the hash
  // immediately, so a workshop losing verified status later doesn't
  // retroactively change what it attested at the time. The same secret
  // slot serves the workshop's own master secret AND any mechanic's
  // secret -- whichever one matches determines who gets attributed.
  const producer = ev.producer || {};
  delete producer.verified;
  delete producer.verifiedAt;
  delete producer.mechanicId;
  delete producer.mechanicName;
  if (producer.domain) {
    const workshop = await getWorkshop(env, producer.domain);
    if (workshop && workshop.verified) {
      const match = await matchProducerSecret(workshop, bearerToken(request));
      if (match) {
        producer.verified = true;
        producer.verifiedAt = workshop.verifiedAt;
        if (match.role === "mechanic") {
          const mech = workshop.mechanicsRaw.get(match.mechanicId);
          producer.mechanicId = match.mechanicId;
          producer.mechanicName = mech.name;
        }
      }
    }
  }
  ev.producer = producer;

  // recordedAt is producer-set, immutable -- same contract as app.py.
  const existing = await loadEvents(env, id);
  const prevHash = existing.length ? existing[existing.length - 1].hash : null;
  delete ev.hash;
  if (prevHash) ev.prevHash = prevHash; else delete ev.prevHash;
  ev.hash = await ovpf.eventHash(ev);

  const key = eventKey(id, ev);
  const existingItem = await env.PASSPORTS.get(key);
  if (existingItem) return json({ error: "event already exists (duplicate id/recordedAt)" }, 409);
  await env.PASSPORTS.put(key, JSON.stringify(ev));

  return json(ev, 201);
}

async function readPassport(request, env, id) {
  if (!(await getMeta(env, id))) return json({ error: "no such passport" }, 404);
  const events = await loadEvents(env, id);
  const state = events.length ? ovpf.reduce(events) : { event_count: 0 };
  return json(state);
}

async function exportPassport(request, env, id) {
  if (!(await getMeta(env, id))) return json({ error: "no such passport" }, 404);
  const events = await loadEvents(env, id);
  const ndjson = events.map(e => JSON.stringify(e)).join("\n");
  return new Response(ndjson, { status: 200, headers: { "content-type": "application/x-ndjson" } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    if (method === "POST" && path === "/v1/passports") return createPassport(request, env);

    let m = path.match(/^\/v1\/passports\/([^/]+)\/events$/);
    if (m && method === "POST") return appendEvent(request, env, m[1]);

    m = path.match(/^\/v1\/passports\/([^/]+)\/export$/);
    if (m && method === "GET") return exportPassport(request, env, m[1]);

    m = path.match(/^\/v1\/passports\/([^/]+)$/);
    if (m && method === "GET") return readPassport(request, env, m[1]);

    if (method === "POST" && path === "/v1/workshops") return registerWorkshop(request, env);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/whoami$/);
    if (m && method === "GET") return whoamiWorkshop(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/verify$/);
    if (m && method === "POST") return verifyWorkshop(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/secret\/reset$/);
    if (m && method === "POST") return resetWorkshopSecret(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics\/([^/]+)$/);
    if (m && method === "DELETE") return removeMechanic(request, env, m[1], m[2]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics$/);
    if (m && method === "POST") return addMechanic(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)$/);
    if (m && method === "GET") return readWorkshop(request, env, m[1]);

    return json({ error: "no such route" }, 404);
  },
};
