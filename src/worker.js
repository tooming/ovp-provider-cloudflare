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
                   verificationToken: null, secretHash: null, mechanicsRaw: new Map(),
                   pendingResetToken: null };
  for (const ev of events) {
    const t = ev.type, d = ev.data || {};
    if (t === "WorkshopRegistered") {
      state.domain = d.domain; state.name = d.name;
      state.verificationToken = d.verificationToken; state.secretHash = d.secretHash;
    } else if (t === "WorkshopDomainVerified") {
      state.verified = true; state.verifiedAt = ev.occurredAt;
    } else if (t === "WorkshopSecretResetRequested") {
      state.pendingResetToken = d.resetToken;
    } else if (t === "WorkshopSecretReset") {
      state.secretHash = d.secretHash;
      state.pendingResetToken = null; // challenge consumed
    } else if (t === "WorkshopMechanicAdded") {
      state.mechanicsRaw.set(d.mechanicId, { name: d.name, email: d.email || null, secretHash: d.secretHash });
    } else if (t === "WorkshopMechanicRemoved") {
      state.mechanicsRaw.delete(d.mechanicId);
    } else if (t === "WorkshopMechanicSecretReset") {
      const mech = state.mechanicsRaw.get(d.mechanicId);
      if (mech) mech.secretHash = d.secretHash;
    }
  }
  // Sanitized list for anything that goes out over the wire -- secretHash
  // never leaves this process, and neither does the raw email (this
  // endpoint is unauthenticated/public; an address is real PII, unlike a
  // first name, so only whether OTP sign-in is available gets shown).
  state.mechanics = [...state.mechanicsRaw].map(([mechanicId, m]) =>
    ({ mechanicId, name: m.name, hasEmail: !!m.email }));
  return state;
}

function findMechanicByEmail(state, email) {
  for (const [mechanicId, m] of state.mechanicsRaw) {
    if (m.email === email) return mechanicId;
  }
  return null;
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
    "shown again. Lost it? POST /v1/workshops/{domain}/secret/reset/start " +
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

async function startSecretReset(request, env, domain) {
  // Deliberately NOT re-checking verificationToken: that's permanent and
  // world-readable via a plain GET /v1/workshops/{domain} (needed so the
  // owner can copy it into their DNS panel), so it stays valid and
  // replayable forever once added -- anyone who simply reads it back off
  // the public API could steal a fresh secret at any time, with no proof
  // they hold live DNS write access right now. A fresh, one-time
  // challenge -- disclosed only in this response and checked against its
  // own DNS name -- requires actually adding something to DNS *after*
  // seeing it, the same bar initial verification cleared, not a
  // permanently-satisfied one.
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);

  // Use the token already in hand (just-minted, or the one already in
  // `state`) rather than re-reading it back -- KV's list() is only
  // eventually consistent, so a re-read right after this append can
  // still return the *previous* (or no) token.
  let resetToken = state.pendingResetToken;
  if (!resetToken) {
    resetToken = randomToken();
    await appendWorkshopEvent(env, domain, newWorkshopEvent(
      "WorkshopSecretResetRequested", { resetToken }));
  }
  return json({
    domain,
    dnsRecord: {
      type: "TXT", name: `_ovp-reset.${domain}`,
      value: `ovp-reset=${resetToken}`,
    },
    note: "Add this DNS TXT record -- separate from the permanent " +
      "verification one -- then call confirm. Remove it afterward: " +
      "unlike the verification record, this one is meant to be " +
      "temporary, so a stale reset attempt can't be replayed by " +
      "someone else later.",
  });
}

async function confirmSecretReset(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  if (!state.pendingResetToken) {
    return json({ error: "no reset in progress -- call .../secret/reset/start first" }, 400);
  }

  const expected = `ovp-reset=${state.pendingResetToken}`;
  let found;
  try {
    found = await dnsTxtLookup(`_ovp-reset.${state.domain}`);
  } catch (e) {
    return json({ error: `DNS check failed: ${e}` });
  }
  if (!found.includes(expected)) {
    return json({ found, dnsRecord: { type: "TXT", name: `_ovp-reset.${domain}`, value: expected } });
  }

  const newSecret = randomSecret();
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopSecretReset", { secretHash: await secretHash(newSecret) }));
  return json({ workshopSecret: newSecret,
    note: "Save this now -- it won't be shown again. You can remove the _ovp-reset TXT record now." });
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
  const email = (body.email || "").trim().toLowerCase();
  if (!name) return json({ error: "name required" }, 400);

  const mechanicId = randomToken(6);
  const mechanicSecret = randomSecret();
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopMechanicAdded",
    { mechanicId, name, email: email || null, secretHash: await secretHash(mechanicSecret) }));
  const view = workshopView(await getWorkshop(env, domain));
  view.mechanicId = mechanicId;
  view.mechanicSecret = mechanicSecret;
  view.note = "Save mechanicSecret now and hand it to the mechanic -- it " +
    "lets them sign in (same sign-in box as the workshop secret) and log " +
    "events attributed to themself. Won't be shown again; if lost, " +
    (email ? "they can fetch a fresh one themselves via email (see the " +
      "\"sign in with email\" option), or you can remove and re-add them."
      : "remove and re-add them.");
  return json(view, 201);
}

// --- Mechanic OTP challenges: deliberately NOT event-sourced ---------------
// Everything else here is an immutable, hash-chained event because it's
// meant to be permanent history. A one-time login code is the opposite:
// only ever meaningful for ~10 minutes, and keeping it around (even
// hashed) after it expires serves no one. Stored as a plain KV entry with
// expirationTtl instead -- Cloudflare deletes it on its own.

function otpKey(domain, mechanicId) {
  return `MECHOTP#${workshopDomain(domain)}#${mechanicId}`;
}

async function storeOtp(env, domain, mechanicId, code, ttlSeconds = 600) {
  await env.PASSPORTS.put(otpKey(domain, mechanicId), await secretHash(code), { expirationTtl: ttlSeconds });
}

async function checkAndConsumeOtp(env, domain, mechanicId, code) {
  const key = otpKey(domain, mechanicId);
  const stored = await env.PASSPORTS.get(key);
  if (!stored) return false;
  if (stored !== (await secretHash(code))) return false;
  await env.PASSPORTS.delete(key); // one-time use
  return true;
}

async function sendEmail(env, to, subject, text) {
  // Thin wrapper around Resend's HTTP API -- not a queue/retry system: an
  // OTP is useless a minute late, so a failed send should surface
  // immediately, not get silently swallowed. Requires RESEND_API_KEY
  // (set via `wrangler secret put RESEND_API_KEY`); with none configured,
  // this throws rather than pretending to succeed.
  if (!env.RESEND_API_KEY) throw new Error("RESEND_API_KEY not configured on this provider");
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ from: env.RESEND_FROM || "onboarding@resend.dev", to: [to], subject, text }),
  });
  if (!resp.ok) throw new Error(`Resend API returned HTTP ${resp.status}`);
  return resp.json();
}

async function requestMechanicOtp(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  if (!email) return json({ error: "email required" }, 400);

  // Always the same generic response regardless of a match -- this must
  // not become a way to enumerate who works at a given shop.
  const mechanicId = findMechanicByEmail(state, email);
  if (mechanicId) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await storeOtp(env, domain, mechanicId, code);
    try {
      await sendEmail(env, email, "Your Open Vehicle Passport sign-in code",
        `Your one-time code is ${code}. It expires in 10 minutes.\n\n` +
        `If you didn't request this, ignore this email.`);
    } catch (e) {
      return json({ error: `could not send email: ${e}` }, 502);
    }
  }
  return json({ sent: true, note: "If that email is on file for this workshop, a code was sent." });
}

async function verifyMechanicOtp(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  const code = (body.code || "").trim();
  if (!email || !code) return json({ error: "email and code required" }, 400);

  const mechanicId = findMechanicByEmail(state, email);
  if (!mechanicId || !(await checkAndConsumeOtp(env, domain, mechanicId, code))) {
    return json({ error: "invalid or expired code" }, 403);
  }

  const mechanicSecret = randomSecret();
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopMechanicSecretReset", { mechanicId, secretHash: await secretHash(mechanicSecret) }));
  const mech = state.mechanicsRaw.get(mechanicId);
  return json({ mechanicId, name: mech.name, mechanicSecret,
    note: "Save this now -- it won't be shown again." });
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

    m = path.match(/^\/v1\/workshops\/([^/]+)\/secret\/reset\/start$/);
    if (m && method === "POST") return startSecretReset(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/secret\/reset\/confirm$/);
    if (m && method === "POST") return confirmSecretReset(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics\/otp\/request$/);
    if (m && method === "POST") return requestMechanicOtp(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics\/otp\/verify$/);
    if (m && method === "POST") return verifyMechanicOtp(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics\/([^/]+)$/);
    if (m && method === "DELETE") return removeMechanic(request, env, m[1], m[2]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics$/);
    if (m && method === "POST") return addMechanic(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)$/);
    if (m && method === "GET") return readWorkshop(request, env, m[1]);

    return json({ error: "no such route" }, 404);
  },
};
