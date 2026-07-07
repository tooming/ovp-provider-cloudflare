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
// / WorkshopOwnerEmailClaimRequested / WorkshopOwnerEmailSet /
// WorkshopMechanicAdded / WorkshopMechanicRemoved.
//
// There is no standing secret anywhere in this system -- login (owner or
// mechanic) is always OTP: prove you control an email already on file, get
// handed a signed, time-limited session token. The only thing DNS proves
// here is which email is *allowed* to claim the owner role in the first
// place (domain control remains the root of trust for that) -- once
// claimed, day-to-day sign-in never touches DNS again.

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
                   verificationToken: null, ownerEmail: null,
                   pendingOwnerEmailClaim: null, mechanicsRaw: new Map() };
  for (const ev of events) {
    const t = ev.type, d = ev.data || {};
    if (t === "WorkshopRegistered") {
      state.domain = d.domain; state.name = d.name;
      state.verificationToken = d.verificationToken;
    } else if (t === "WorkshopDomainVerified") {
      state.verified = true; state.verifiedAt = ev.occurredAt;
    } else if (t === "WorkshopOwnerEmailClaimRequested") {
      state.pendingOwnerEmailClaim = { email: d.email, token: d.token };
    } else if (t === "WorkshopOwnerEmailSet") {
      state.ownerEmail = d.email;
      state.pendingOwnerEmailClaim = null;
    } else if (t === "WorkshopMechanicAdded") {
      state.mechanicsRaw.set(d.mechanicId, { name: d.name, email: d.email || null });
    } else if (t === "WorkshopMechanicRemoved") {
      state.mechanicsRaw.delete(d.mechanicId);
    }
    // WorkshopSecretResetRequested/WorkshopSecretReset/WorkshopMechanicSecretReset:
    // legacy events from before the OTP-only redesign, replayed harmlessly
    // (nothing left in current state reads them). A mechanic added under
    // the old secret system with no email on file has no way to sign in
    // anymore -- the owner needs to remove and re-add them with one.
  }
  // Sanitized list for anything that goes out over the wire -- an email is
  // real PII on an otherwise-unauthenticated endpoint, unlike a first
  // name, so only whether OTP sign-in is available (hasEmail) is shown.
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

function findLoginIdentity(state, email) {
  // One sign-in box, one lookup -- whichever matches (the workshop's
  // registered owner email, or a mechanic's) decides the role.
  if (state.ownerEmail && state.ownerEmail === email) return { role: "workshop", mechanicId: null };
  const mechanicId = findMechanicByEmail(state, email);
  if (mechanicId) return { role: "mechanic", mechanicId };
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
    ownerEmailSet: !!state.ownerEmail,
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

async function secretHash(secret) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function bearerToken(request) {
  const auth = request.headers.get("authorization") || "";
  return auth.toLowerCase().startsWith("bearer ") ? auth.slice(7) : "";
}

// --- Signed session tokens -- no server-side session storage at all.
// Whoever holds one IS the identity inside it, exactly the trust model
// the old workshop/mechanic secrets had, except this one is only ever
// handed out after an OTP proves the holder currently controls the
// email on file (see verifyOtp), expires on its own, and costs nothing
// to issue (no row written, unlike a secret).

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hmacSign(keyString, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(keyString), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, dataBytes));
}

async function issueSessionToken(env, domain, role, email, mechanicId, name, ttlSeconds = 30 * 24 * 3600) {
  if (!env.SESSION_SIGNING_KEY) throw new Error("SESSION_SIGNING_KEY not configured on this provider");
  const payload = {
    domain, role, email, mechanicId: mechanicId || null, name,
    exp: Math.floor(Date.now() / 1000) + ttlSeconds,
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const sig = await hmacSign(env.SESSION_SIGNING_KEY, payloadBytes);
  return `${b64urlEncode(payloadBytes)}.${b64urlEncode(sig)}`;
}

async function verifySessionToken(env, token) {
  // Recomputes the signature -- no lookup, no store. An expired or
  // tampered token (or one signed with a since-rotated key) fails here;
  // a token for a mechanic since removed, or an owner email since
  // changed, fails the *next* check in matchProducerSession instead,
  // which re-reads live state rather than trusting the token forever.
  if (!env.SESSION_SIGNING_KEY || !token || !token.includes(".")) return null;
  const idx = token.lastIndexOf(".");
  let payloadBytes, sig;
  try {
    payloadBytes = b64urlDecode(token.slice(0, idx));
    sig = b64urlDecode(token.slice(idx + 1));
  } catch {
    return null;
  }
  const expectedSig = await hmacSign(env.SESSION_SIGNING_KEY, payloadBytes);
  if (!timingSafeEqual(sig, expectedSig)) return null;
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

async function matchProducerSession(workshop, env, token) {
  // Returns {role:"workshop"} for a valid owner session,
  // {role:"mechanic", mechanicId} for a valid mechanic session, or null.
  // Deliberately re-checks live state on every call rather than trusting
  // the token's embedded claims: removing a mechanic, or changing the
  // owner email, revokes any outstanding session for that identity
  // immediately, without needing a separate revocation list.
  const payload = await verifySessionToken(env, token);
  if (!payload || payload.domain !== workshop.domain) return null;
  if (payload.role === "workshop") {
    if (payload.email && payload.email === workshop.ownerEmail) return { role: "workshop" };
    return null;
  }
  if (payload.role === "mechanic") {
    const mech = workshop.mechanicsRaw.get(payload.mechanicId);
    if (mech && mech.email === payload.email) return { role: "mechanic", mechanicId: payload.mechanicId };
  }
  return null;
}

async function checkOwnerSession(state, env, request) {
  // Gate for admin-only actions (add/remove a mechanic, claim/change the
  // owner email). Only a role=="workshop" session passes -- a mechanic's
  // own session is deliberately never enough, see matchProducerSession.
  const match = await matchProducerSession(state, env, bearerToken(request));
  return !!match && match.role === "workshop";
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

  await appendWorkshopEvent(env, domain, newWorkshopEvent("WorkshopRegistered", {
    domain, name: body.name || domain,
    verificationToken: randomToken(),
  }));

  const view = workshopView(await getWorkshop(env, domain));
  view.note = "Verify the domain via DNS (POST .../verify), then claim your " +
    "owner login email (POST .../owner-email/start) to be able to sign in " +
    "and manage mechanics.";
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

async function startOwnerEmailClaim(request, env, domain) {
  // Begin claiming (or changing) the email that's allowed to sign in as
  // this workshop's owner, by minting a fresh, one-time DNS challenge on
  // a name separate from the permanent verification record.
  //
  // Deliberately NOT reusing verifyWorkshop's check: that
  // verificationToken is permanent and world-readable via a plain
  // GET /v1/workshops/{domain} (needed so the owner can copy it into
  // their DNS panel), so it stays valid and repeatable forever once
  // added -- anyone who simply reads it back off the public API could
  // replay it and claim owner-email rights at any time, with no proof
  // they hold live DNS write access right now. A fresh challenge,
  // disclosed only in this response and checked against its own DNS
  // name, requires the caller to actually add something to DNS *after*
  // seeing it -- exactly the same bar initial verification cleared, not
  // a permanently-satisfied one. This is the only place DNS matters for
  // login at all; day-to-day sign-in afterward is pure OTP.
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

  let token;
  const pending = state.pendingOwnerEmailClaim;
  if (pending && pending.email === email) {
    token = pending.token;
  } else {
    token = randomToken();
    await appendWorkshopEvent(env, domain, newWorkshopEvent(
      "WorkshopOwnerEmailClaimRequested", { email, token }));
  }
  return json({
    domain, email,
    dnsRecord: { type: "TXT", name: `_ovp-owner.${domain}`, value: `ovp-owner=${token}` },
    note: "Add this DNS TXT record -- separate from the permanent " +
      "verification one -- then call confirm. Remove it afterward. " +
      "Needed once (or again if you ever change the owner email) -- " +
      "day-to-day sign-in afterward is just OTP, no DNS involved.",
  });
}

async function confirmOwnerEmailClaim(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  const pending = state.pendingOwnerEmailClaim;
  if (!pending) return json({ error: "no claim in progress -- call .../owner-email/start first" }, 400);

  const expected = `ovp-owner=${pending.token}`;
  let found;
  try {
    found = await dnsTxtLookup(`_ovp-owner.${state.domain}`);
  } catch (e) {
    return json({ error: `DNS check failed: ${e}` });
  }
  if (!found.includes(expected)) {
    return json({ found, dnsRecord: { type: "TXT", name: `_ovp-owner.${domain}`, value: expected } });
  }

  await appendWorkshopEvent(env, domain, newWorkshopEvent("WorkshopOwnerEmailSet", { email: pending.email }));
  return json({ email: pending.email,
    note: "Owner email set. Sign in any time via OTP with this address. " +
      "You can remove the _ovp-owner TXT record now." });
}

async function addMechanic(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  if (!(await checkOwnerSession(state, env, request))) {
    return json({ error: "missing or invalid owner session -- sign in via OTP first" }, 403);
  }
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  const name = (body.name || "").trim();
  if (!email) return json({ error: "email required" }, 400);

  const mechanicId = randomToken(6);
  await appendWorkshopEvent(env, domain, newWorkshopEvent(
    "WorkshopMechanicAdded", { mechanicId, name: name || email, email }));
  const view = workshopView(await getWorkshop(env, domain));
  view.mechanicId = mechanicId;
  view.note = "Mechanic added. They sign in with this email via OTP -- no secret to hand over.";
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
  // Thin wrapper around Postmark's HTTP API -- not a queue/retry system:
  // an OTP is useless a minute late, so a failed send should surface
  // immediately, not get silently swallowed. Requires POSTMARK_API_TOKEN
  // (set via `wrangler secret put POSTMARK_API_TOKEN`) and POSTMARK_FROM;
  // with no token configured, this throws rather than pretending to
  // succeed.
  if (!env.POSTMARK_API_TOKEN) throw new Error("POSTMARK_API_TOKEN not configured on this provider");
  const resp = await fetch("https://api.postmarkapp.com/email", {
    method: "POST",
    headers: {
      "X-Postmark-Server-Token": env.POSTMARK_API_TOKEN,
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      From: env.POSTMARK_FROM, To: to, Subject: subject, TextBody: text,
      MessageStream: "outbound",
    }),
  });
  if (!resp.ok) throw new Error(`Postmark API returned HTTP ${resp.status}`);
  return resp.json();
}

async function requestOtp(request, env, domain) {
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
  // not become a way to enumerate the owner's address or who works at a
  // given shop.
  const identity = findLoginIdentity(state, email);
  if (identity) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await storeOtp(env, domain, identity.mechanicId || "OWNER", code);
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

async function verifyOtp(request, env, domain) {
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

  const identity = findLoginIdentity(state, email);
  if (!identity || !(await checkAndConsumeOtp(env, domain, identity.mechanicId || "OWNER", code))) {
    return json({ error: "invalid or expired code" }, 403);
  }

  const name = identity.role === "workshop" ? state.name : state.mechanicsRaw.get(identity.mechanicId).name;
  let token;
  try {
    token = await issueSessionToken(env, domain, identity.role, email, identity.mechanicId, name);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
  return json({ token, role: identity.role, domain, mechanicId: identity.mechanicId, name });
}

async function whoamiWorkshop(request, env, domain) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  const match = await matchProducerSession(state, env, bearerToken(request));
  if (!match) return json({ error: "invalid or expired session" }, 403);
  if (match.role === "workshop") {
    return json({ role: "workshop", domain, name: state.name });
  }
  const mech = state.mechanicsRaw.get(match.mechanicId);
  return json({ role: "mechanic", domain, mechanicId: match.mechanicId, name: mech.name });
}

async function removeMechanic(request, env, domain, mechanicId) {
  const state = await getWorkshop(env, domain);
  if (!state) return json({ error: "no such workshop registered" }, 404);
  if (!(await checkOwnerSession(state, env, request))) {
    return json({ error: "missing or invalid owner session -- sign in via OTP first" }, 403);
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
  // re-added here if this request also presents a valid, unexpired
  // session token for this workshop (see matchProducerSession). Knowing
  // a domain is verified is not the same as being its holder -- found
  // and fixed live, this was a real gap in the first version. Baked into
  // the hash immediately, so a workshop losing verified status later
  // doesn't retroactively change what it attested at the time. Sessions
  // are only ever issued via OTP (see requestOtp/verifyOtp) -- there is
  // no standing secret to leak, share, or forget to rotate.
  const producer = ev.producer || {};
  delete producer.verified;
  delete producer.verifiedAt;
  delete producer.mechanicId;
  delete producer.mechanicName;
  if (producer.domain) {
    const workshop = await getWorkshop(env, producer.domain);
    if (workshop && workshop.verified) {
      const match = await matchProducerSession(workshop, env, bearerToken(request));
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

    m = path.match(/^\/v1\/workshops\/([^/]+)\/owner-email\/start$/);
    if (m && method === "POST") return startOwnerEmailClaim(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/owner-email\/confirm$/);
    if (m && method === "POST") return confirmOwnerEmailClaim(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/otp\/request$/);
    if (m && method === "POST") return requestOtp(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/otp\/verify$/);
    if (m && method === "POST") return verifyOtp(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics\/([^/]+)$/);
    if (m && method === "DELETE") return removeMechanic(request, env, m[1], m[2]);

    m = path.match(/^\/v1\/workshops\/([^/]+)\/mechanics$/);
    if (m && method === "POST") return addMechanic(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)$/);
    if (m && method === "GET") return readWorkshop(request, env, m[1]);

    return json({ error: "no such route" }, 404);
  },
};
