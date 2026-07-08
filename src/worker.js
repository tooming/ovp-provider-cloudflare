/**
 * OVP reference provider (Cloudflare). One Worker, one KV namespace.
 *
 * Same contract as ovp-provider-aws/src/app.py -- same routes, same
 * storage key shape (conceptually: DynamoDB's pk/sk maps onto a single
 * KV key `PASSPORT#<id>#<sk>`, and KV's list({prefix}) returns keys in
 * sorted order for free, same as a DynamoDB Query). Two independently-
 * built providers speaking the same protocol -- that's the point.
 *
 * Read access is public by design -- anyone who knows a passport id (as
 * guessable as the QR code, i.e. not guessable: a UUIDv7 with 62 random
 * bits) can read it. Writes (creating a passport, appending an event)
 * require *some* signed-in identity -- see authenticateWrite -- but
 * that identity can be a plain personal email (see requestUserOtp/
 * verifyUserOtp), not necessarily a registered workshop: the bar is
 * "controls a real mailbox", not "is affiliated with anything". This
 * lets the viewer's local-first outbox queue events completely
 * anonymously (no login needed to use the app offline/locally) while
 * still requiring a login at the moment those events actually get
 * pushed to this provider.
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
  // KNOWN LIMITATION: this is read *before* computing a new event's
  // prevHash (see appendEvent), so a stale read of "the latest event"
  // computes a prevHash pointing at the wrong predecessor -- observed
  // live: two events appended to the same passport within roughly a
  // minute of each other silently broke the chain. Workers KV's list()
  // is only eventually consistent (Cloudflare documents up to ~60s
  // propagation) with no strongly-consistent-read option at all, unlike
  // DynamoDB's ConsistentRead (see app.py's _load_events) -- there is no
  // equivalent fix available within the KV API itself. A real fix needs
  // per-passport serialized writes, which means Durable Objects instead
  // of KV for this specific read-modify-write path; that's a genuine
  // migration, not a patch, and hasn't been done here yet.
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
  // Local-first: the passport id is normally minted *locally* first (the
  // viewer's own crypto.randomUUID(), before this provider ever hears
  // about it), so this registers that existing id with this provider
  // rather than handing out a new one. Requires *some* signed-in
  // identity (see authenticateWrite) -- registering is the moment a
  // locally-anonymous passport actually becomes visible to this
  // provider, so it's the moment a login is needed, not before.
  if (!(await authenticateWrite(env, request))) {
    return json({ error: "sign in required to sync a passport to this provider" }, 401);
  }
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
// / WorkshopMechanicAdded / WorkshopMechanicRemoved.
//
// There is no standing secret anywhere in this system -- login (owner or
// mechanic) is always OTP: prove you control an email already on file, get
// handed a signed, time-limited session token. Owner is structural, not
// claimed or stored: any email whose domain matches this (verified)
// workshop's own domain qualifies -- domain verification already proved
// someone legitimate controls it, and the OTP proves this holder can
// receive mail there. No separate claim step, no DNS beyond the one-time
// domain verification.

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
                   verificationToken: null, mechanicsRaw: new Map() };
  for (const ev of events) {
    const t = ev.type, d = ev.data || {};
    if (t === "WorkshopRegistered") {
      state.domain = d.domain; state.name = d.name;
      state.verificationToken = d.verificationToken;
    } else if (t === "WorkshopDomainVerified") {
      state.verified = true; state.verifiedAt = ev.occurredAt;
    } else if (t === "WorkshopMechanicAdded") {
      state.mechanicsRaw.set(d.mechanicId, { name: d.name, email: d.email || null });
    } else if (t === "WorkshopMechanicRemoved") {
      state.mechanicsRaw.delete(d.mechanicId);
    }
    // WorkshopSecretResetRequested/WorkshopSecretReset/WorkshopMechanicSecretReset/
    // WorkshopOwnerEmailClaimRequested/WorkshopOwnerEmailSet: legacy events
    // from earlier auth designs, replayed harmlessly (nothing left in
    // current state reads them). Owner login no longer needs a claimed
    // email at all: it's just "does this email's domain match the
    // workshop's own domain" (see findLoginIdentity).
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

function emailDomain(email) {
  const at = (email || "").lastIndexOf("@");
  return at === -1 ? null : email.slice(at + 1);
}

function findLoginIdentity(state, email) {
  // One sign-in box, one lookup. A specific mechanic's email is checked
  // first -- before the domain-match fallback, since a mechanic's email
  // is commonly at the workshop's own domain (company address) and must
  // resolve to the *restricted* mechanic role, not silently escalate to
  // owner. Owner is structural, not a claimed/stored value: any other
  // email whose domain matches this (verified) workshop's own domain
  // qualifies -- domain verification already proved someone legitimate
  // controls it, and the OTP this login requires proves *this* holder
  // can receive mail there.
  const mechanicId = findMechanicByEmail(state, email);
  if (mechanicId) return { role: "mechanic", mechanicId };
  if (state.verified && emailDomain(email) === state.domain) return { role: "workshop", mechanicId: null };
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
  // the token's embedded claims: removing a mechanic, or the workshop
  // losing its verified status, revokes any outstanding session for
  // that identity immediately, without needing a separate revocation
  // list. Owner is structural, not a stored value: any email whose
  // domain matches this (verified) workshop's own domain qualifies.
  const payload = await verifySessionToken(env, token);
  if (!payload || payload.domain !== workshop.domain) return null;
  if (payload.role === "workshop") {
    if (workshop.verified && emailDomain(payload.email) === workshop.domain) return { role: "workshop" };
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

async function authenticateWrite(env, request) {
  // Base gate for creating/appending to a passport: is *some* identity
  // signed in at all? A personal (role="user") session -- just a plain
  // email OTP, not tied to any workshop -- always qualifies, since the
  // bar for this gate is "controls a real mailbox", not "is affiliated
  // with anything". A workshop-owner or mechanic session also qualifies
  // (re-validated against live workshop state, same as
  // matchProducerSession, so a removed mechanic can't keep writing).
  // This is deliberately separate from the *producer.verified* stamping
  // logic in appendEvent, which additionally requires producer.domain
  // to match the session's own domain -- this gate only asks "is anyone
  // logged in", not "as whom".
  const token = bearerToken(request);
  const payload = await verifySessionToken(env, token);
  if (!payload) return false;
  if (payload.role === "user") return true;
  if (payload.domain) {
    const workshop = await getWorkshop(env, payload.domain);
    if (workshop && (await matchProducerSession(workshop, env, token))) return true;
  }
  return false;
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
  view.note = "Verify the domain via DNS (POST .../verify), then sign in any " +
    "time with any email at that domain (POST .../otp/request) to manage " +
    "mechanics.";
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

const OTP_TTL_SECONDS = 600;
const OTP_RESEND_COOLDOWN_SECONDS = 60;

function otpKey(domain, mechanicId) {
  return `MECHOTP#${workshopDomain(domain)}#${mechanicId}`;
}

async function storeOtp(env, domain, mechanicId, code, ttlSeconds = OTP_TTL_SECONDS) {
  // Stores createdAt alongside the hash (not just the bare hash string)
  // specifically so otpCooldownActive can tell how old this entry is --
  // KV's own expirationTtl manages cleanup but doesn't expose remaining
  // TTL or creation time back on a plain get().
  await env.PASSPORTS.put(otpKey(domain, mechanicId),
    JSON.stringify({ hash: await secretHash(code), createdAt: Date.now() }),
    { expirationTtl: ttlSeconds });
}

async function otpCooldownActive(env, domain, mechanicId) {
  // True if a code was already minted for this identity within the last
  // OTP_RESEND_COOLDOWN_SECONDS -- without this, hitting .../otp/request
  // repeatedly for the same victim would fire a fresh email every single
  // time, at zero cost to the caller and real cost to both the victim's
  // inbox and this provider's own sender reputation. Callers must still
  // return the *same* response whether or not this was true (see
  // requestOtp/requestUserOtp) -- a distinct status would leak exactly
  // the kind of "is this identity real" signal the anti-enumeration
  // design elsewhere in this file exists to avoid.
  const stored = await env.PASSPORTS.get(otpKey(domain, mechanicId));
  if (!stored) return false;
  let parsed;
  try { parsed = JSON.parse(stored); } catch { return false; }
  return (Date.now() - (parsed.createdAt || 0)) < OTP_RESEND_COOLDOWN_SECONDS * 1000;
}

async function checkAndConsumeOtp(env, domain, mechanicId, code) {
  const key = otpKey(domain, mechanicId);
  const stored = await env.PASSPORTS.get(key);
  if (!stored) return false;
  let parsed;
  try { parsed = JSON.parse(stored); } catch { return false; }
  if (parsed.hash !== (await secretHash(code))) return false;
  await env.PASSPORTS.delete(key); // one-time use
  return true;
}

async function sendEmail(env, to, subject, text) {
  // Dispatches to whichever provider env.EMAIL_PROVIDER selects
  // ("postmark", the default, or "resend") -- switching is a config
  // change (one var + its secret), not a code change. Not a queue/retry
  // system: an OTP is useless a minute late, so a failed send should
  // surface immediately, not get silently swallowed.
  if ((env.EMAIL_PROVIDER || "postmark").toLowerCase() === "resend") {
    return sendEmailResend(env, to, subject, text);
  }
  return sendEmailPostmark(env, to, subject, text);
}

// A real-looking User-Agent, not fetch()'s Workers-runtime default --
// found live (AWS side, via Python's urllib, same class of bug): a
// provider sitting behind Cloudflare's edge with bot-fight-style rules
// enabled can reject a generic/default UA outright with a bare
// "error code: 1010", no JSON body at all. Applied here too for parity,
// since either provider's email API could end up behind similar
// protection even though only one is Cloudflare-fronted today.
const OUTBOUND_USER_AGENT = "OpenVehiclePassport/1.0 (+https://openvehiclepassport.org)";

async function sendEmailPostmark(env, to, subject, text) {
  if (!env.POSTMARK_API_TOKEN) throw new Error("POSTMARK_API_TOKEN not configured on this provider");
  const resp = await fetch("https://api.postmarkapp.com/email", {
    method: "POST",
    headers: {
      "X-Postmark-Server-Token": env.POSTMARK_API_TOKEN,
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": OUTBOUND_USER_AGENT,
    },
    body: JSON.stringify({
      From: env.POSTMARK_FROM, To: to, Subject: subject, TextBody: text,
      MessageStream: "outbound",
    }),
  });
  if (!resp.ok) throw new Error(`Postmark API returned HTTP ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

async function sendEmailResend(env, to, subject, text) {
  if (!env.RESEND_API_KEY) throw new Error("RESEND_API_KEY not configured on this provider");
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
      "user-agent": OUTBOUND_USER_AGENT,
    },
    body: JSON.stringify({
      from: env.RESEND_FROM, to: [to], subject, text,
    }),
  });
  if (!resp.ok) throw new Error(`Resend API returned HTTP ${resp.status}: ${await resp.text()}`);
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
    const slot = identity.mechanicId || "OWNER";
    if (!(await otpCooldownActive(env, domain, slot))) {
      const code = String(Math.floor(100000 + Math.random() * 900000));
      await storeOtp(env, domain, slot, code);
      try {
        await sendEmail(env, email, "Your Open Vehicle Passport sign-in code",
          `Your one-time code is ${code}. It expires in 10 minutes.\n\n` +
          `If you didn't request this, ignore this email.`);
      } catch (e) {
        return json({ error: `could not send email: ${e}` }, 502);
      }
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

// --- Personal (non-workshop) OTP login --------------------------------------
// Not tied to any domain or a pre-existing record -- unlike a workshop's
// owner/mechanic OTP (which only fires for an email already on file, to
// avoid leaking who's affiliated with a shop), *any* email qualifies here:
// verifying it IS the identity, with nothing else to look up. Reuses
// otpKey/storeOtp/checkAndConsumeOtp under the pseudo-domain "USER" (a
// real workshop domain always contains a ".", so this can never collide
// with one) -- no new storage shape needed.

async function requestUserOtp(request, env) {
  // POST /v1/auth/otp/request {email} -> emails a one-time code for a
  // plain personal identity. Used to gate pushing local-first outbox
  // events to this provider (see appendEvent/createPassport) -- the
  // whole point is that using the app locally/anonymously needs no
  // login at all; only the moment of syncing to the cloud does.
  let body = {};
  try {
    const text = await request.text();
    if (text) body = JSON.parse(text);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) return json({ error: "a valid email is required" }, 400);

  if (await otpCooldownActive(env, "USER", email)) {
    // Any email "succeeds" here (unlike requestOtp above, there's no
    // existence check to protect), which makes this endpoint an even
    // easier mailbox-bombing vector without a cooldown -- silently skip
    // the resend rather than mint a fresh code (and email) on every hit.
    return json({ sent: true });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  await storeOtp(env, "USER", email, code);
  try {
    await sendEmail(env, email, "Your Open Vehicle Passport sign-in code",
      `Your one-time code is ${code}. It expires in 10 minutes.\n\n` +
      `If you didn't request this, ignore this email.`);
  } catch (e) {
    return json({ error: `could not send email: ${e}` }, 502);
  }
  return json({ sent: true });
}

async function verifyUserOtp(request, env) {
  // POST /v1/auth/otp/verify {email, code} -> a signed session token
  // with role="user", good for pushing local passports/events to this
  // provider (see authenticateWrite). Not scoped to any domain.
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
  if (!(await checkAndConsumeOtp(env, "USER", email, code))) {
    return json({ error: "invalid or expired code" }, 403);
  }

  let token;
  try {
    token = await issueSessionToken(env, null, "user", email, null, email);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
  return json({ token, role: "user", email });
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
  // Requires *some* signed-in identity (see authenticateWrite) -- a
  // plain personal email OTP is enough, no workshop affiliation needed.
  // This is deliberately a separate, weaker requirement than the
  // producer.verified stamping below: being logged in as *someone* lets
  // you write; being logged in as *this specific workshop* is what
  // additionally earns the verified badge.
  const meta = await getMeta(env, id);
  if (!meta) return json({ error: "no such passport" }, 404);
  if (!(await authenticateWrite(env, request))) {
    return json({ error: "sign in required to sync events to this provider" }, 401);
  }

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

    if (method === "POST" && path === "/v1/auth/otp/request") return requestUserOtp(request, env);
    if (method === "POST" && path === "/v1/auth/otp/verify") return verifyUserOtp(request, env);

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
