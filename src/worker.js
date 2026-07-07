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

function workshopKey(domain) {
  return `WORKSHOP#${(domain || "").trim().toLowerCase().replace(/\.+$/, "")}`;
}

async function getWorkshop(env, domain) {
  const v = await env.PASSPORTS.get(workshopKey(domain));
  return v ? JSON.parse(v) : null;
}

function workshopView(item) {
  return {
    domain: item.domain,
    name: item.name,
    verified: !!item.verified,
    verifiedAt: item.verifiedAt || null,
    verificationToken: item.verificationToken,
    dnsRecord: {
      type: "TXT",
      name: `_ovp-verify.${item.domain}`,
      value: `ovp-verify=${item.verificationToken}`,
    },
  };
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
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

  const domain = (body.domain || "").trim().toLowerCase().replace(/\.+$/, "");
  if (!domain || !domain.includes(".")) {
    return json({ error: 'domain required, e.g. "skoor.ee"' }, 400);
  }

  const existing = await getWorkshop(env, domain);
  if (existing) return json(workshopView(existing), 200);

  const item = {
    domain, name: body.name || domain,
    verificationToken: randomToken(),
    verified: false, createdAt: new Date().toISOString(),
  };
  await env.PASSPORTS.put(workshopKey(domain), JSON.stringify(item));
  return json(workshopView(item), 201);
}

async function readWorkshop(request, env, domain) {
  const item = await getWorkshop(env, domain);
  if (!item) return json({ error: "no such workshop registered" }, 404);
  return json(workshopView(item));
}

async function verifyWorkshop(request, env, domain) {
  const item = await getWorkshop(env, domain);
  if (!item) return json({ error: "no such workshop registered" }, 404);
  if (item.verified) return json(workshopView(item));

  const expected = `ovp-verify=${item.verificationToken}`;
  let found;
  try {
    found = await dnsTxtLookup(`_ovp-verify.${item.domain}`);
  } catch (e) {
    return json({ ...workshopView(item), checkError: String(e) });
  }

  if (!found.includes(expected)) {
    return json({ ...workshopView(item), found });
  }

  item.verified = true;
  item.verifiedAt = new Date().toISOString();
  await env.PASSPORTS.put(workshopKey(domain), JSON.stringify(item));
  return json(workshopView(item));
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

  // Server-side provenance stamping (see docs/TRUST.md) -- matches
  // app.py exactly: a client's producer.verified claim is stripped and
  // only re-added here, from this provider's own workshop registry, at
  // write time. Baked into the hash immediately, so a workshop losing
  // verified status later doesn't retroactively change what it attested.
  const producer = ev.producer || {};
  delete producer.verified;
  delete producer.verifiedAt;
  if (producer.domain) {
    const workshop = await getWorkshop(env, producer.domain);
    if (workshop && workshop.verified) {
      producer.verified = true;
      producer.verifiedAt = workshop.verifiedAt;
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

    m = path.match(/^\/v1\/workshops\/([^/]+)\/verify$/);
    if (m && method === "POST") return verifyWorkshop(request, env, m[1]);

    m = path.match(/^\/v1\/workshops\/([^/]+)$/);
    if (m && method === "GET") return readWorkshop(request, env, m[1]);

    return json({ error: "no such route" }, 404);
  },
};
