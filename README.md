# ovp-provider-cloudflare

A second, independent reference Provider for
[Open Vehicle Passport](https://github.com/tooming/openvehiclepassport) --
alongside [ovp-provider-aws](https://github.com/tooming/ovp-provider-aws),
not instead of it. Different language, different storage engine, same
protocol: that's the actual point of building two.

Serverless: one Worker (JS, no framework) + one KV namespace + Pages/assets
for the static viewer. Free tier covers a single car's worth of traffic
many times over (100k requests/day, 1k KV writes/day).

## Why a second implementation, in a second language

`src/ovpf-core.js` is a from-scratch port of
[reference/python/ovpf_core.py](https://github.com/tooming/openvehiclepassport/tree/main/reference/python),
not a translation-by-copy. Porting it surfaced a real bug in the Python
reference: `json.dumps(45.0)` keeps the `.0`, but JS's
`(45.0).toString()` doesn't, so the two languages canonicalized (and
therefore hashed) the exact same logical event differently the moment
a numeric field was a whole number. See
[openvehiclepassport's spec/OVPF.md §7](https://github.com/tooming/openvehiclepassport/blob/main/spec/OVPF.md)
and `conformance/fixtures/canonicalization.json` for the fix and the
shared test vectors. `test/ovpf-core.test.js` proves both
implementations now produce byte-identical hashes for the same event,
including that exact edge case.

## API

Same contract as `ovp-provider-aws` -- same routes, same
recordedAt-is-immutable rule:

| Method | Path                          | Auth                        |
|--------|-------------------------------|------------------------------|
| POST   | `/v1/passports`                | none |
| GET    | `/v1/passports/{id}`           | none -- the id is the read capability |
| POST   | `/v1/passports/{id}/events`    | none -- see below |
| GET    | `/v1/passports/{id}/export`    | none |

**POC MODE: there is no write access control at all right now**,
matching `ovp-provider-aws`. A write-capability-token model existed and
was removed entirely (not just left unenforced) for easier POCing --
anyone who knows a passport id can append to it. Not the intended
posture; see git history if it needs to come back.

## Rate limiting & cost protection

This zone (`skoor.ee`) and this account's Workers subscription are
both on Cloudflare's **Free** plan, which changes the risk shape
compared to `ovp-provider-aws`: Free-tier Workers (100k requests/day)
and KV (1k writes/day) have hard daily caps baked in. Abuse past the
cap gets rejected, not billed -- there's no surprise invoice here the
way there is on AWS's pay-per-request model. If this account is ever
upgraded to the $5/mo Bundled plan, revisit this: overage past the
included quota is billed per request, and the protections below become
as important as the AWS side's.

Already active, observed rather than configured: Cloudflare's
bot-fight-mode is blocking non-browser-like clients on this zone (see
`openvehiclepassport`'s `sync.py` User-Agent fix -- the exact block
that forced that fix is also deflecting a category of scripted abuse
here for free).

Not yet done, needs the Cloudflare dashboard (this repo's OAuth token
only has `zone:read`, not the scope to create rules via `wrangler` or
API): add a **Rate Limiting Rule** (Security -> WAF -> Rate limiting
rules) matching `passport.skoor.ee/v1/*`, e.g. block an IP past ~20
requests/10s. This isn't about cost on the Free plan -- it's about one
abusive client not exhausting the shared 1k-writes/day quota that
legitimate use (yours, testing, anyone else's passport) also draws
from.

## Storage

One KV namespace, `PASSPORTS`:

- `PASSPORT#<id>#META` -- registration marker (just `createdAt`; no
  credential stored here anymore, see Auth above).
- `PASSPORT#<id>#EVENT#<recordedAt>#<eventId>` -- one immutable value per
  event. `list({prefix})` returns keys in sorted order, same role
  DynamoDB's `Query`-by-`sk` plays for the AWS provider -- no schema,
  no SQL, the KV key ordering does the work.

**Known, disclosed limitation: Cloudflare KV is eventually consistent.**
Observed in production: an event `PUT` right before a `GET` on the same
passport was missing from the derived state for roughly 15-20 seconds
before showing up. This is expected KV behavior (Cloudflare documents
up to ~60s global propagation), not a bug in this Worker -- but it's a
real, disclosable tradeoff of choosing KV over a strongly-consistent
store like DynamoDB. If a client (the QR viewer, `ovpf --sync`) reads
immediately after writing and doesn't see its own write yet, that's
this, not corruption. Also observed on the workshop event log (same
`list({prefix})` read pattern): removing a mechanic and immediately
re-reading the workshop can still show them present for a few seconds
-- same cause, same fix (wait and re-read), not a logic bug in
`reduceWorkshop`.

## Viewer

`viewer/index.html` is the identical file used by `ovp-provider-aws` --
provider-agnostic by construction, since it only ever calls same-origin
`/v1/*`. Served via Cloudflare's `assets` binding with
`not_found_handling: "single-page-application"` (built-in SPA fallback
for `/p/<uuid>` -- no custom edge function needed, unlike the AWS side's
CloudFront Function). `run_worker_first: ["/v1/*"]` keeps API paths from
ever being treated as a missing static asset.

## Test

```
npm test              # node --test, no Cloudflare account needed
npm run dev           # wrangler dev, local KV emulation, no account needed
```

`test/fixtures/` is copied from `openvehiclepassport/conformance/fixtures`
-- shared, language-agnostic test vectors, not an implementation to keep
in sync via a golden-hash test. Re-copy if that repo's fixtures change.

## Deploy

Requires `wrangler login` (interactive, your browser) and a real KV
namespace:

```
wrangler login
wrangler kv namespace create PASSPORTS   # put the returned id into wrangler.jsonc
wrangler deploy
```

`wrangler.jsonc` already routes `passport.skoor.ee` as a custom domain
-- since that zone is on Cloudflare, this needs no separate cert request
or CNAME dance the way the AWS provider's CloudFront setup does (that
one lives at `passport-aws.skoor.ee` instead -- two providers can't
share one hostname). Once deployed, Cloudflare handles TLS for the
custom domain automatically.

Then generate a QR against this deployment (this is `qr.py`'s default
base URL already, no `--base-url` flag needed):

```
python3 qr.py <uuid> -o car-passport.svg
```
