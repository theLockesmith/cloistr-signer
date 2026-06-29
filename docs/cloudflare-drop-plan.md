# Cloudflare Egress Drop Plan

**Status:** Plan draft
**Last updated:** 2026-06-29
**Implements:** privacy-architecture.md §3.2
**Dependencies:** Atlas access (the actual cutover work lives in `~/Atlas`)

> **2026-06-29 architecture decision (resolves Open Question #1):** the public ingress is realized
> by **reusing the existing `nginx_proxy` edge box** (`72.18.53.189`; hosts `10.61.2.160`/`.99`) in the
> **same pattern as the empacchosting gitlab / integrations routes** — NOT a new in-cluster
> nginx-ingress controller and NOT a newly-allocated public IP. This is lower-effort, reuses proven
> infra, and supports non-HTTP traffic (SSH for git, SMTP) via nginx `stream{}`. It revises §3 and §6
> below. See the new §13 "Architecture realization (edge-box)" for the verified specifics.
>
> **2026-06-29 sequencing decision (revises §6 / §12):** do **all cutovers FIRST**, then harden.
> Rationale: Cloistr is public but largely unknown, so current attack surface is low. Priority is
> getting every service onto correct direct ingress; the **protection prerequisites — DDoS-replacement
> decision, fail2ban, nginx rate-limiting, the load test — are explicitly DEFERRED to a post-cutover
> hardening phase** (new §12 phase H). **Accepted interim risk:** between first cutover and phase H the
> origin (`72.18.53.189` / cluster) has no DDoS shield and minimal L7 rate limiting (privacy-arch item
> #8 per-user quotas still apply). Accepted knowingly per this decision.
>
> **2026-06-29 scope correction:** the apex **`cloistr.xyz` landing page is IN scope** (its prior
> omission from §5 was an oversight) and is the **first cutover / playbook-validation target** — it is
> also the currently-broken service (§13.2).
>
> **2026-06-29 management decision:** **every artifact is declared and applied idempotently via Atlas**
> — no hand-run `oc`/`kubectl apply`, no manual edits to live nginx, no Cloudflare-dashboard DNS clicks.
> Each component has an Atlas home (see §13.4): nginx vhosts/streams and certbot SANs in the
> `nginx_proxy` role; OpenShift Routes + NodePorts in a dedicated `kube/*` role applied with
> `kubernetes.core.k8s` (like `cloistr-tunnel` renders its ConfigMap); DNS A-records via the role's
> `flarectl`/`uri` tasks. Re-running the relevant `atlas` apply must converge state with no drift.

This document plans the removal of the Cloudflare Tunnel as the public ingress for Cloistr (cloistr.xyz) and Coldforge (coldforge.xyz) services. It is the planning artifact that precedes Atlas role changes and DNS cutover work.

It does NOT execute the cutover. The cutover is live operational work that requires a planned window, ops attention, and explicit go/no-go decisions per service.

---

## 1. Why Drop Cloudflare

Per privacy-architecture.md §1.1 ("We Cannot Comply") and §3.2:

- **Cloudflare terminates TLS** for every Cloistr service. That means every byte of every request — Nostr DM cleartext (before NIP-44/17 wrap), bunker URI traffic, file uploads to Blossom — is decrypted at Cloudflare's edge before being re-encrypted to our origin.
- **Cloudflare holds connection logs** by default. Whether or not we configure them off, the capability exists at the provider level.
- **Cloudflare is independently subpoenable.** A demand served against Cloudflare for user X's traffic to signer.cloistr.xyz is a path that goes around our "we cannot comply" architecture entirely.
- **Cloudflare maintains a real-IP-to-pubkey mapping** for any signed-in user, because the request includes session cookies. Even with our own server-side IP retention removed (privacy commit `ed079f4`), Cloudflare's edge sees and can log the IP.

The Cloudflare-as-DDoS-shield argument is real. The Cloudflare-as-MITM concern outweighs it for a privacy product.

## 2. Current State

**Tunnel:** `cloistr-tunnel` namespace, `cloudflared` Deployment, 2 replicas. Tunnel ID `a5608c8f-5194-44c5-839f-fcc5879c0f28`. Configured via `~/Atlas/roles/kube/cloistr-tunnel/`.

**Services routed through the tunnel** (from `defaults/main.yml`):

| Hostname | K8s service | WebSocket | Notes |
|---|---|---|---|
| relay.cloistr.xyz | cloistr-relay:80 | yes | Nostr relay, primary domain |
| relay-admin.cloistr.xyz | cloistr-relay:80 | no | NIP-86 admin UI |
| signer.cloistr.xyz | cloistr-signer:7777 | no | NIP-46 remote signer |
| bunker.cloistr.xyz | cloistr-signer:7777 | yes | Alias for signer |
| files.cloistr.xyz | cloistr-blossom:80 | no | Blossom file storage |
| stash.cloistr.xyz | cloistr-drive:80 | no | File manager UI |
| drive.cloistr.xyz | cloistr-drive:80 | no | Legacy alias |
| contacts.cloistr.xyz | cloistr-contacts:80 | no | Encrypted contacts |
| documents.cloistr.xyz | cloistr-documents:8080 | yes | Collaborative editing |
| ... and ~5 more |  |  |  |

**Cert management:** cert-manager with Cloudflare DNS-01 challenges (`~/Atlas/roles/kube/apply/cert-manager/templates/cloudflare-api-token-secret.yml.j2`). The Cloudflare API token is *also* used for cert issuance, distinct from the tunnel. This needs separate consideration during cutover.

**DNS:** all hostnames are CNAMEs into the tunnel managed by `flarectl`. DNS is itself managed via Cloudflare's API.

## 3. End State

**(Revised 2026-06-29 — edge-box realization; supersedes the cluster-ingress-controller draft.)**

After the drop:

- **Public edge = the existing `nginx_proxy` box** (`72.18.53.189`; hosts `10.61.2.160`/`.99`), the same
  box that already fronts the empacchosting gitlab / integrations routes. No new in-cluster ingress
  controller; no new public IP.
- **HTTP/HTTPS:** an nginx vhost per hostname under `~/Atlas/roles/nginx_proxy/files/sites-enabled/`
  terminates TLS (the box's `coldforge.xyz` certbot cert, whose SANs already include `cloistr.xyz` and
  `*.cloistr.xyz`) and `proxy_pass`es to the **OpenShift router internal VIP `10.51.0.6:80`** with
  `Host` preserved → a **per-service OpenShift Route** dispatches to the k8s service. (Template:
  `sites-enabled/cloistr.xyz/files-staging.cloistr.xyz`.)
- **L4 / non-HTTP (SSH for git, SMTP, etc.):** an nginx `stream{}` config under
  `~/Atlas/roles/nginx_proxy/files/stream.d/` binds a dedicated edge VIP:port and `proxy_pass`es to an
  **internal cluster VIP:NodePort** (MetalLB `10.50.x` IPs are NOT edge-routable; node IPs `10.51.x`
  are). Template: `stream.d/gitlab-ssh.conf` (`10.61.0.69:22 → 10.51.0.5:30869`), `stream.d/mail.conf`.
- **Direct DNS A records** (gray-cloud, proxy off) pointing each hostname at `72.18.53.189`. DNS stays
  on Cloudflare (we own the zone) but Cloudflare no longer proxies traffic.
- **Let's Encrypt certs:** keep **DNS-01 via Cloudflare** (DNS-edit token only; no traffic visibility).
  ⚠ New hostnames cut over must have an **explicit fully-qualified SAN** added to the edge box's
  certbot cert — a TLS wildcard matches exactly one label, so `*.cloistr.xyz` does NOT cover deeper
  names, and the apex `cloistr.xyz` is its own SAN (already present).
- **fail2ban on the edge nodes** (`nginx_proxy` hosts) for connection-level rate limiting.
- **nginx `limit_req` rate-limiting** per vhost for L7 protection.
- **Onion endpoint** (privacy-architecture.md item #4) live in parallel — separate work.

## 4. DDoS Replacement Strategy

> **DEFERRED to post-cutover phase H (2026-06-29 sequencing decision).** This section is the design for
> the hardening phase, not a pre-cutover gate. Interim risk accepted (public-but-unknown).

This is the load-bearing risk of the drop. Cloudflare's edge absorbs DDoS today; our cluster does not.

### 4.1 Layer-3/4 (volumetric)

Options, by ascending cost and effectiveness:

| Option | Cost | Effectiveness | Notes |
|---|---|---|---|
| Cluster-edge `iptables` rate limiting | Free | Low | Stops trivial floods; falls over at any real DDoS |
| Provider-level DDoS protection (DigitalOcean / Hetzner / Vultr basic) | Included | Medium | Covers most volumetric attacks below 10 Gbps |
| AWS Shield Advanced / GCP Cloud Armor | $$$$ | High | Comparable to Cloudflare; same MITM concern |
| Path through OVH BGP or Voxility | $$$ | High | DDoS scrubbing without TLS termination — preserves the privacy property |

**Recommendation:** start with provider-level basic DDoS protection (whatever the K8s host provider offers). If volumetric attacks become a real concern, route through OVH/Voxility, NOT through a TLS-terminating CDN.

### 4.2 Layer-7 (application)

- **nginx-ingress rate-limit annotations** per host (`nginx.ingress.kubernetes.io/limit-rps`).
- **fail2ban** on ingress nodes scanning nginx logs for repeated 4xx/5xx patterns.
- **Application-level rate limiting** (privacy-architecture.md item #8 partially shipped; per-user quotas exist).
- **Connection rate limit at the LoadBalancer** if the provider supports it.

### 4.3 Pre-cutover load test

Run k6 / vegeta against the staging ingress with realistic peak traffic patterns BEFORE the cutover. Establishes a baseline. If a 10x spike from baseline can be absorbed, the safety margin is acceptable.

## 5. Cutover Sequence

Per-service, not all-at-once. Each service moves independently. Order matters: start with the least-trafficked, most-cutover-tolerant service first.

### 5.1 Per-service cutover steps

For each service:

1. **Add Ingress resource** in Atlas role. Initial state: ingress exists but DNS still points at tunnel. Verify cert issues, ingress serves correctly via direct IP probe (with `Host:` header).
2. **Verify cert provisioning** for the hostname on the direct ingress. Should be valid LE cert with full chain.
3. **Lower DNS TTL** to 60 seconds on the existing CNAME-to-tunnel record. Wait one TTL cycle.
4. **DNS flip:** change CNAME → A record (or CNAME to ingress LB hostname). Cloudflare proxy off ("DNS only" / gray cloud).
5. **Verify external clients reach the direct ingress** (not the tunnel).
6. **Remove from `cloistr_services` list** in `~/Atlas/roles/kube/cloistr-tunnel/defaults/main.yml`. Apply the tunnel role — tunnel no longer routes this hostname.
7. **Verify tunnel-side route is gone** (curl through the tunnel's old route now 404s).
8. **Raise DNS TTL back to normal** (3600s+) once stable.
9. **Per-service privacy claim updated** in the privacy-architecture.md status table.

Estimated wall-clock per service: 2-4 hours including the TTL waits.

### 5.2 Recommended service order

Ordered by progressively higher stakes:

0. **cloistr.xyz** (apex landing page → `cloistr-sanctuary`; `/.well-known` + `/api` → `cloistr-me`) —
   **first / playbook validation.** Static landing page, lowest stakes, and currently broken (§13.2), so
   fixing it via the new edge-box playbook both clears a live bug and proves the path. Special vs the
   subdomains: needs path-split Routes (sanctuary + me) and restores NIP-05 / Lightning Address.
1. **drive.cloistr.xyz** (legacy alias) — lowest traffic, easy to roll back, validates the cutover playbook.
2. **stash.cloistr.xyz** (the actual file manager) — similar profile to drive.
3. **contacts.cloistr.xyz** — encrypted contact management, sees moderate traffic.
4. **files.cloistr.xyz** (Blossom) — large-file uploads stress the ingress more; tests that side.
5. **relay-admin.cloistr.xyz** — low traffic, admin-only.
6. **signer.cloistr.xyz** + **bunker.cloistr.xyz** — the privacy-critical pair. Move together since they share the same backend.
7. **documents.cloistr.xyz** — WebSocket, real-time. Tests that the new ingress handles WS at scale.
8. **relay.cloistr.xyz** — highest traffic, most disruptive if it fails. Move last.

> The apex (item 0 above) is the root domain / landing page — detailed cutover steps and the active bug
> it fixes are in §13.2.

### 5.3 Rollback procedure (per service)

If a cutover fails:

1. **Re-flip DNS** back to the tunnel CNAME. TTL was already lowered in step 3.
2. **Re-add service to `cloistr_services`** in the tunnel role and re-apply.
3. **Verify traffic returns to the tunnel route.**
4. **Leave the Ingress resource in place** for next attempt; debug offline.

Rollback wall-clock: 5-10 minutes if DNS TTL was lowered first.

## 6. Pre-Cutover Prerequisites

These must be in place BEFORE the first service cutover **(revised 2026-06-29 for the edge-box realization)**:

- [x] **Public edge available** — reuse the `nginx_proxy` box `72.18.53.189` (no new controller/IP).
- [x] **Edge → cluster reachability confirmed** — edge reaches router VIP `10.51.0.6:80` and node IPs
  `10.51.x` (ping + TCP verified 2026-06-29); MetalLB `10.50.x` NOT reachable → L4 uses NodePort.
- [x] **Edge TLS covers the targets** — certbot cert SANs include `cloistr.xyz` + `*.cloistr.xyz`.
- [ ] **Per-hostname SAN additions** for any cut-over host not already covered (no nested wildcards —
  add explicit `-d <fqdn>` in `Atlas/roles/nginx_proxy/tasks/main.yml` certonly `--expand`).
- [ ] **Create the `roles/kube/cloistr-ingress/` Atlas role** (mirrors `cloistr-tunnel`) to own the
  OpenShift Routes + NodePorts + DNS A-records idempotently (§13.4). This is the Route-ownership answer —
  cloistr-config manages no Routes and lacks `cloistr-me`/`cloistr-email`, so the edge lives in Atlas.
- [ ] **cert path kept on DNS-01** via Cloudflare (no HTTP-01 migration this round).
- [ ] **Test cert + route** for a throwaway hostname (`test-direct.cloistr.xyz`) end-to-end.
- [x] **Mail backend decided** (§13.3): `cloistr-email` REPLACES `10.60.169.11` as the sole mail app.
  Action = repoint `stream.d/mail.conf` upstreams → cloistr-email NodePorts (per-protocol map). Mail is
  already grey-cloud/direct (`72.18.53.189` = `mail.cloistr.xyz` per PTR/MX/SPF), independent of the web
  cutover. Open item: confirm cloistr-email's protocol surface (IMAP/POP vs SMTP+webmail) before repoint.
- [ ] **Documentation update**: revise the `cloistr-tunnel/README.md` "Don't create Ingress resources"
  line — tunnel-era rule; the edge-box pattern uses OpenShift Routes + nginx vhosts instead.
- [ ] **Runbook for cutover steps** with per-step verification commands.

> **Deferred to post-cutover phase H** (not pre-cutover gates, per the 2026-06-29 sequencing decision):
> fail2ban on edge nodes, nginx `limit_req` rate-limiting, DDoS-replacement decision (§4), load test.

## 7. cert-manager Cloudflare-API Dependency

Even after the tunnel drops, cert-manager still uses the Cloudflare DNS-01 challenge to issue Let's Encrypt certs. That means we still:

- Hold a Cloudflare API token
- Cloudflare sees DNS-01 challenges
- Cloudflare knows our hostnames (which they already do, because they manage DNS)

This is acceptable post-drop because:

- The API token has DNS-edit scope only — no traffic-data access.
- DNS challenges happen at cert issuance/renewal, not per-request.
- Cloudflare doesn't see user traffic anymore once the tunnel is gone.

If we want zero Cloudflare dependency, we'd need to move DNS itself to a different provider (deSEC, Vultr DNS, self-hosted) and rewire cert-manager. That's a separate item, not in scope here.

## 8. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| First DDoS after cutover saturates cluster | Med | Service down | Provider-level DDoS protection on standby, load test baseline established |
| Cert renewal fails post-cutover | Low | Service serves expired cert | Keep DNS-01 path; monitor cert renewals; alerting on cert age > 60 days |
| Origin IP exposed via DNS history | High | Increased attack surface (existed before behind tunnel) | Accept the trade. Origin exposure is the cost of removing the MITM. |
| WebSocket reconnect storms during cutover | Med | Brief connection churn | Lower DNS TTL in advance, run cutover during low-traffic window |
| Ansible role drift between cloistr-tunnel removal and cloistr-ingress addition | Med | Some service double-routed or missing | Sequence cutover per-service per §5.1, not all-at-once |
| Cloudflare API token rotation breaks DNS automation | Low | Cert renewals fail | Token already in 3 places; rotation procedure documented (cloistr-tunnel README) |

## 9. Success Metrics

The drop is considered complete when:

- [ ] All Cloistr services serve from direct cluster ingress, not tunnel.
- [ ] `cloistr-tunnel` Deployment scaled to 0 (then deleted after a 30-day rollback window).
- [ ] No production traffic observed at the tunnel ingress for 7 consecutive days.
- [ ] Cert renewals working on the new ingress for two cycles (~60 days).
- [ ] Load test of 2x baseline traffic passes on the new ingress.
- [ ] privacy-architecture.md §1.2 row "Cloudflare tunnel sees user traffic" updated to "removed."
- [ ] privacy-architecture.md §4 item #3 marked shipped.

## 10. Out of Scope

- **Migrating DNS off Cloudflare.** Separate work; significantly larger blast radius.
- **Onion endpoint setup.** privacy-architecture.md item #4. Independent and parallel.
- **Per-key Tor egress runtime.** privacy-architecture.md item #5. Independent; needs upstream go-nostr fork.
- **Migrating other domains off the tunnel — separate sessions, same playbook.** This plan executes
  **cloistr.xyz** (prove the edge-box playbook here). Intended to follow once cloistr is proven
  (2026-06-29): **`aegis-hq.xyz`, `aegisitservices.com`, `coldforge.xyz`** — each onto the same edge-box
  ingress pattern. Mail consolidation is implied: since **`cloistr-email` is the sole mail application**
  (§13.3), these domains' mail also lands on it (each domain needs its own MX/SPF/DKIM/DMARC and a SAN on
  the mail cert; PTR is per-IP so multi-domain mail on one IP shares one HELO identity — revisit per
  domain). The retired `10.60.169.11` is the current multi-domain backend cloistr-email replaces.

## 11. Open Questions

1. ~~**Ingress controller choice:** nginx-ingress vs Traefik.~~ **RESOLVED 2026-06-29:** neither — reuse
   the existing `nginx_proxy` edge box (empacchosting gitlab/integrations pattern). See §3 / §13.
2. **Provider DDoS:** which tier from current K8s host. Need to enumerate options + pricing.
3. **WebSocket ingress sticky session behavior:** verify that the new ingress doesn't break NIP-46 client reconnects for the signer.
4. **Cloudflare API token scope reduction post-cutover:** the current token has DNS-edit on cloistr.xyz, coldforge.xyz, coldforge.net. After the drop, we still need DNS-edit (cert-manager). Can we narrow scope further?
5. **`flarectl` automation** lives in the tunnel role today and manages the CNAME records. Post-drop, what manages the A records? Likely cert-manager's annotations + a separate flarectl pass for A records.

## 12. Phasing

Suggested implementation phases **(revised 2026-06-29: cutovers first, harden after — §intro sequencing decision)**:

| Phase | Scope | Wall-clock |
|---|---|---|
| C1 | Minimal technical prep: create **`roles/kube/cloistr-ingress/`** (Routes/NodePorts/DNS, §13.4), edge-box vhost/stream templates, per-host SAN additions, `test-direct.cloistr.xyz` end-to-end cert+route, runbook. **No protections/load-test in this phase.** | days |
| C2 | ✅ apex `cloistr.xyz` SHIPPED 2026-06-29 (§13.2). Remaining: **drive.cloistr.xyz**. | 1-2 days |
| C3 | Cutover stash, contacts, files, relay-admin. | days |
| C4 | Cutover privacy-critical pair (signer, bunker). Update privacy-architecture status. | 2-3 days |
| C5 | Cutover WebSocket-heavy (documents). Parallel (independent of web cutover): **mail backend repoint** — `stream.d/mail.conf` upstreams `10.60.169.11` → cloistr-email NodePorts (§13.3), retire `10.60.169.11`. | 1-2 days |
| C6 | Cutover highest-traffic (relay). | 2-3 days |
| **H** | **Hardening (deferred protections): DDoS-replacement decision (§4), fail2ban on edge nodes, nginx `limit_req` per vhost, load test / baseline.** Done AFTER everything is on direct ingress. | 1-2 weeks |
| C7 | Decommission cloistr-tunnel. Scale to 0, leave 30 days, then delete. | 30-day soak + cleanup |

Sequencing note: C2–C6 (all cutovers) precede H (protections) by explicit decision. Run cutovers in a
low-traffic window with DNS TTL lowered first; rollback per §5.3 is 5-10 min.

---

## 13. Architecture realization — edge-box (verified 2026-06-29)

Folds in the prior `cloistr-sanctuary/docs/grey-cloud-apex-ingress.md` scoping (now deleted).

### 13.1 Verified facts

- **No cluster public ingress exists.** OpenShift router `router-internal-default` is ClusterIP;
  MetalLB LBs get **private** IPs (`10.50.x`); ingress domain `apps.atlantis.coldforge.xyz` is internal.
  The Cloudflare tunnel is currently the only public entry — which is exactly what this plan retires.
- **The edge box is the public origin.** `72.18.53.189` lands directly on the `nginx_proxy` box for
  `Host: cloistr.xyz` (verified). Its certbot cert SANs include `cloistr.xyz` + `*.cloistr.xyz`.
- **Edge → cluster paths:** edge reaches router VIP `10.51.0.6:80` (used by existing vhosts like
  `files-staging.cloistr.xyz`) and node IPs `10.51.x` (ping + TCP ok). MetalLB `10.50.x` is **not**
  edge-routable → L4 services must be exposed via **NodePort** and reached at `node-IP:nodePort`.
- **Two reusable templates** on the edge box: HTTP `sites-enabled/cloistr.xyz/files-staging.cloistr.xyz`
  (→ router VIP); L4 `stream.d/gitlab-ssh.conf` (dedicated edge VIP → internal VIP:NodePort).
- **Cloudflare API token is DNS-edit only** (`Atlas/inventory/group_vars/kube/cloudflare.yml`): 403 on
  pagerules/rulesets/workers, 401 on `cfd_tunnel`. Fine for the gray-cloud A-record flips and DNS-01
  certs; cannot read/modify Cloudflare edge rules (see §13.2).

### 13.2 Apex `cloistr.xyz` — ✅ SHIPPED 2026-06-29 (first cutover, validated the playbook)

**Status: DONE.** Live state: `cloistr.xyz` is a grey-cloud `A → 72.18.53.189` (no CNAME, Cloudflare
proxy off), served directly by the edge box → router VIP `10.51.0.6:80` → Routes →
`cloistr-sanctuary` (`/`) and `cloistr-me` (`/.well-known`, `/api`). Verified: apex serves sanctuary
(`Server: nginx`), `/.well-known/nostr.json` returns real `{"names":{}}` (NIP-05 restored), subdomains
unaffected. Implemented idempotently via the **`cloistr-ingress`** role (Routes + gated DNS) +
`nginx_proxy` apex vhost; apex removed from the `cloistr-tunnel` config. The Cloudflare apex edge-rule is
now moot (proxy out of path). Hardening: nginx `limit_req` (zone `cloistr_apex`) live; fail2ban nginx
jails added to the edge.

Original bug + how it was fixed (kept for reference):


**Bug (active):** the apex serves a legacy nginx "Nostr-native services coming soon" stub
(`Server: nginx/1.24.0`; `/.well-known/nostr.json` → `{"names":{},"relays":{}}`; `/lnurlp/*` 502 to a
dead `10.32.0.10`) instead of `cloistr-sanctuary`. Root cause: a **Cloudflare edge rule scoped to the
apex** overrides its origin to the edge box, bypassing the tunnel — even though the live tunnel
ConfigMap (tunnel `a5608c8f`, the apex CNAME target) already routes `cloistr.xyz` → `cloistr-sanctuary`
correctly. Reconciling the ConfigMap + rolling cloudflared had zero effect (proves the rule intercepts
before the tunnel). The DNS-only token can't read/remove that rule.

**Why the cutover fixes it cleanly:** going gray-cloud (DNS-only A → `72.18.53.189`) removes Cloudflare
proxy from the apex path entirely, making the edge rule moot, and the edge box serves sanctuary directly.

**Apex cutover steps (edge-box):**
1. OpenShift Routes: `cloistr.xyz/` → `cloistr-sanctuary:80`; `cloistr.xyz` path `/.well-known` and
   `/api` → `cloistr-me:80` (decide Route ownership per §6).
2. nginx vhost `sites-enabled/cloistr.xyz/cloistr.xyz`: replace the "coming soon" stub with the
   files-staging pattern (80→443 redirect; 443 TLS → `proxy_pass http://10.51.0.6:80`, `Host` preserved).
   This removes the dead hardcoded `nostr.json` and dead `10.32.0.10` lnurlp proxy and restores real
   NIP-05 / Lightning Address via `cloistr-me`.
3. DNS: apex orange CNAME→tunnel ⟶ **A `cloistr.xyz` → 72.18.53.189, proxied=false**.
4. Verify sanctuary + real `/.well-known/nostr.json` + `/.well-known/lnurlp/<name>`; subdomains unaffected.

> Note: steps 1–2 alone (without the DNS flip) already make the *current orange* apex serve sanctuary,
> because the CF rule routes apex → edge box → (new vhost) → sanctuary. That is the fastest way to clear
> the visible placeholder bug if a same-window DNS flip isn't desired.

### 13.3 Mail transport — a separate, already-direct lane (NOT via the router VIP)

Mail does **not** traverse the OpenShift router VIP `10.51.0.6:80` — that VIP is the L7 HTTP router and
only carries web (sanctuary, cloistr-me, the email *web UI*). Mail rides the independent nginx `stream{}`
lane on the same edge box, exactly like `stream.d/gitlab-ssh.conf`:

- `:443` → nginx vhost → router VIP `10.51.0.6:80` → Routes → web services.
- `:25/465/587/143/993` → nginx `stream` → mail backend (TLS **passthrough**, terminated at the backend).

**Mail is already grey-cloud / direct, so the Cloudflare drop is a web-only event.** Verified DNS
(2026-06-29): PTR `72.18.53.189` → `mail.cloistr.xyz`; `cloistr.xyz` MX → `mail.cloistr.xyz` →
`72.18.53.189` (resolves direct, not Cloudflare); SPF `v=spf1 ip4:72.18.53.189 -all`. Cloudflare never
proxied SMTP. So reusing `72.18.53.189` for mail is consistent — the IP *is* the cloistr mail identity
(PTR/MX/SPF aligned). The orange→grey cutover changes nothing about mail posture.

**The live mail path today:** `stream.d/mail.conf` binds `:25/465/587/143/993/110/995` on the edge →
backend `10.60.169.11`. So there is no port-25 "rebind blocker".

**DECIDED 2026-06-29: `cloistr-email` REPLACES `10.60.169.11` and becomes the sole mail application.**
This is the simple, idempotent path — a backend repoint, not a new listener:

1. Expose `cloistr-email` over **NodePort** for every mail protocol it serves (≥ SMTP 25, submission 587;
   plus 465/143/993/110/995 if it implements them). `cloistr-email-smtp` is a private MetalLB LB today →
   add NodePorts in the `cloistr-ingress` role so the edge reaches it at `node-IP:nodePort`.
2. In `stream.d/mail.conf`, repoint each `proxy_pass` upstream `10.60.169.11:<port>` → the matching
   `cloistr-email` NodePort. **Map per-protocol:** keep only the ports cloistr-email actually implements;
   drop any the new app doesn't serve (don't blind-forward 143/993/110/995 if it's SMTP-only).
   ⚠ **Confirm cloistr-email's protocol surface** before repointing (does it do IMAP/POP, or webmail-only
   mailbox access + SMTP?). This is the one open item for the mail repoint.
3. `10.60.169.11` is retired once no protocol still points at it.

All idempotent via Atlas: the stream file lives in `nginx_proxy/files/stream.d/`, the NodePorts in the
`cloistr-ingress` role.

**Two mail properties to honor:**
- **TLS terminates at the mail backend** (the stream is L4 passthrough). The edge HTTPS/coldforge cert is
  irrelevant to mail; the backend needs its own valid cert for `mail.cloistr.xyz`.
- **Real client IP** is hidden from the backend by the L4 proxy unless **PROXY protocol** (v1/v2) is
  enabled on the nginx stream *and* supported by the backend — matters for spam scoring / logging.

### 13.4 Idempotent Atlas management (per the 2026-06-29 management decision)

Everything below is declared in Atlas and applied idempotently — re-running converges with no drift. No
hand-run `oc`/`kubectl`, no manual nginx edits, no dashboard DNS changes.

| Artifact | Atlas home | Apply / mechanism |
|---|---|---|
| HTTP vhosts (`sites-enabled/cloistr.xyz/*`) | `roles/nginx_proxy/files/sites-enabled/` | `site.yml` nginx_proxy play (file + `nginx -t` + reload) |
| L4 stream configs (`stream.d/*.conf`) | `roles/nginx_proxy/files/stream.d/` | same nginx_proxy play |
| certbot SANs (per-host `-d`) | `roles/nginx_proxy/tasks/main.yml` (`certonly --expand`) | nginx_proxy play; renewal via certbot.renew.timer |
| OpenShift **Routes** + **NodePorts** | new `roles/kube/cloistr-ingress/` (mirror `cloistr-tunnel`'s structure) | `atlas kube apply cloistr-ingress` via `kubernetes.core.k8s` |
| **DNS** A-records (gray-cloud) | the cloistr-ingress role's `flarectl`/`uri` DNS task | role apply (idempotent create/update; token is DNS-edit scope) |
| Tunnel route removal (per service) | `roles/kube/cloistr-tunnel/defaults/main.yml` `cloistr_services` | `atlas kube apply cloistr-tunnel` |

Notes:
- The new `cloistr-ingress` role is the §6 "Route ownership" answer — Routes/NodePorts live in Atlas, not
  cloistr-config (which manages no Routes and doesn't contain `cloistr-me`/`cloistr-email`). Keeps the
  whole edge in one idempotent place alongside `cloistr-tunnel`.
- The DNS gray-cloud flip must be idempotent (remove stale CNAME→tunnel, ensure A→`72.18.53.189`
  proxied=false). Note `flarectl dns create` errors on the apex's empty `--name`, so the apex record
  needs the `uri` module against the CF API (as the cert-manager token task already does).
- Prod applies are gated by the V17 prod-target hooks; each `atlas kube apply` / nginx play needs a
  `verify_action` (or override) per the go/no-go for that phase.

---

## Reference

- `~/Atlas/roles/kube/cloistr-tunnel/` — current tunnel role to be retired
- `~/Atlas/roles/nginx_proxy/` — edge box: `sites-enabled/` (HTTP vhosts), `stream.d/` (L4), `tasks/main.yml` (certbot SANs)
- `~/Atlas/roles/kube/apply/cert-manager/` — cert issuance, retained post-drop
- `~/Atlas/roles/kube/cloistr-signer/` — signer service definition, ingress-config target
- privacy-architecture.md §1.1, §3.2, §4 item #3
- privacy-architecture.md item #4 — onion endpoint, separate parallel work
