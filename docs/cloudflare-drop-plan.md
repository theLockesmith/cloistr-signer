# Cloudflare Egress Drop Plan

**Status:** Plan draft
**Last updated:** 2026-06-16
**Implements:** privacy-architecture.md §3.2
**Dependencies:** Atlas access (the actual cutover work lives in `~/Atlas`)

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

After the drop:

- **Ingress controller** running on the cluster (nginx-ingress or Traefik), listening on a public IP.
- **Per-service Ingress resources** (currently forbidden per the existing tunnel role's README) replacing tunnel routes.
- **Direct DNS A records** pointing each hostname at the cluster ingress IP. DNS itself stays on Cloudflare (we still own the zone), but with proxying disabled (gray-cloud) so traffic goes direct.
- **Let's Encrypt certs issued via HTTP-01 challenge** on the new ingress, OR DNS-01 retained through Cloudflare's DNS API (lower-touch but keeps the Cloudflare API surface). Recommendation: keep DNS-01 — the DNS API is read-mostly for us and doesn't see user traffic.
- **fail2ban on the ingress nodes** for connection-level rate limiting.
- **nginx-ingress rate-limit annotations** for application-level rate limiting per host.
- **Onion endpoint** (privacy-architecture.md item #4) live in parallel as a co-equal entry point — separate work tracked as item #4.

## 4. DDoS Replacement Strategy

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

1. **drive.cloistr.xyz** (legacy alias) — lowest traffic, easy to roll back, validates the cutover playbook.
2. **stash.cloistr.xyz** (the actual file manager) — similar profile to drive.
3. **contacts.cloistr.xyz** — encrypted contact management, sees moderate traffic.
4. **files.cloistr.xyz** (Blossom) — large-file uploads stress the ingress more; tests that side.
5. **relay-admin.cloistr.xyz** — low traffic, admin-only.
6. **signer.cloistr.xyz** + **bunker.cloistr.xyz** — the privacy-critical pair. Move together since they share the same backend.
7. **documents.cloistr.xyz** — WebSocket, real-time. Tests that the new ingress handles WS at scale.
8. **relay.cloistr.xyz** — highest traffic, most disruptive if it fails. Move last.

### 5.3 Rollback procedure (per service)

If a cutover fails:

1. **Re-flip DNS** back to the tunnel CNAME. TTL was already lowered in step 3.
2. **Re-add service to `cloistr_services`** in the tunnel role and re-apply.
3. **Verify traffic returns to the tunnel route.**
4. **Leave the Ingress resource in place** for next attempt; debug offline.

Rollback wall-clock: 5-10 minutes if DNS TTL was lowered first.

## 6. Pre-Cutover Prerequisites

These must be in place BEFORE the first service cutover:

- [ ] **Ingress controller deployed** (nginx-ingress recommended; install via Atlas role).
- [ ] **Public IP allocated** for the ingress LoadBalancer service.
- [ ] **fail2ban configured** on ingress nodes with starter ruleset.
- [ ] **cert-manager keeping DNS-01 path** for now (no migration to HTTP-01 in this round).
- [ ] **Test certificate issued** for a throwaway hostname (`test-direct.cloistr.xyz`) to validate the path end-to-end.
- [ ] **Load test on staging** complete, baseline + safety margin established.
- [ ] **Atlas role for `cloistr-ingress`** (or similar) created, separate from `cloistr-tunnel`.
- [ ] **Documentation update**: the `cloistr-tunnel/README.md` line "Don't create Ingress resources" needs revision — that rule was tunnel-era; now we're explicitly creating them.
- [ ] **Runbook for cutover steps** with the per-step verification commands.

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
- **Migrating coldforge.xyz services off the tunnel.** Same tunnel routes those; this plan addresses cloistr.xyz only. Coldforge services follow with the same playbook once cloistr is proven.

## 11. Open Questions

1. **Ingress controller choice:** nginx-ingress vs Traefik. Both work; nginx-ingress is more battle-tested at the scale we're operating. Default to nginx-ingress unless ops has a reason.
2. **Provider DDoS:** which tier from current K8s host. Need to enumerate options + pricing.
3. **WebSocket ingress sticky session behavior:** verify that the new ingress doesn't break NIP-46 client reconnects for the signer.
4. **Cloudflare API token scope reduction post-cutover:** the current token has DNS-edit on cloistr.xyz, coldforge.xyz, coldforge.net. After the drop, we still need DNS-edit (cert-manager). Can we narrow scope further?
5. **`flarectl` automation** lives in the tunnel role today and manages the CNAME records. Post-drop, what manages the A records? Likely cert-manager's annotations + a separate flarectl pass for A records.

## 12. Phasing

Suggested implementation phases:

| Phase | Scope | Wall-clock |
|---|---|---|
| C1 | Pre-cutover prep: ingress controller, fail2ban, cert path validation, runbook | 1-2 weeks |
| C2 | Cutover service #1 (drive.cloistr.xyz). Validate playbook on lowest-stakes target. | 1 day + 1 week observation |
| C3 | Cutover services #2-#5 (stash, contacts, files, relay-admin). | 1 week |
| C4 | Cutover privacy-critical services (signer, bunker). Updates privacy-architecture status. | 2-3 days with extra monitoring |
| C5 | Cutover WebSocket-heavy services (documents). | 1-2 days |
| C6 | Cutover highest-traffic service (relay). | 2-3 days |
| C7 | Decommission cloistr-tunnel. Scale to 0, leave for 30 days, then delete. | 30-day soak + cleanup |

Total wall-clock with safety margins: **6-8 weeks** end-to-end. Compressible if a dedicated ops window is available.

---

## Reference

- `~/Atlas/roles/kube/cloistr-tunnel/` — current tunnel role to be retired
- `~/Atlas/roles/kube/apply/cert-manager/` — cert issuance, retained post-drop
- `~/Atlas/roles/kube/cloistr-signer/` — signer service definition, ingress-config target
- privacy-architecture.md §1.1, §3.2, §4 item #3
- privacy-architecture.md item #4 — onion endpoint, separate parallel work
