# Signer Chaining: How We Solved Nostr's Delegation Problem Without a New NIP

**TL;DR:** We figured out how to let teams share a Nostr identity with instant revocation, no new NIPs required. It uses existing NIP-46 infrastructure in a way nobody's tried before. Here's how it works and why it matters.

---

## The Problem Everyone Gave Up On

NIP-26 delegation is dead. Officially "unrecommended." And for good reason - it never solved revocation properly, and getting the entire ecosystem to implement verification was a pipe dream.

But the problem it tried to solve is very real:

**How do you let multiple people post as a shared identity (a business, a project, a DAO) without sharing the private key?**

Current options suck:
- **Share the nsec** - Security nightmare. One person leaves angry, your identity is compromised.
- **Everyone uses the same remote signer** - Works, but now your team is locked into that signer's clients and workflows.
- **NIP-26 delegation** - Dead. No revocation. Nobody implements it.

We've been building [cloistr-signer](https://signer.cloistr.xyz), a NIP-46 remote signer, and we kept hitting this wall. Then we realized something obvious that apparently nobody had tried.

## NIP-46 Signers Can Be Clients Too

Here's the key insight: **Nothing in NIP-46 says a signer can't connect to another signer.**

What if your personal signer (Amber, nsecbunker, whatever you use) could proxy signing requests to an upstream business signer?

```
Your Client ──► Your Signer ──► Business Signer
   (Primal)       (Amber)        (cloistr-signer)
                                       │
                                  signs with
                                 business key
                                       │
Your Client ◄── Your Signer ◄──────────┘
```

**That's it.** NIP-46 all the way down. No new protocol. No new NIPs. No ecosystem-wide changes needed.

## Why This Actually Works

### Instant Revocation

The business signer has a simple permissions table:

```
delegate_pubkey: npub1john...
signing_key: npub1business...
methods: [sign_event, get_public_key]
```

John leaves the company? **DELETE FROM permissions.** Done. His next signing request fails immediately.

Compare this to NIP-26 where you'd need to:
- Publish a revocation event
- Hope all relays propagate it
- Hope all clients check it
- Or just wait for time-bounded delegation to expire

### Team Members Keep Their Setup

John uses Amber on his phone. Sarah uses nsecbunker on her server. Neither has to change their workflow.

They just add the business signer's bunker:// URI to their personal signer as a "proxy key." When their client asks them to sign as the business identity, their signer forwards the request upstream.

### The Business Stays in Control

Every signature flows through the business signer. You can:
- See exactly who signed what (audit log)
- Set per-delegate permissions (John can only sign kind:1, Sarah can sign anything)
- Revoke instantly
- Set expiration dates on permissions

### No Ecosystem Changes Required

The protocol already supports this. We don't need relays to change. We don't need clients to change. We don't even need most signers to change.

The only new feature needed is for personal signers to support "proxy keys" - bunker:// URIs that they forward requests to instead of signing locally.

## The Catch (And Why We're Building It Ourselves)

For this to work end-to-end, personal signers need to implement proxy key support. Currently:

| Signer | Proxy Key Support |
|--------|-------------------|
| Amber | Not yet |
| nsecbunker | Not yet |
| cloistr-signer | Ready as upstream, **proxy support in development** |

We're not waiting for the ecosystem. **We're implementing both sides in cloistr-signer** - it will work as an upstream business signer AND as a proxy personal signer. This gives us:

1. A working reference implementation to point to
2. A full test harness (two instances, one chain)
3. Proof that the pattern actually works before asking others to implement it

Once we have it working, we'll file feature requests on Amber and nsecbunker with "here's how we did it, here's the code."

## How to Try It (Coming Soon)

We're building full signer chaining support now. The test setup will be:

```
Your Client ──► cloistr-signer (proxy) ──► coldforge-signer (upstream)
```

Two instances of the same signer software, one acting as your "personal signer" with proxy support, one acting as the "business signer" holding the shared key.

**In the meantime**, you can test the upstream pattern:

1. Your team members connect their clients directly to cloistr-signer
2. Each member's pubkey gets authorized to sign with the business key
3. Revocation works instantly - remove permission, next request fails

This proves the authorization model. Full chaining is next.

## What We're Building

In cloistr-signer, we're adding:
- Team management UI - invite delegates by npub
- One-time bunker:// URIs for secure onboarding
- Delegate activity dashboard - who signed what, when
- Per-delegate kind restrictions - limit what types of events they can sign

We'll open source the technical spec and welcome other signers to implement the pattern.

## The Bigger Picture

This is what makes Nostr special. We didn't need permission to solve this. We didn't need a committee. We just... realized the protocol already supported what we needed.

NIP-46 was designed for "keep your key safe, let apps request signatures." But the same primitive works for "keep the business key safe, let delegates request signatures."

Same protocol. Same flow. New use case.

## Get Involved

- **Technical docs:** [docs/signer-chaining.md](https://github.com/coldforge/cloistr-signer/blob/master/docs/signer-chaining.md)
- **Try cloistr-signer:** [signer.cloistr.xyz](https://signer.cloistr.xyz)
- **Discussion:** Reply to this note or find us on the usual relays

If you maintain a personal signer and want to discuss implementing proxy key support, reach out. We're happy to collaborate.

---

*This is a Coldforge project. We build infrastructure for Nostr.*
