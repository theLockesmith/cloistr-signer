# Telegram Summary

---

**Signer Chaining: Team Delegation Without New NIPs**

We figured out how to let teams share a Nostr identity with instant revocation - using only existing NIP-46.

The trick: NIP-46 signers can also be NIP-46 clients. Your personal signer (Amber) proxies to a business signer. Revocation = delete a database row.

No new NIPs. No ecosystem-wide changes. Just a new feature for personal signers.

Full writeup: [LINK TO BLOG POST]

Looking for feedback + signer maintainers interested in implementing proxy key support.

---

# Alternative (shorter)

---

**Solved: Team delegation with instant revocation**

NIP-26 is dead. We found a better way using NIP-46 signer chaining:

Client → Personal Signer → Business Signer → signed event

No new NIPs. Revocation is instant (database delete). Team members keep their signer of choice.

Writeup: [LINK]

---

# Alternative (question format to spark discussion)

---

**Has anyone tried chaining NIP-46 signers?**

We realized signers can be clients to other signers. This means:

- Your Amber can proxy to a business signer
- Business controls the key, you control your workflow
- Revocation = instant (no NIP-26 time-bound nonsense)

We wrote it up: [LINK]

Curious if this has been tried before or if we're missing something obvious.
