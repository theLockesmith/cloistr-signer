// FROST P4e: browser-side cosign listener.
//
// Subscribes to kind:24135 (cosign request) events on the user's FROST
// key relays. When a request arrives:
//   1. NIP-44 decrypt using our session ephemeral privkey
//   2. Verify key_id matches one of our locally stored FROST shares
//   3. Emit a UI event so a modal can render the approval prompt
//   4. On approve: use WASM to compute the user's partial sig,
//      publish kind:24136 back to the same relays
//   5. On deny: publish a denial kind:24136
//
// Design contract: docs/frost-cosigning-design.md §2.2.

import { SimplePool, generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools';
import { nip44 } from 'nostr-tools';
import { hasShare, loadShare, isShareStorageUnlocked } from './frostStorage';
import init, {
  generate_signing_nonce_pair,
  compute_user_partial_signature,
} from '../../frost-wasm/pkg/cloistr_frost_wasm.js';
import wasmUrl from '../../frost-wasm/pkg/cloistr_frost_wasm_bg.wasm?url';

let wasmReady: Promise<void> | null = null;
async function ensureWasm(): Promise<void> {
  if (!wasmReady) {
    wasmReady = init(wasmUrl).then(() => undefined);
  }
  return wasmReady;
}

const KIND_COSIGN_REQUEST = 24135;
const KIND_COSIGN_RESPONSE = 24136;

/** Payload the signer NIP-44-encrypts inside a kind:24135 event. */
export interface CosignRequestPayload {
  v: number;
  event_to_sign: {
    pubkey: string;
    kind: number;
    tags: string[][];
    content: string;
    created_at: number;
    id?: string;
    sig?: string;
  };
  event_id: string;
  signer_commitment: {
    hiding: string;
    binding: string;
  };
  session_id: string;
  key_id: string;
}

/** Payload the browser NIP-44-encrypts inside a kind:24136 response. */
export interface CosignResponsePayload {
  v: 1;
  approved: boolean;
  reason?: string;
  user_commitment?: {
    hiding: string;
    binding: string;
  };
  partial_signature_hex?: string;
}

/** Extra context passed alongside the request for UI display. */
export interface PendingCosignRequest {
  sessionEphemeralPubkey: string; // signer's ephemeral pubkey (kind:24135 event.pubkey)
  sessionId: string;
  keyId: string;
  eventToSign: CosignRequestPayload['event_to_sign'];
  eventId: string;
  signerCommitment: CosignRequestPayload['signer_commitment'];
  receivedAt: number;
}

/** Handle emitted to the UI so it can call back approve/deny. */
export interface CosignApprovalHandle {
  request: PendingCosignRequest;
  approve: () => Promise<void>;
  deny: (reason: string) => Promise<void>;
}

export type CosignApprovalHandler = (h: CosignApprovalHandle) => void;

interface ListenerConfig {
  /** Relays to subscribe on for cosign requests. */
  relays: string[];
  /** Session-scoped ephemeral secret key (hex). Same one that signs
   *  NIP-46 responses for this session. Used to NIP-44-decrypt
   *  incoming cosign requests. */
  sessionSecretKey: string;
  /** Called when a valid cosign request arrives. UI renders modal,
   *  calls approve or deny on the handle. */
  onRequest: CosignApprovalHandler;
}

export class FrostCosignListener {
  private pool: SimplePool;
  private sub: { close: () => void } | null = null;
  private config: ListenerConfig;
  private sessionPubkey: string;

  constructor(config: ListenerConfig) {
    this.pool = new SimplePool();
    this.config = config;
    const skBytes = hexToBytes(config.sessionSecretKey);
    this.sessionPubkey = getPublicKey(skBytes);
  }

  async start(): Promise<void> {
    if (this.sub) return; // already running
    await ensureWasm();

    // Filter: cosign requests p-tagged to our session pubkey.
    const filter = {
      kinds: [KIND_COSIGN_REQUEST],
      '#p': [this.sessionPubkey],
    };
    this.sub = this.pool.subscribeMany(this.config.relays, [filter] as any, {
      onevent: (event) => {
        this.handleRequest(event).catch((err) => {
          console.error('[FrostCosignListener] request handling failed:', err);
        });
      },
    });
  }

  stop(): void {
    if (this.sub) {
      this.sub.close();
      this.sub = null;
    }
  }

  private async handleRequest(event: {
    id: string;
    pubkey: string;
    kind: number;
    tags: string[][];
    content: string;
  }): Promise<void> {
    if (event.kind !== KIND_COSIGN_REQUEST) return;

    // Tags: [p, session, key_id]
    const sessionTag = event.tags.find((t) => t[0] === 'session')?.[1];
    const keyIdTag = event.tags.find((t) => t[0] === 'key_id')?.[1];
    if (!sessionTag || !keyIdTag) return;

    // Verify we have a local share for this key. If not, silently drop —
    // maybe the request is for a different device.
    if (!(await hasShare(keyIdTag))) return;

    // NIP-44 decrypt via nostr-tools nip44.
    const conversationKey = nip44.v2.utils.getConversationKey(
      hexToBytes(this.config.sessionSecretKey),
      event.pubkey,
    );
    let plaintext: string;
    try {
      plaintext = nip44.v2.decrypt(event.content, conversationKey);
    } catch (err) {
      console.warn('[FrostCosignListener] decrypt failed:', err);
      return;
    }

    let payload: CosignRequestPayload;
    try {
      payload = JSON.parse(plaintext);
    } catch {
      return;
    }
    if (payload.v !== 1) return;
    if (payload.session_id !== sessionTag) return;
    if (payload.key_id !== keyIdTag) return;

    // Emit approval handle to UI.
    const request: PendingCosignRequest = {
      sessionEphemeralPubkey: event.pubkey,
      sessionId: payload.session_id,
      keyId: payload.key_id,
      eventToSign: payload.event_to_sign,
      eventId: payload.event_id,
      signerCommitment: payload.signer_commitment,
      receivedAt: Date.now(),
    };
    const handle: CosignApprovalHandle = {
      request,
      approve: () => this.approveRequest(request),
      deny: (reason) => this.denyRequest(request, reason),
    };
    this.config.onRequest(handle);
  }

  private async approveRequest(req: PendingCosignRequest): Promise<void> {
    if (!isShareStorageUnlocked()) {
      throw new Error('share storage is locked; cannot cosign');
    }
    await ensureWasm();

    const share = await loadShare(req.keyId);
    if (!share) throw new Error(`no local share for key ${req.keyId}`);

    // Generate our nonce pair.
    const nonce = generate_signing_nonce_pair() as {
      nonce_state_hex: string;
      hiding_commitment_hex: string;
      binding_commitment_hex: string;
    };

    // Compute our partial sig.
    const jointPubkeyCompressed = '02' + share.pubkey; // x-only Nostr → even-Y compressed
    const partialHex = compute_user_partial_signature(
      nonce.nonce_state_hex,
      share.finalShareHex,
      nonce.hiding_commitment_hex,
      nonce.binding_commitment_hex,
      req.signerCommitment.hiding,
      req.signerCommitment.binding,
      jointPubkeyCompressed,
      req.eventId,
    ) as string;

    const responsePayload: CosignResponsePayload = {
      v: 1,
      approved: true,
      user_commitment: {
        hiding: nonce.hiding_commitment_hex,
        binding: nonce.binding_commitment_hex,
      },
      partial_signature_hex: partialHex,
    };

    await this.publishResponse(req, responsePayload);
  }

  private async denyRequest(req: PendingCosignRequest, reason: string): Promise<void> {
    await this.publishResponse(req, { v: 1, approved: false, reason });
  }

  private async publishResponse(
    req: PendingCosignRequest,
    payload: CosignResponsePayload,
  ): Promise<void> {
    const responseSK = generateSecretKey();

    const conversationKey = nip44.v2.utils.getConversationKey(
      responseSK,
      req.sessionEphemeralPubkey,
    );
    const ciphertext = nip44.v2.encrypt(JSON.stringify(payload), conversationKey);

    const event = finalizeEvent(
      {
        kind: KIND_COSIGN_RESPONSE,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['p', req.sessionEphemeralPubkey],
          ['session', req.sessionId],
        ],
        content: ciphertext,
      },
      responseSK,
    );
    // Publish to all configured relays.
    await Promise.allSettled(
      this.config.relays.map(async (url) => {
        const relay = await this.pool.ensureRelay(url);
        await relay.publish(event);
      }),
    );
  }
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

