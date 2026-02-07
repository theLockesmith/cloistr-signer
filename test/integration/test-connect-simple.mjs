// Simple connect test
import NDK, { NDKPrivateKeySigner, NDKEvent, NDKUser } from '@nostr-dev-kit/ndk';
import crypto from 'crypto';

const RELAY_URL = 'wss://relay.coldforge.xyz';
const TESTKEY_PUBKEY = '1b9a8d756b54ee7f6807ed36ced1f220ee7b7fc159e397f71c195a7a289a17af';
const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';

async function main() {
  console.log('=== Connect Test ===\n');

  const clientSigner = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  const clientUser = await clientSigner.user();

  const ndk = new NDK({
    explicitRelayUrls: [RELAY_URL, 'wss://relay.damus.io'],
    enableOutboxModel: false
  });
  ndk.signer = clientSigner;
  await ndk.connect(5000);
  console.log('Connected!\n');

  const requestId = crypto.randomBytes(16).toString('hex');
  // connect takes the client pubkey as first param
  const request = { id: requestId, method: 'connect', params: [clientUser.pubkey] };

  console.log(`Request ID: ${requestId}`);
  console.log(`Target: ${TESTKEY_PUBKEY}`);
  console.log(`Method: connect`);
  console.log(`Client pubkey: ${clientUser.pubkey}\n`);

  const encryptedContent = await clientSigner.encrypt(
    new NDKUser({ pubkey: TESTKEY_PUBKEY }),
    JSON.stringify(request)
  );

  const event = new NDKEvent(ndk);
  event.kind = 24133;
  event.content = encryptedContent;
  event.tags = [['p', TESTKEY_PUBKEY]];
  await event.sign();

  console.log('Sending connect request...');
  const relays = await event.publish();
  console.log(`Published to ${relays.size} relay(s)\n`);

  const sub = ndk.subscribe({
    kinds: [24133, 24134],
    '#p': [clientUser.pubkey],
    since: Math.floor(Date.now() / 1000) - 60
  });

  sub.on('event', async (e) => {
    console.log(`Event from ${e.pubkey.slice(0, 16)}...`);
    if (e.pubkey !== TESTKEY_PUBKEY) return;

    try {
      const d = await clientSigner.decrypt(new NDKUser({ pubkey: e.pubkey }), e.content);
      console.log(`Decrypted: ${d}`);
      const r = JSON.parse(d);
      if (r.id === requestId) {
        console.log(`\n✅ Connect result: ${r.result}`);
        console.log(`   Error: ${r.error || 'none'}`);
        process.exit(0);
      }
    } catch (err) {
      console.log(`Decrypt error: ${err.message}`);
    }
  });

  setTimeout(() => { console.log('\n⏱️ Timeout'); process.exit(1); }, 15000);
}

main().catch(console.error);
