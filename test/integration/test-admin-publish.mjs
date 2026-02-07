// Test if admin key can publish to coldforge relay
import NDK, { NDKPrivateKeySigner, NDKEvent } from '@nostr-dev-kit/ndk';

const ADMIN_KEY_HEX = '5c300b0008fa7307ca35585aab688eb4aae6ab98250b968c4ebb425be7af98fe';

async function main() {
  const ndk = new NDK({
    explicitRelayUrls: ['wss://relay.coldforge.xyz'],
    enableOutboxModel: false
  });

  const signer = new NDKPrivateKeySigner(ADMIN_KEY_HEX);
  ndk.signer = signer;

  const user = await signer.user();
  console.log(`Testing publish with pubkey: ${user.pubkey}`);

  await ndk.connect(5000);
  console.log('Connected to relay');

  // Create a test note
  const event = new NDKEvent(ndk);
  event.kind = 1;
  event.content = `Test from admin key - ${Date.now()}`;
  event.tags = [];

  try {
    await event.sign();
    const relays = await event.publish();
    console.log(`Published to ${relays.size} relay(s)`);
    console.log(`Event ID: ${event.id}`);

    // Try to fetch it back
    const events = await ndk.fetchEvents({ ids: [event.id] });
    if (events.size > 0) {
      console.log('✅ Event stored and retrieved successfully!');
    } else {
      console.log('❌ Event not found on relay');
    }
  } catch (e) {
    console.log(`❌ Failed to publish: ${e.message}`);
  }

  process.exit(0);
}

main().catch(console.error);
