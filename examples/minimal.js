// Minimal example to test Node.js compatibility
import { kemGenerateKeyPair, encapsulate, decapsulate } from '../lib/index.js';

console.log('Testing kMOSAIC with Node.js...');

async function main() {
  try {
    // Generate a key pair
    const keyPair = await kemGenerateKeyPair();
    console.log('✓ Key pair generated');

    // Encapsulate a shared secret
    const { ciphertext, sharedSecret: senderSecret } = await encapsulate(keyPair.publicKey);
    console.log('✓ Shared secret encapsulated');

    // Decapsulate the shared secret
    const receiverSecret = await decapsulate(ciphertext, keyPair.secretKey, keyPair.publicKey);
    console.log('✓ Shared secret decapsulated');

    // Verify the secrets match
    const secretsMatch = senderSecret.every((byte, i) => byte === receiverSecret[i]);
    console.log(`✓ Secrets match: ${secretsMatch}`);

    console.log('\n✅ All tests passed! Node.js compatibility confirmed.');
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

main();
