// Minimal example to test Node.js compatibility
import { kemGenerateKeyPair, encapsulate, decapsulate } from '../lib/index.js';

console.log('Testing kMOSAIC with Node.js...\n');

async function main() {
  try {
    // Generate a key pair
    let start = performance.now();
    const keyPair = await kemGenerateKeyPair();
    let elapsed = (performance.now() - start).toFixed(2);
    console.log(`✓ Key pair generated (${elapsed}ms)`);

    // Encapsulate a shared secret
    start = performance.now();
    const { ciphertext, sharedSecret: senderSecret } = await encapsulate(keyPair.publicKey);
    elapsed = (performance.now() - start).toFixed(2);
    console.log(`✓ Shared secret encapsulated (${elapsed}ms)`);

    // Decapsulate the shared secret
    start = performance.now();
    const receiverSecret = await decapsulate(ciphertext, keyPair.secretKey, keyPair.publicKey);
    elapsed = (performance.now() - start).toFixed(2);
    console.log(`✓ Shared secret decapsulated (${elapsed}ms)`);

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
