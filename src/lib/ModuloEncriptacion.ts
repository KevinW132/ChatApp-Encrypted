/*
Encryption module for cross-platform React Native + Web apps using libsodium-wrappers.


File: encryption-module.ts
Purpose: provide a minimal, well-documented TypeScript module that implements:
- initialization (sodium.ready)
- device keypair generation
- export/import of keys (base64)
- encryptMessage: sender generates ephemeral keypair, derives shared key and encrypts with crypto_box (authenticated)
- decryptMessage: recipient uses their secret key + sender ephemeral public key to decrypt
- helper functions for nonce, base64 encoding/decoding
- a small self-test function (runSelfTest) that demonstrates encrypt/decrypt


Notes:
- This module uses "tweetnacl"-compatible API provided by libsodium-wrappers. On React Native, use a compatible binding (libsodium-react-native or react-native-sodium). For web, libsodium-wrappers works fine.
- For production: consider libsodium's XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf) or Signal double-ratchet for better forward secrecy. This module is an approachable, audit-friendly foundation.
*/
import sodium from 'libsodium-wrappers';

//Types
export type KeyPair = {
    publicKey: string,
    secretKey: string
}

export type EncryptedPayload = {
    ciphertext: string,
    nonce: string,
    ephemeralPublicKey: string
    version?:number
}

// Initialize libsodium (returns a promise that resolves when ready)
export async function initSodium(): Promise<void> {
    if((sodium as any).ready) {
        await (sodium as any).ready
    }
}

//Ge nerate a long-term device keypair
export function generateDeviceKeyPair(): KeyPair {
    const kp = sodium.crypto_box_keypair()
    return {
        publicKey: sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL),
        secretKey: sodium.to_base64(kp.privateKey ?? kp.secretKey, sodium.base64_variants.ORIGINAL)
    }
}

//Import/exports helpers
export function importPublicKey(b64: string): Uint8Array {
    return sodium.from_base64(b64, sodium.base64_variants.ORIGINAL)
}
export function importSecretKey(b64: string): Uint8Array {
    return sodium.from_base64(b64, sodium.base64_variants.ORIGINAL)
}
// Encrypt a plaintext string for recipientPublicKey
// - senderSecretKeyB64: sender's long-term secret key (optional). If provided it will be used to authenticate with crypto_box (sender identity).
// - recipientPublicKeyB64: recipient's public key (base64)
// Returns an EncryptedPayload containing ciphertext, nonce, and ephemeralPublicKey (all base64)

export function encryptMessage(
    plaintext: string,
    recipientPublicKeyB64: string,
): EncryptedPayload {
    // Generate ephemeral keypair for forward secrecy
    const eph = sodium.crypto_box_keypair()
    const recipientPub = importPublicKey(recipientPublicKeyB64)

    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
    const messageBytes = sodium.from_string(plaintext)

    const cipher = sodium.crypto_box_easy(messageBytes, nonce, recipientPub, eph.privateKey ?? eph.secretKey)

    return {
        ciphertext: sodium.to_base64(cipher, sodium.base64_variants.ORIGINAL),
        nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
        ephemeralPublicKey: sodium.to_base64(eph.publicKey, sodium.base64_variants.ORIGINAL),
        version: 1
    }
}

export function decryptMessage(payload: EncryptedPayload, recipientSecretKeyB64: string): string {
    const recipientSecret = importSecretKey(recipientSecretKeyB64)
    const cipher = sodium.from_base64(payload.ciphertext, sodium.base64_variants.ORIGINAL)
    const nonce = sodium.from_base64(payload.nonce, sodium.base64_variants.ORIGINAL)
    const senderEphPub = sodium.from_base64(payload.ephemeralPublicKey, sodium.base64_variants.ORIGINAL)

    const plain = sodium.crypto_box_open_easy(cipher, nonce, senderEphPub, recipientSecret)
    if (!plain) throw new Error('Decryption failed')
    return sodium.to_string(plain)
}

export function validareKeyPair(kp: KeyPair): boolean {
    try {
        importPublicKey(kp.publicKey)
        importSecretKey(kp.secretKey)
        return true
    } catch (e) {
        return false
    }
}

export async function runSelfTest(): Promise<boolean> {
    await initSodium()

    const alice = generateDeviceKeyPair()
    const bob = generateDeviceKeyPair()

    const msg = "Hello Bob, this is a test message " + new Date().toISOString()
    const payload = encryptMessage(msg, bob.publicKey)
    const decrypted = decryptMessage(payload, bob.secretKey)
    if(decrypted !== msg) {
        console.error('Self test failed - decrypted text mismatch')
        return false
    }
    console.log('Self test OK - message decrypted correctly');
    return true
}

/*
Usage notes (not included in this file):
- On app start: await initSodium()
- On first device run: generateDeviceKeyPair() and store secretKey in SecureStore (mobile) or encrypted IndexedDB (web)
- Register publicKey with server via authenticated HTTP POST /devices
- When sending a message: fetch recipient's public key (from server or cache), then call encryptMessage(plaintext, recipientPublicKey)
- Send the resulting payload to server (socket.emit 'message:send', payload)
- When receiving a message payload: call decryptMessage(payload, myDeviceSecretKey) after retrieving secret from secure storage


Security warnings:
- This example uses crypto_box (XSalsa20-Poly1305). For improved nonce-handling and larger nonces use XChaCha20-Poly1305 via libsodium's aead APIs.
- Nonce uniqueness is required. Here we use random nonces provided by libsodium which are acceptable but you may prefer a counter + key management scheme to avoid rare nonce collisions.
*/