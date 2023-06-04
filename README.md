# DIDComm Message Encryption Implementation

This project aims to implement DIDComm message encryption using the X25519 elliptic curve for key agreement. The project is based on the DIDComm Messaging specification, which provides guidelines for encrypting messages with the keys of a single DID.

## What We Are Trying to Accomplish

We are implementing Anonymous Sender Encryption ("anoncrypt") for DIDComm messages. This form of encryption ensures that the message is encrypted to the recipient DID, but does not provide direct assurances of who the sender is. 

The encrypted form of a JWM (JSON Web Message) is a JWE (JSON Web Encryption) in General JSON Format. We are using the JOSE (JavaScript Object Signing and Encryption) family of standards, specifically the `jose` library, to create and manage these structures.

## How We Are Doing It

1. **Message Encryption**: We are encrypting DIDComm Messages with the keys of a single DID. If a message is being sent to multiple DIDs, it must be encrypted for each DID independently.

2. **Key Agreement**: We are using the X25519 elliptic curve for key agreement. This curve is used in the context of Diffie-Hellman for key exchange.

3. **Content Encryption**: For content encryption of the message, we are using AES 256-bit keys.

4. **Key Wrapping**: We are using ECDH-ES+A256KW for key wrapping, using a key with X25519 to create a 256 bits key.

5. **Key Representation**: Keys are represented in JWK (JSON Web Key) format. 

6. **Key Import**: We are importing JWKs using the `jose` library's `.importJWK` function.

7. **SHA256 Hashing**: We are using SHA256 hashing for certain operations, and encoding the hash in base64 URL format.

## What Still Needs to Be Done

1. **Key Derivation**: We need to determine how to derive the "d" (private key) value for a JWK from a Uint8Array private key.

2. **Code Implementation**: We need to implement the encryption and decryption functions in TypeScript, using the `jose` library for JOSE operations and the chosen alternative library for other cryptographic operations.

3. **Testing**: Once the implementation is complete, we need to test it thoroughly to ensure it works correctly and securely.

## Resources

- [DIDComm Messaging Specification](https://identity.foundation/didcomm-messaging/spec/)
- [JOSE Library Documentation](https://github.com/panva/jose/blob/main/docs/classes/jwt_encrypt.EncryptJWT.md)
- [Crypto-JS Library](https://github.com/brix/crypto-js)
- [AES-JS Library](https://www.npmjs.com/package/aes-js)
