import {
  DIDCommEncryptedMessage,
  PlaintextMessage,
} from "../models/didCommMessage";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import * as Jose from "jose";
import { base64url } from "jose";
import { stringToShaHash } from "../utils/helpers";
import * as Kilt from "@kiltprotocol/sdk-js";
import { DidDocument } from "../models/didDocument";

// export async function encryptMessage(
//   message: { plaintext: PlaintextMessage; signature: Kilt.DidSignature },
//   recipientDidDoc: DidDocument
// ) {
//   // Convert the DIDCommMessage to a JSON string
//   const messageString = JSON.stringify(message);

//   // Generate a random 256-bit key for AES encryption
//   const aesKey = randomBytes(32);

//   // Encrypt the message using AES-256-GCM
//   const iv = randomBytes(12); // GCM requires a 12-byte IV
//   const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
//   let encrypted = cipher.update(messageString, "utf8", "hex");
//   encrypted += cipher.final("hex");

//   const recipentsKeyAgreementJwk =
//     recipientDidDoc.keyAgreement![0].publicKeyJwk;

//   // Convert the recipient's public key to a JWK
//   const publicKeyJwk = await Jose.importJWK(
//     recipentsKeyAgreementJwk,
//     "ECDH-ES+A256KW"
//   );

//   // Encrypt the AES key using ECDH-ES+A256KW with the recipient's public key
//   const jwt = await new Jose.EncryptJWT({
//     encrypted_key: aesKey.toString("base64"),
//   })
//     .setIssuedAt()
//     .setProtectedHeader({
//       alg: "ECDH-ES+A256KW",
//       enc: "A256GCM",
//       epk: recipentsKeyAgreementJwk,
//       apv: await stringToShaHash(recipientDidDoc.keyAgreement![0].id),
//     })
//     .encrypt(publicKeyJwk);

//   // Return encryption objects needed for the EncryptedDIDCommMessage
//   return {
//     ciphertext: encrypted,
//     protect: jwt.split(".")[0],
//     iv: iv.toString("hex"),
//     tag: jwt.split(".")[3],
//     encrypted_key: aesKey.toString("base64"),
//   };
// }

// export async function decryptMessage(
//   encryptedMessage: DIDCommEncryptedMessage,
//   recipientPrivateKey: Jose.JWK
// ): Promise<{ plaintext: PlaintextMessage; signature: Kilt.DidSignature }> {
//   // Fetch the encrypted key for the recipient from the recipients array
//   const recipient = encryptedMessage.recipients.find(
//     (recipient) => recipient.header.kid === recipientPrivateKey.kid
//   );
//   if (!recipient) {
//     throw new Error("No encrypted key found for the recipient in the message");
//   }

//   // Convert the recipient's private key to a JWK
//   const privateKeyJwk = await Jose.importJWK(
//     recipientPrivateKey,
//     "ECDH-ES+A256KW"
//   );

//   const jwt = `${encryptedMessage.protected}..${recipient.encrypted_key}..${encryptedMessage.tag}`;
//   const protectedHeader = Jose.decodeProtectedHeader(jwt);
//   console.log(protectedHeader);
//   // Decrypt the AES key using ECDH-ES+A256KW with the recipient's private key
//   const { payload } = await Jose.jwtDecrypt(jwt, privateKeyJwk);

//   const aesKey = base64url.decode(payload.encrypted_key as string);

//   // Decrypt the message using AES-256-GCM
//   const iv = Buffer.from(encryptedMessage.iv, "hex");
//   const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);

//   let decrypted = decipher.update(encryptedMessage.ciphertext, "hex", "utf8");
//   decrypted += decipher.final("utf8");

//   // Parse the decrypted message
//   const message = JSON.parse(decrypted);

//   return {
//     plaintext: message,
//     signature: encryptedMessage.signature,
//   };
// }
export async function encryptMessage(
  message: { plaintext: PlaintextMessage; signature: Kilt.DidSignature },
  recipientDidDoc: DidDocument
) {
  // Convert the DIDCommMessage to a JSON string
  const messageString = JSON.stringify(message);

  // Generate a random 256-bit key for AES encryption
  const aesKey = randomBytes(32);

  // Encrypt the message using AES-256-GCM
  const iv = randomBytes(12); // GCM requires a 12-byte IV
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  let encrypted = cipher.update(messageString, "utf8", "hex");
  encrypted += cipher.final("hex");

  const recipientKeyAgreementJwk =
    recipientDidDoc.keyAgreement![0].publicKeyJwk;

  // Convert the recipient's public key to a JWK
  const publicKeyJwk = await Jose.importJWK(
    recipientKeyAgreementJwk,
    "ECDH-ES+A256KW"
  );

  // Encrypt the AES key using ECDH-ES+A256KW with the recipient's public key
  const jwe = await new Jose.CompactEncrypt(aesKey)
    .setProtectedHeader({
      alg: "ECDH-ES+A256KW",
      enc: "A256GCM",
      epk: recipientKeyAgreementJwk,
      apv: await stringToShaHash(recipientDidDoc.keyAgreement![0].id),
    })
    .encrypt(publicKeyJwk);

  const jweSegments = jwe.split(".");
  const protectedHeader = jweSegments[0];
  const encryptedKey = jweSegments[1];
  const tag = jweSegments[4];

  // Return encryption objects needed for the EncryptedDIDCommMessage
  return {
    ciphertext: encrypted,
    protect: protectedHeader,
    iv: iv.toString("hex"),
    tag: tag,
    recipients: [
      {
        encrypted_key: encryptedKey,
        header: {
          kid: recipientDidDoc.keyAgreement[0].id as Kilt.DidResourceUri,
        },
      },
    ],
  };
}
export async function decryptMessage(
  encryptedMessage: DIDCommEncryptedMessage,
  recipientPrivateKey: Jose.JWK
): Promise<{ plaintext: PlaintextMessage; signature: Kilt.DidSignature }> {
  console.log("encryptedMessage", encryptedMessage.recipients[0]);
  console.log("recipientPrivateKey", recipientPrivateKey);
  // Fetch the encrypted key for the recipient from the recipients array
  const recipient = encryptedMessage.recipients.find(
    (recipient) => recipient.header.kid === recipientPrivateKey.kid
  );

  if (!recipient) {
    throw new Error("No encrypted key found for the recipient in the message");
  }

  // Convert the recipient's private key to a JWK
  const privateKeyJwk = await Jose.importJWK(
    recipientPrivateKey,
    "ECDH-ES+A256KW"
  );

  const jwe = `${encryptedMessage.protected}..${recipient.encrypted_key}..${encryptedMessage.tag}`;

  // Decrypt the AES key using ECDH-ES+A256KW with the recipient's private key
  const decryptedKey = await Jose.compactDecrypt(jwe, privateKeyJwk);

  // We now have the AES key, we can decrypt the message
  const aesKey = decryptedKey.plaintext;

  // Decrypt the message using AES-256-GCM
  const iv = Buffer.from(encryptedMessage.iv, "hex");
  const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);

  let decrypted = decipher.update(encryptedMessage.ciphertext, "hex", "utf8");
  decrypted += decipher.final("utf8");

  // Parse the decrypted message
  const message = JSON.parse(decrypted);

  return {
    plaintext: message,
    signature: encryptedMessage.signature,
  };
}
