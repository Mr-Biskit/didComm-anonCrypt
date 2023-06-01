import { sha256 } from "js-sha256";
import { base64url } from "jose";
import * as Jose from "jose";
import { generateKeypairs } from "./keyManagement";
import { DidDocument } from "../models/didDocument";
import { createPrivateKey, createPublicKey, KeyObject } from "crypto";
import * as jose from "node-jose";

export async function createKeyObjectFromUint8Array(
  publicKey: Uint8Array,
  privateKey?: Uint8Array
): Promise<KeyObject> {
  // 1. Convert Uint8Array to JWK
  let jwk = {
    kty: "OKP",
    crv: "X25519",
    x: Buffer.from(publicKey).toString("base64"),
    ...(privateKey ? { d: Buffer.from(privateKey).toString("base64") } : {}),
  };

  // 2. Convert JWK to PEM
  let pem = (await jose.JWK.asKey(jwk)).toPEM();

  // 3. Create KeyObject
  return privateKey ? createPrivateKey(pem) : createPublicKey(pem);
}

export function arrayBufferToBase64Url(arrayBuffer: Uint8Array) {
  return base64url.encode(arrayBuffer);
}

export async function stringToShaHash(string: string) {
  const hash = await sha256.create();
  hash.update(string);

  const hexHash = hash.hex();

  const bytes = new Uint8Array(
    hexHash.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
  );
  return base64url.encode(bytes);
}

export async function createPrivateKeyJwk(seed: string, didDoc: DidDocument) {
  const { keyAgreementPrivateKey, keyAgreementPublicKey } =
    await generateKeypairs(seed);
  const privateKey = await createKeyObjectFromUint8Array(
    keyAgreementPublicKey,
    keyAgreementPrivateKey
  );
  const privateKeyJwk = {
    kid: didDoc.keyAgreement![0].id,
    kty: "OKP",
    crv: "X25519",
    x: arrayBufferToBase64Url(keyAgreementPublicKey),
    d: arrayBufferToBase64Url(keyAgreementPrivateKey),
  };

  return privateKey;
}
