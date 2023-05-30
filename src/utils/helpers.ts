import { sha256 } from "js-sha256";
import { base64url } from "jose";
import * as Jose from "jose";
import { generateKeypairs } from "./keyManagement";
import { DidDocument } from "../models/didDocument";

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

export async function createPrivateKeyJwk(
  seed: string,
  didDoc: DidDocument
): Promise<Jose.JWK> {
  const { keyAgreementPrivateKey, keyAgreementPublicKey } =
    await generateKeypairs(seed);
  const privateKeyJwk = {
    kid: didDoc.keyAgreement![0].id,
    kty: "OKP",
    crv: "X25519",
    x: arrayBufferToBase64Url(keyAgreementPublicKey),
    d: arrayBufferToBase64Url(keyAgreementPrivateKey),
  };

  return privateKeyJwk;
}
