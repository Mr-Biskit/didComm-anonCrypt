import * as Jose from "jose";

interface PublicKey {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: Jose.JWK;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  keyAgreement: PublicKey[];
}
