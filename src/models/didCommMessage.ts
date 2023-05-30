import * as Kilt from "@kiltprotocol/sdk-js";

export interface PlaintextMessage {
  id: string;
  type: string;
  from?: string;
  to?: string[];
  body: {
    text: string;
  };
  created_time?: number;
}

export enum DIDCommMessageTypes {
  PLAINTEXT = "application/didcomm-plain+json",
  SIGNED = "application/didcomm-signed+json",
  ANONCRYPT = "application/didcomm-encrypted+json",
  AUTHCRYPT = "application/didcomm-encrypted+json",
}

export interface DIDCommSignedMessage {
  payload: string;
  signatures: Signature[];
}

interface Signature {
  protected: string;
  signature: string;
  header: Header;
}

interface Header {
  kid: Kilt.DidResourceUri;
}

export interface DIDCommEncryptedMessage {
  signature: Kilt.DidSignature;
  ciphertext: string;
  protected: string;
  recipients: Recipient[];
  tag: string;
  iv: string;
}

interface Recipient {
  encrypted_key: string;
  header: Header;
}
