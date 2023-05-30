import * as Kilt from "@kiltprotocol/sdk-js";
import { DidDocument } from "../models/didDocument";
import { arrayBufferToBase64Url } from "./helpers";

export async function queryFullDid(
  didUri: Kilt.DidUri
): Promise<Kilt.DidDocument | null> {
  const resolutionResult = await Kilt.Did.resolve(didUri);

  if (
    resolutionResult === null ||
    resolutionResult.metadata.deactivated ||
    resolutionResult.document === undefined
  ) {
    console.log(`DID ${didUri} has been deleted or does not exist.`);
    return null;
  } else {
    return resolutionResult.document;
  }
}

export async function convertDidDocumentToJwk(
  didDocument: Kilt.DidDocument
): Promise<DidDocument> {
  const context = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
  ];
  const id = didDocument.uri;
  const keyAgreementId = `${didDocument.uri}${didDocument.keyAgreement![0].id}`;
  const base64PublicKey = arrayBufferToBase64Url(
    didDocument.keyAgreement![0].publicKey
  );

  const DIDDoc: DidDocument = {
    "@context": context,
    id: id,
    keyAgreement: [
      {
        id: keyAgreementId,
        type: "JsonWebKey2020",
        controller: id,
        publicKeyJwk: {
          kty: "OKP",
          crv: "X25519",
          x: base64PublicKey,
        },
      },
    ],
  };

  return DIDDoc;
}
