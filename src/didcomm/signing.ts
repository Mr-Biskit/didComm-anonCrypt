import { PlaintextMessage } from "../models/didCommMessage";
import * as Kilt from "@kiltprotocol/sdk-js";
import { queryFullDid } from "../utils/didResolver";

// Sign a DIDComm message
export async function signMessage(
  message: PlaintextMessage,
  signCallback: Kilt.SignExtrinsicCallback,
  didUri: Kilt.DidUri
): Promise<Kilt.DidSignature> {
  try {
    const signData: Kilt.SignRequestData = {
      data: Buffer.from(JSON.stringify(message)),
      keyRelationship: "authentication",
      did: didUri,
    };
    const signResult = await signCallback(signData);
    console.log("Message signed successfully");
    const document = await queryFullDid(didUri);
    const keyId = document?.authentication[0].id;

    return {
      keyUri: `${didUri}${keyId!}`,
      signature: Buffer.from(signResult.signature).toString("hex"),
    };
  } catch (error) {
    console.error("Error signing message:", error);
    throw error;
  }
}

// Verify the signature of a DIDComm message
export async function verifyMessageSignature(
  message: PlaintextMessage,
  signature: Kilt.DidSignature
): Promise<boolean> {
  try {
    const signatureUint8Array = Buffer.from(signature.signature, "hex");

    const keyUri: Kilt.DidResourceUri = signature.keyUri;

    const stringifiedMessage = Buffer.from(JSON.stringify(message));

    const expectedMethod: Kilt.VerificationKeyRelationship = "authentication";

    const verificationInput = {
      message: stringifiedMessage,
      signature: signatureUint8Array,
      keyUri: keyUri,
      expectedVerificationMethod: expectedMethod,
    };

    await Kilt.Did.verifyDidSignature(verificationInput);

    console.log("Signature verified successfully");
    return true;
  } catch (error) {
    console.error("Error verifying signature:", error);
    return false;
  }
}
