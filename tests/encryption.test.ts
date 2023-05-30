import { decryptMessage, encryptMessage } from "../src/didcomm/encryption";
import {
  DIDCommEncryptedMessage,
  PlaintextMessage,
} from "../src/models/didCommMessage";
import { createMessage } from "../src/didcomm/message";
import {
  queryFullDid,
  convertDidDocumentToJwk,
} from "../src/utils/didResolver";
import * as Kilt from "@kiltprotocol/sdk-js";
import { signMessage } from "../src/didcomm/signing";
import { generateKeypairs } from "../src/utils/keyManagement";
import * as Jose from "jose";
import { createPrivateKeyJwk } from "../src/utils/helpers";

const seed = process.env.ACCOUNT1_DID_MNEMONIC!;

describe("DIDComm encryption and decryption", () => {
  it("should encrypt a message", async () => {
    // Connect to the KILT blockchain
    await Kilt.connect("wss://peregrine.kilt.io/parachain-public-ws");

    // Query the DID
    const receiverdidDocument: Kilt.DidDocument | null = await queryFullDid(
      "did:kilt:4sBCQNWZAL9UkzEzSq56NFPecEzRysjsdAqigY1cPQbuK1W1" as Kilt.DidUri
    );
    const senderdidDocument: Kilt.DidDocument | null = await queryFullDid(
      "did:kilt:4qNLDkBxZDaM5U2jKkHro4xkQsyhnXFWMvQJ71WzAfDM51WU" as Kilt.DidUri
    );
    const didDocumentJwk = await convertDidDocumentToJwk(receiverdidDocument!);

    // Define a test message
    const plaintext: PlaintextMessage = createMessage(
      { test: "cheese" },
      senderdidDocument!.uri,
      [receiverdidDocument!.uri]
    );

    console.log(
      "This is the publickey: ",
      didDocumentJwk.keyAgreement![0].publicKeyJwk
    );

    // Sign the message
    const { authentication } = generateKeypairs(seed);
    const signature = await signMessage(
      plaintext,
      async ({ data }) => ({
        signature: authentication.sign(data),
        keyType: authentication.type,
      }),
      senderdidDocument!.uri
    );

    const message = {
      plaintext,
      signature,
    };

    // Encrypt the message
    const { ciphertext, protect, iv, tag } = await encryptMessage(
      message,
      didDocumentJwk
    );
    console.log("This is the ciphertext: ", ciphertext);
    console.log("This is the protect: ", protect);
    console.log("This is the iv: ", iv);
    console.log("This is the tag: ", tag);

    // Check that the decrypted message is the same as the original message
    expect(encryptMessage).toBeDefined();
    await Kilt.disconnect();
  });

  it.only("should decrypt a message", async () => {
    // Connect to the KILT blockchain
    await Kilt.connect("wss://peregrine.kilt.io/parachain-public-ws");

    // Query the DID
    const receiverdidDocument: Kilt.DidDocument | null = await queryFullDid(
      "did:kilt:4sBCQNWZAL9UkzEzSq56NFPecEzRysjsdAqigY1cPQbuK1W1" as Kilt.DidUri
    );
    const senderdidDocument: Kilt.DidDocument | null = await queryFullDid(
      "did:kilt:4qNLDkBxZDaM5U2jKkHro4xkQsyhnXFWMvQJ71WzAfDM51WU" as Kilt.DidUri
    );

    const didDocumentJwk = await convertDidDocumentToJwk(receiverdidDocument!);

    const seed = process.env.ACCOUNT2_DID_MNEMONIC! as string;

    const privateKeyJwk: Jose.JWK = await createPrivateKeyJwk(
      seed,
      didDocumentJwk
    );

    // Define a test message
    const plaintext: PlaintextMessage = createMessage(
      { test: "cheese" },
      senderdidDocument!.uri,
      [receiverdidDocument!.uri]
    );

    // Sign the message
    const { authentication } = generateKeypairs(seed);
    const signature = await signMessage(
      plaintext,
      async ({ data }) => ({
        signature: authentication.sign(data),
        keyType: authentication.type,
      }),
      senderdidDocument!.uri
    );

    const message = {
      plaintext,
      signature,
    };

    // Encrypt the message
    const { ciphertext, protect, iv, tag, recipients } = await encryptMessage(
      message,
      didDocumentJwk
    );

    const encryptedMessage: DIDCommEncryptedMessage = {
      signature: signature,
      ciphertext: ciphertext,
      protected: protect,
      iv: iv,
      tag: tag,
      recipients: [recipients[0]],
    };

    // Decrypt the message
    const decryptedMessage = await decryptMessage(
      encryptedMessage,
      privateKeyJwk
    );
    console.log("This is the decrypted message: ", decryptedMessage);

    // Check that the decrypted message is the same as the original message
    expect(decryptedMessage).toEqual(plaintext);
    await Kilt.disconnect();
  });
});
