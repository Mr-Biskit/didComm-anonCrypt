import { encryptMessage } from "./encryption";
import { signMessage } from "./signing";
import {
  PlaintextMessage,
  DIDCommEncryptedMessage,
} from "../models/didCommMessage";

// Create, Sign and Encrypt a DIDComm message
export async function createSignedEncryptedMessage(
  message: PlaintextMessage,
  signCallback: any,
  didUri: string,
  recipients: string[]
): Promise<DIDCommEncryptedMessage> {
  try {
    const signedMessage = await signMessage(message, signCallback, didUri);
    const encryptedMessage = await encryptMessage(
      message,
      signedMessage,
      recipients
    );
    return encryptedMessage;
  } catch (error) {
    console.error("Error creating message:", error);
    throw error;
  }
}

// const encryptedMessage = {
//     ciphertext: encrypted,
//     iv: iv.toString("hex"),
//     tag: jwt.split(".")[3], // The tag is the fourth part of the JWT
//     recipients: [
//       {
//         encrypted_key: aesKey.toString("base64"),
//         header: {
//           kid: publicKeyJwk,
//         },
//       },
//     ],
//     protected: jwt.split(".")[0], // The protected header is the first part of the JWT
//   };
