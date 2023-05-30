import { v4 as uuidv4 } from "uuid";
import { PlaintextMessage } from "../models/didCommMessage";

// Create a new PlainTextMessage
export function createMessage(
  body: any,
  from?: string,
  to?: string[]
): PlaintextMessage {
  return {
    id: uuidv4(),
    type: "protocol-identifier-uri/message-type-name",
    body: body,
    from: from,
    to: to,
    created_time: Math.floor(Date.now() / 1000),
  };
}

// Parse a DIDComm message from a string
export function parseMessage(messageString: string): PlaintextMessage {
  const message = JSON.parse(messageString);
  if (!message.id || !message.type || !message.body) {
    throw new Error("Invalid DIDComm message");
  }
  return message;
}

// Validate a DIDComm message
export function validateMessage(message: PlaintextMessage): boolean {
  return !!message.id && !!message.type && !!message.body;
}

// Create a new
