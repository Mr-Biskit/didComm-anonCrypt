import * as Kilt from "@kiltprotocol/sdk-js";
import crypto from "crypto";

import {
  blake2AsU8a,
  keyExtractPath,
  keyFromPath,
  mnemonicGenerate,
  mnemonicToMiniSecret,
  sr25519PairFromSeed,
} from "@polkadot/util-crypto";
import { generateAccount } from "./generateAccount";

// Generate a key agreement key pair from a mnemonic
function generateKeyAgreement(mnemonic: string) {
  const secretKeyPair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic));
  const { path } = keyExtractPath("//did//keyAgreement//0");
  const { secretKey } = keyFromPath(secretKeyPair, path, "sr25519");
  return Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(
    blake2AsU8a(secretKey)
  );
}

// Generate all necessary key pairs for a DID
export function generateKeypairs(mnemonic = mnemonicGenerate()) {
  const { account } = generateAccount(mnemonic);
  const authentication = {
    ...account.derive("//did//0"),
    type: "sr25519",
  } as Kilt.KiltKeyringPair;
  const assertionMethod = {
    ...account.derive("//did//assertion//0"),
    type: "sr25519",
  } as Kilt.KiltKeyringPair;
  const capabilityDelegation = {
    ...account.derive("//did//delegation//0"),
    type: "sr25519",
  } as Kilt.KiltKeyringPair;
  const keyAgreement = generateKeyAgreement(mnemonic);

  return {
    authentication: authentication,
    keyAgreementPublicKey: keyAgreement.publicKey,
    keyAgreementPrivateKey: keyAgreement.secretKey,
    keyAgreement: keyAgreement,
    assertionMethod: assertionMethod,
    capabilityDelegation: capabilityDelegation,
  };
}
