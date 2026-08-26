import { generateKeyPairSync } from "node:crypto";
import type { GlobalSetupContext } from "vitest/node";

function standardBase64FromBase64Url(value: string): string {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return padded + "=".repeat((4 - (padded.length % 4)) % 4);
}

function makeKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "jwk" });
  const priv = privateKey.export({ format: "jwk" });
  if (!pub.x || !priv.d || !priv.x) throw new Error("ED25519_JWK_EXPORT_FAILED");
  return {
    publicRawB64: standardBase64FromBase64Url(pub.x),
    privateJwk: JSON.stringify(priv),
  };
}

export default function setup({ provide }: GlobalSetupContext) {
  const admin = makeKey();
  const approval = makeKey();
  provide("adminPublicKeyB64", admin.publicRawB64);
  provide("adminPrivateJwk", admin.privateJwk);
  provide("approvalPublicKeyB64", approval.publicRawB64);
  provide("approvalPrivateJwk", approval.privateJwk);
}
