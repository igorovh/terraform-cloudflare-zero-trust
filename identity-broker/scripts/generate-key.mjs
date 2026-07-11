import { generateKeyPairSync, randomUUID } from "node:crypto";

const { privateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

const jwk = privateKey.export({ format: "jwk" });
jwk.alg = "ES256";
jwk.use = "sig";
jwk.kid = `identity-broker-${randomUUID()}`;

console.log(JSON.stringify(jwk, null, 2));
