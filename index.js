import {
  compactDecrypt,
  CompactEncrypt,
  exportJWK,
  importJWK,
  generateKeyPair,
  generateSecret,
  jwtVerify,
  SignJWT,
} from "jose";

const { publicKey, privateKey } = await generateKeyPair("ES256");
const secretKey = await generateSecret("HS256");

const privateJwk = await exportJWK(privateKey);
const publicJwk = await exportJWK(publicKey);
const secretJwk = await exportJWK(secretKey);

const importedPublicKey = await importJWK(publicJwk, "ES256");
const importedPrivateKey = await importJWK(privateJwk, "ES256");
const importedSecretKey = await importJWK(secretJwk, "HS256");

const payload = { data: { hello: "world" } };

const jwt = await new SignJWT(payload)
  .setProtectedHeader({ alg: "ES256" })
  .setIssuedAt()
  .setIssuer("urn:example:issuer")
  .setAudience("urn:example:audience")
  .setExpirationTime("2h")
  .sign(importedPrivateKey);

const jwe = await new CompactEncrypt(new TextEncoder().encode(jwt))
  .setProtectedHeader({ alg: "dir", cty: "JWT", enc: "A256GCM" })
  .encrypt(importedSecretKey);

const decryptedJwe = await compactDecrypt(jwe, importedSecretKey);

const decodedJwt = await jwtVerify(
  new TextDecoder().decode(decryptedJwe.plaintext),
  importedPublicKey
);

console.log(
  "did it work?",
  payload.data.hello === decodedJwt.payload.data.hello
);
