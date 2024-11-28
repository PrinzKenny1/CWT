import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { EdDSA } from "../../src/algorithms/EdDSA.js";
import CWT from "../../src/cwt.js";

describe("EdDSA Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () =>
        new EdDSA("./keys/ed-25519-private.key", "./keys/ed-25519-public.key")
    );
  });

  it("should sign and verify EdDSA", () => {
    const alg = new EdDSA(
      "./keys/ed-25519-private.key",
      "./keys/ed-25519-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "test",
      },
      alg
    );

    CWT.verify(token, alg, {});
  });

  it("should return a private and public key", () => {
    doesNotThrow(() => EdDSA.generateKeyPair());
  });
});
