import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { ES384 } from "../../src/algorithms/ES384.js";
import { CWT } from "../../src/cwt.js";

describe("ES384 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new ES384("./keys/es-384-private.key", "./keys/es-384-public.key")
    );
  });

  it("should sign and verify ES384", () => {
    const alg = new ES384(
      "./keys/es-384-private.key",
      "./keys/es-384-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.ES384,
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
    doesNotThrow(() => ES384.generateKeyPair());
  });
});
