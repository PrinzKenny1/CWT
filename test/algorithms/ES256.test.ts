import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { ES256 } from "../../src/algorithms/ES256.js";
import { CWT } from "../../src/cwt.js";

describe("ES256 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new ES256("./keys/es-256-private.key", "./keys/es-256-public.key")
    );
  });

  it("should sign and verify ES256", () => {
    const alg = new ES256(
      "./keys/es-256-private.key",
      "./keys/es-256-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.ES256,
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
    doesNotThrow(() => ES256.generateKeyPair());
  });
});
