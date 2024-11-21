import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { RS256 } from "../../src/algorithms/RS256.js";
import { CWT } from "../../src/cwt.js";

describe("RS256 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new RS256("./keys/rs-512-private.key", "./keys/rs-512-public.key")
    );
  });

  it("should sign and verify RS256", () => {
    const alg = new RS256(
      "./keys/rs-512-private.key",
      "./keys/rs-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.RS256,
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
    doesNotThrow(() => RS256.generateKeyPair());
  });
});
