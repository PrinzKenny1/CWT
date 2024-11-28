import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { RS384 } from "../../src/algorithms/RS384.js";
import CWT from "../../src/cwt.js";

describe("RS384 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new RS384("./keys/rs-512-private.key", "./keys/rs-512-public.key")
    );
  });

  it("should sign and verify RS384", () => {
    const alg = new RS384(
      "./keys/rs-512-private.key",
      "./keys/rs-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.RS384,
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
    doesNotThrow(() => RS384.generateKeyPair());
  });
});
