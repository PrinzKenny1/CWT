import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { PS384 } from "../../src/algorithms/PS384.js";
import CWT from "../../src/cwt.js";

describe("PS384 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new PS384("./keys/ps-512-private.key", "./keys/ps-512-public.key")
    );
  });

  it("should sign and verify PS384", () => {
    const alg = new PS384(
      "./keys/ps-512-private.key",
      "./keys/ps-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.PS384,
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
    doesNotThrow(() => PS384.generateKeyPair());
  });
});
