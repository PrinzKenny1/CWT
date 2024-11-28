import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { PS256 } from "../../src/algorithms/PS256.js";
import CWT from "../../src/cwt.js";

describe("PS256 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new PS256("./keys/ps-512-private.key", "./keys/ps-512-public.key")
    );
  });

  it("should sign and verify PS256", () => {
    const alg = new PS256(
      "./keys/ps-512-private.key",
      "./keys/ps-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.PS256,
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
    doesNotThrow(() => PS256.generateKeyPair());
  });
});
