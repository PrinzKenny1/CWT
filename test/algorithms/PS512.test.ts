import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { PS512 } from "../../src/algorithms/PS512.js";
import CWT from "../../src/cwt.js";

describe("PS512 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new PS512("./keys/ps-512-private.key", "./keys/ps-512-public.key")
    );
  });

  it("should sign and verify PS512", () => {
    const alg = new PS512(
      "./keys/ps-512-private.key",
      "./keys/ps-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.PS512,
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
    doesNotThrow(() => PS512.generateKeyPair());
  });
});
