import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { RS512 } from "../../src/algorithms/RS512.js";
import { CWT } from "../../src/cwt.js";

describe("RS512 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new RS512("./keys/rs-512-private.key", "./keys/rs-512-public.key")
    );
  });

  it("should sign and verify RS512", () => {
    const alg = new RS512(
      "./keys/rs-512-private.key",
      "./keys/rs-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.RS512,
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
    doesNotThrow(() => RS512.generateKeyPair());
  });
});
