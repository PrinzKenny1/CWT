import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { ES512 } from "../../src/algorithms/ES512.js";
import { CWT } from "../../src/cwt.js";

describe("ES512 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(
      () => new ES512("./keys/es-512-private.key", "./keys/es-512-public.key")
    );
  });

  it("should sign and verify ES512", () => {
    const alg = new ES512(
      "./keys/es-512-private.key",
      "./keys/es-512-public.key"
    );

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.ES512,
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
    doesNotThrow(() => ES512.generateKeyPair());
  });
});
