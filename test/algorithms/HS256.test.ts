import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { HS256 } from "../../src/algorithms/HS256.js";
import CWT from "../../src/cwt.js";

describe("HS256 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(() => new HS256("./keys/secret.txt"));
  });

  it("should sign and verify HS256", () => {
    const alg = new HS256("./keys/secret.txt");

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.HS256,
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
});
