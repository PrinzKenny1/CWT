import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { HS512 } from "../../src/algorithms/HS512.js";
import { CWT } from "../../src/cwt.js";

describe("HS512 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(() => new HS512("./keys/secret.txt"));
  });

  it("should sign and verify HS512", () => {
    const alg = new HS512("./keys/secret.txt");

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.HS512,
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
