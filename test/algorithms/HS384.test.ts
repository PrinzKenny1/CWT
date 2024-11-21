import { doesNotThrow } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../../src/algorithms.js";
import { HS384 } from "../../src/algorithms/HS384.js";
import { CWT } from "../../src/cwt.js";

describe("HS384 Check", () => {
  it("check read file functionality", () => {
    doesNotThrow(() => new HS384("./keys/secret.txt"));
  });

  it("should sign and verify HS384", () => {
    const alg = new HS384("./keys/secret.txt");

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.HS384,
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
