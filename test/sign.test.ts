import { doesNotThrow, throws } from "assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../src/algorithms.js";
import { EdDSA } from "../src/algorithms/EdDSA.js";
import CWT from "../src/cwt.js";

const { privateKey, publicKey } = EdDSA.generateKeyPair();

const alg = new EdDSA(privateKey, publicKey);

describe("Signing/Create", () => {
  it("Ed22519 Token Sign/Create", () => {
    doesNotThrow(() =>
      CWT.sign(
        {
          protected: {
            alg: CWTAlgorithms.EdDSA,
          },
          unprotected: {},
        },
        {
          sub: "1234567890",
          name: "John Doe",
          iat: Math.floor(Date.now() / 1000),
        },
        alg
      )
    );
  });

  it("Ed22519 Token Sign/Create Wrong Header Algorithm", () => {
    throws(
      () =>
        CWT.sign(
          {
            protected: {
              alg: CWTAlgorithms.ES256,
            },
            unprotected: {},
          },
          {
            sub: "1234567890",
            name: "John Doe",
            iat: Math.floor(Date.now() / 1000),
          },
          alg
        ),
      /^Error: Header algorithm .*$/
    );
  });
});
