import { deepStrictEqual, throws } from "assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../src/algorithms.js";
import { EdDSA } from "../src/algorithms/EdDSA.js";
import { CWT } from "../src/cwt.js";

const { privateKey, publicKey } = EdDSA.generateKeyPair();

const alg = new EdDSA(privateKey, publicKey);

describe("Decode", () => {
  it("Ed22519 Token Decode", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
          10: "abc",
          abc: 10,
        },
        unprotected: {
          10: "abc",
          abc: 10,
        },
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    const decoded = CWT.decode(token);

    deepStrictEqual(decoded.header.protected.alg, CWTAlgorithms.EdDSA);
    deepStrictEqual(decoded.header.protected[10], "abc");
    deepStrictEqual(decoded.header.protected["abc"], 10);

    deepStrictEqual(decoded.header.unprotected[10], "abc");
    deepStrictEqual(decoded.header.unprotected["abc"], 10);

    deepStrictEqual(decoded.payload.sub, "1234567890");
    deepStrictEqual(decoded.payload.name, "John Doe");
    deepStrictEqual(decoded.payload.iat, date);
    deepStrictEqual(decoded.payload.test, undefined);
  });

  it("Token Decode Empty Buffer", () => {
    throws(
      () => CWT.decode(Buffer.from([])),
      /^Error: Unexpected end of CBOR data$/
    );
  });
});
