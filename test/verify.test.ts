import { decode, encode } from "cbor-x";
import { deepStrictEqual, doesNotThrow, throws } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../src/algorithms.js";
import { EdDSA } from "../src/algorithms/EdDSA.js";
import CWT from "../src/cwt.js";
import { CWTHeader } from "../src/header.js";

const { privateKey, publicKey } = EdDSA.generateKeyPair();

const alg = new EdDSA(privateKey, publicKey);

describe("Verify", () => {
  it("Ed22519 Token Verify", () => {
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
        iss: "Issuer",
        nbf: date,
        exp: date,
        iat: date,
        aud: ["Audience1", "Audience2"],
        cti: "nfsdn832rhs",
      },
      alg
    );

    doesNotThrow(() =>
      CWT.verify(token, alg, {
        aud: "Audience1",
      })
    );
  });

  it("Ed22519 Token Verify Modified Token", () => {
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

    const fakeToken = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "111111",
        name: "John Prime",
        iat: date,
      },
      alg
    );

    const [_, __, ___, signature] = decode(token);

    const [
      protectedHeaderSerialized,
      unprotectedHeader,
      payloadSerialized,
      ____,
    ] = decode(fakeToken);

    const modifiedToken = encode([
      protectedHeaderSerialized,
      unprotectedHeader,
      payloadSerialized,
      signature,
    ]);

    throws(
      () => CWT.verify(modifiedToken, alg, {}),
      /^Error: Signature doesn't match header and\/or payload.$/
    );
  });

  it("Ed22519 Token Verify Modified Token Header Algorithm", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    const [_, unprotectedHeader, payloadSerialized, signature] = decode(token);

    const [protectedHeaderSerialized, __] = CWTHeader.convertToMap({
      protected: {
        alg: CWTAlgorithms.HS256,
      },
      unprotected: {},
    });

    const modifiedToken = encode([
      protectedHeaderSerialized,
      unprotectedHeader,
      payloadSerialized,
      signature,
    ]);

    throws(
      () => CWT.verify(modifiedToken, alg, {}),
      /^Error: Header algorithm .*$/
    );
  });

  it("Ed22519 Token Verify Modified Token Header No Algorithm", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    const [_, unprotectedHeader, payloadSerialized, signature] = decode(token);

    const modifiedToken = encode([
      encode(new Map()),
      unprotectedHeader,
      payloadSerialized,
      signature,
    ]);

    throws(() => CWT.verify(modifiedToken, alg, {}), /^Error: This alg .*$/);
  });

  it("Ed22519 Token Verify Modified Token Unknown Header Key", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    const [_, unprotectedHeader, payloadSerialized, signature] = decode(token);

    const modifiedToken = encode([
      encode(new Map([[-1000000, undefined]])),
      unprotectedHeader,
      payloadSerialized,
      signature,
    ]);

    throws(() => CWT.verify(modifiedToken, alg, {}), /^Error: This alg .*$/);
  });

  it("Ed22519 Token Verify Modified Token Unknown Payload Key", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    const [protectedHeaderSerialized, unprotectedHeader, _, signature] =
      decode(token);

    const modifiedToken = encode([
      protectedHeaderSerialized,
      unprotectedHeader,
      encode(new Map([[-1000000, undefined]])),
      signature,
    ]);

    throws(
      () => CWT.verify(modifiedToken, alg, {}),
      /^Error: Signature doesn't match header and\/or payload.$/
    );
  });

  it("Ed22519 Token Verify Modified Token No Signature", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    const [protectedHeaderSerialized, unprotectedHeader, payloadSerialized, _] =
      decode(token);

    const modifiedToken = encode([
      protectedHeaderSerialized,
      unprotectedHeader,
      payloadSerialized,
    ]);

    throws(
      () => CWT.verify(modifiedToken, alg, {}),
      /^TypeError \[ERR_INVALID_ARG_TYPE\]: The "signature" argument must be an instance of Buffer, TypedArray, or DataView. Received undefined$/
    );
  });

  it("Ed22519 Token Verify Equals Decode", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    deepStrictEqual(CWT.verify(token, alg, {}), CWT.decode(token));
  });

  it("Ed22519 Token Verify ValidationOpts OverrideCurrentDate", () => {
    const date = Math.floor(Date.now() / 1000);

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        sub: "1234567890",
        name: "John Doe",
        iat: date,
      },
      alg
    );

    deepStrictEqual(
      CWT.verify(token, alg, {
        overrideCurrentDate: new Date(),
        iatNeeded: true,
        clockSkewSeconds: 2,
      }),
      CWT.decode(token)
    );
  });

  it("Ed22519 Token Verify ValidationOpts undefined clockskew", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    deepStrictEqual(
      CWT.verify(token, alg, {
        clockSkewSeconds: undefined,
      }),
      CWT.decode(token)
    );
  });

  /**
   * IAT CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing iat", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          iatNeeded: true,
        }),
      /Error: Expected payload to have iat key/
    );
  });

  it("Ed22519 Token Verify ValidationOpts iat in future", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        iat: Date.now(),
      },
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          iatNeeded: true,
        }),
      /Error: Token is issued in the future/
    );
  });

  it("Ed22519 Token Verify ValidationOpts iat no number", () => {
    const payload: any = {
      iat: "Date.now()",
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          iatNeeded: true,
        }),
      /Error: Expected iat to be of type number, got: .*/
    );
  });

  /**
   * NBF CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing nbf", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          nbfNeeded: true,
        }),
      /Error: Expected payload to have nbf key/
    );
  });

  it("Ed22519 Token Verify ValidationOpts nbf in future", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        nbf: Date.now(),
      },
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          nbfNeeded: true,
        }),
      /Error: Token is not valid yet/
    );
  });

  it("Ed22519 Token Verify ValidationOpts nbf no number", () => {
    const payload: any = {
      nbf: "Date.now()",
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          nbfNeeded: true,
        }),
      /Error: Expected nbf to be of type number, got: .*/
    );
  });

  /**
   * EXP CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing exp", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          expNeeded: true,
        }),
      /Error: Expected payload to have exp key/
    );
  });

  it("Ed22519 Token Verify ValidationOpts exp expired", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {
        exp: 0,
      },
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          expNeeded: true,
        }),
      /Error: Token is expired/
    );
  });

  it("Ed22519 Token Verify ValidationOpts exp no number", () => {
    const payload: any = {
      exp: "Date.now()",
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          expNeeded: true,
        }),
      /Error: Expected exp to be of type number, got: .*/
    );
  });

  /**
   * SUB CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing sub", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          subNeeded: true,
        }),
      /Error: Expected payload to have sub key/
    );
  });

  it("Ed22519 Token Verify ValidationOpts sub no string", () => {
    const payload: any = {
      sub: 1234,
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          subNeeded: true,
        }),
      /Error: Expected sub to be of type string, got: .*/
    );
  });

  /**
   * CTI CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing cti", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          ctiNeeded: true,
        }),
      /Error: Expected payload to have cti key/
    );
  });

  it("Ed22519 Token Verify ValidationOpts cti no string", () => {
    const payload: any = {
      cti: 1234,
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          ctiNeeded: true,
        }),
      /Error: Expected cti to be of type string, got: .*/
    );
  });

  /**
   * ISS CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing iss", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          iss: "Issuer1",
        }),
      /Error: iss of payload and validation options is not matching! expected: .*/
    );
  });

  it("Ed22519 Token Verify ValidationOpts iss no string", () => {
    const payload: any = {
      iss: 1234,
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          iss: "Issuer1",
        }),
      /Error: Expected iss to be of type string, got: .*/
    );
  });

  /**
   * AUD CHECK
   */

  it("Ed22519 Token Verify ValidationOpts Missing aud", () => {
    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      {},
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          aud: "",
        }),
      /Error: aud of payload and validation options is not matching! expected: .*/
    );
  });

  it("Ed22519 Token Verify ValidationOpts aud is not an array", () => {
    const payload: any = {
      aud: 1234,
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          aud: "Audience1",
        }),
      /Error: Expected aud to be of type stringarray, got: .*/
    );
  });

  it("Ed22519 Token Verify ValidationOpts aud element in array is not a string", () => {
    const payload: any = {
      aud: [1234],
    };

    const token = CWT.sign(
      {
        protected: {
          alg: CWTAlgorithms.EdDSA,
        },
        unprotected: {},
      },
      payload,
      alg
    );

    throws(
      () =>
        CWT.verify(token, alg, {
          aud: "Audience1",
        }),
      /Error: An element inside of aud is not a string/
    );
  });
});
