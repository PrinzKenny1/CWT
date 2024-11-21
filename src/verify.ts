import { decode } from "cbor-x";
import { CWTAlgorithms } from "./algorithms.js";
import { Algorithm } from "./algorithms/algorithm.js";
import { CWTHeader } from "./header.js";
import { CWTPayload } from "./payload.js";
import { CWTSign } from "./sign.js";

export type CWTValidationOpts = {
  iss?: string;
  aud?: string;
  clockSkewSeconds?: number;
  expNeeded?: boolean;
  subNeeded?: boolean;
  nbfNeeded?: boolean;
  iatNeeded?: boolean;
  ctiNeeded?: boolean;
  overrideCurrentDate?: Date;
};

export namespace CWTVerify {
  export function verify(
    token: Buffer,
    alg: Algorithm,
    validationOpts: CWTValidationOpts
  ) {
    const [
      protectedHeaderSerialized,
      unprotectedHeader,
      payloadSerialized,
      signature,
    ] = decode(token);

    const header = CWTHeader.convertToHeader(
      protectedHeaderSerialized,
      unprotectedHeader
    );

    if (header.protected.alg !== alg.getAlgorithm()) {
      throw new Error(
        `Header algorithm "${CWTAlgorithms.toName(
          header.protected.alg
        )}" doesn't match input algorithm "${CWTAlgorithms.toName(
          alg.getAlgorithm()
        )}".`
      );
    }

    const signatureObject = CWTSign.createSignObject(
      protectedHeaderSerialized,
      payloadSerialized
    );

    const verifyResult = alg.verify(signatureObject, signature);

    if (false === verifyResult) {
      throw new Error("Signature doesn't match header and/or payload.");
    }

    const payload = CWTPayload.convertToPayload(payloadSerialized);

    validate(payload, validationOpts);

    return { header, payload, signature };
  }

  function validate(payload: CWTPayload, validationOpts: CWTValidationOpts) {
    validationOpts = {
      iss: undefined,
      aud: undefined,
      clockSkewSeconds: 0,
      expNeeded: false,
      subNeeded: false,
      nbfNeeded: false,
      iatNeeded: false,
      ctiNeeded: false,
      overrideCurrentDate: undefined,
      ...validationOpts,
    };

    validateIss(payload, validationOpts);
    validateAud(payload, validationOpts);
    validateCti(payload, validationOpts);
    validateSub(payload, validationOpts);

    const currentDateInSeconds = Math.floor(
      (validationOpts.overrideCurrentDate == undefined
        ? Date.now()
        : validationOpts.overrideCurrentDate.getTime()) / 1000
    );

    const clockSkew = validationOpts.clockSkewSeconds ?? 0;

    validateExp(payload, validationOpts, currentDateInSeconds, clockSkew);
    validateNbf(payload, validationOpts, currentDateInSeconds, clockSkew);
    validateIat(payload, validationOpts, currentDateInSeconds, clockSkew);
  }

  function validateIss(payload: CWTPayload, validationOpts: CWTValidationOpts) {
    if (undefined !== payload.iss) {
      if (typeof payload.iss !== "string") {
        throw new Error(
          `Expected iss to be of type string, got: "${typeof payload.iss}"`
        );
      }
    }

    if (undefined !== validationOpts.iss) {
      if (payload.iss !== validationOpts.iss) {
        throw new Error(
          `iss of payload and validation options is not matching! expected: "${validationOpts.iss}" got: "${payload.iss}"`
        );
      }
    }
  }

  function validateAud(payload: CWTPayload, validationOpts: CWTValidationOpts) {
    if (undefined !== payload.aud) {
      if (!Array.isArray(payload.aud)) {
        throw new Error(
          `Expected aud to be of type stringarray, got: "${typeof payload.aud}"`
        );
      } else if (!payload.aud.every((val) => typeof val == "string")) {
        throw new Error(`An element inside of aud is not a string"`);
      }
    }

    if (undefined !== validationOpts.aud) {
      if (!payload.aud?.includes(validationOpts.aud)) {
        throw new Error(
          `aud of payload and validation options is not matching! expected: "${validationOpts.aud}" got: "${payload.aud}"`
        );
      }
    }
  }

  function validateCti(payload: CWTPayload, validationOpts: CWTValidationOpts) {
    if (undefined !== payload.cti) {
      if (typeof payload.cti !== "string") {
        throw new Error(
          `Expected cti to be of type string, got: "${typeof payload.cti}"`
        );
      }
    }

    if (validationOpts.ctiNeeded) {
      if (undefined === payload.cti) {
        throw new Error(`Expected payload to have cti key`);
      }
    }
  }

  function validateSub(payload: CWTPayload, validationOpts: CWTValidationOpts) {
    if (undefined !== payload.sub) {
      if (typeof payload.sub !== "string") {
        throw new Error(
          `Expected sub to be of type string, got: "${typeof payload.sub}"`
        );
      }
    }

    if (validationOpts.subNeeded) {
      if (undefined === payload.sub) {
        throw new Error(`Expected payload to have sub key`);
      }
    }
  }

  function validateExp(
    payload: CWTPayload,
    validationOpts: CWTValidationOpts,
    currentDateInSeconds: number,
    clockSkew: number
  ) {
    if (undefined !== payload.exp) {
      if (typeof payload.exp !== "number") {
        throw new Error(
          `Expected exp to be of type number, got: "${typeof payload.exp}"`
        );
      }
    }

    if (validationOpts.expNeeded) {
      if (undefined === payload.exp) {
        throw new Error(`Expected payload to have exp key`);
      }

      if (payload.exp + clockSkew < currentDateInSeconds) {
        throw new Error(`Token is expired`);
      }
    }
  }

  function validateNbf(
    payload: CWTPayload,
    validationOpts: CWTValidationOpts,
    currentDateInSeconds: number,
    clockSkew: number
  ) {
    if (undefined !== payload.nbf) {
      if (typeof payload.nbf !== "number") {
        throw new Error(
          `Expected nbf to be of type number, got: "${typeof payload.nbf}"`
        );
      }
    }

    if (validationOpts.nbfNeeded) {
      if (undefined === payload.nbf) {
        throw new Error(`Expected payload to have nbf key`);
      }

      if (payload.nbf > currentDateInSeconds + clockSkew) {
        throw new Error(`Token is not valid yet`);
      }
    }
  }

  function validateIat(
    payload: CWTPayload,
    validationOpts: CWTValidationOpts,
    currentDateInSeconds: number,
    clockSkew: number
  ) {
    if (undefined !== payload.iat) {
      if (typeof payload.iat !== "number") {
        throw new Error(
          `Expected iat to be of type number, got: "${typeof payload.iat}"`
        );
      }
    }

    if (validationOpts.iatNeeded) {
      if (undefined === payload.iat) {
        throw new Error(`Expected payload to have iat key`);
      }

      if (payload.iat > currentDateInSeconds + clockSkew) {
        throw new Error(`Token is issued in the future`);
      }
    }
  }
}
