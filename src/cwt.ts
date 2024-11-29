import { decode, encode } from "cbor-x";
import { Algorithm } from "./algorithms/algorithm.js";
import { CWTHeader } from "./header.js";
import { CWTPayload } from "./payload.js";
import { CWTSign } from "./sign.js";
import { CWTValidationOpts, CWTVerify } from "./verify.js";

export class CWT {
  static sign(header: CWTHeader, payload: CWTPayload, alg: Algorithm) {
    const [protectedHeaderSerialized, unprotectedHeader] =
      CWTHeader.convertToMap(header);

    const payloadSerialized = CWTPayload.convertToMap(payload);

    const signatureObject = CWTSign.createSignObject(
      protectedHeaderSerialized,
      payloadSerialized
    );

    const signature = CWTSign.sign(signatureObject, header.protected.alg, alg);

    return encode([
      protectedHeaderSerialized,
      unprotectedHeader,
      payloadSerialized,
      signature,
    ]);
  }

  static decode(token: Buffer): {
    header: CWTHeader;
    payload: CWTPayload;
    signature: Buffer;
  } {
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

    const payload = CWTPayload.convertToPayload(payloadSerialized);

    return { header, payload, signature };
  }

  static verify(
    token: Buffer,
    alg: Algorithm,
    validationOpts: CWTValidationOpts
  ) {
    return CWTVerify.verify(token, alg, validationOpts);
  }
}
