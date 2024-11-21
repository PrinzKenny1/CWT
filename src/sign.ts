import { encode } from "cbor-x";

import { CWTAlgorithms } from "./algorithms.js";
import { Algorithm } from "./algorithms/algorithm.js";

export namespace CWTSign {
  export function createSignObject(
    protectedHeaderSerialized: Buffer,
    payloadSerialized: Buffer,
  ) {
    return encode([
      protectedHeaderSerialized,
      new Uint8Array(),
      payloadSerialized,
    ]);
  }

  export function sign(
    message: Buffer,
    headerAlg: CWTAlgorithms,
    alg: Algorithm
  ) {
    if (headerAlg !== alg.getAlgorithm()) {
      throw new Error(
        `Header algorithm "${CWTAlgorithms.toName(
          headerAlg
        )}" doesn't match input algorithm "${CWTAlgorithms.toName(
          alg.getAlgorithm()
        )}".`
      );
    }

    return alg.sign(message);
  }
}
