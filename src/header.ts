import { decode, encode } from "cbor-x";
import { CWTAlgorithms } from "./algorithms.js";

export type CWTHeader = {
  protected: CWTHeaderProtected;
  unprotected: CWTHeaderUnprotected;
};

type CWTHeaderProtected = {
  alg: CWTAlgorithms;
  [x: string]: unknown;
};

type CWTHeaderUnprotected = {
  [x: string]: unknown;
};

export namespace CWTHeader {
  export function convertToMap(
    header: CWTHeader
  ): [Buffer, Map<string | number, unknown>] {
    const protectedHeader = objectToMap(header.protected);
    const unprotectedHeader = objectToMap(header.unprotected);

    return [encode(protectedHeader), unprotectedHeader];
  }

  export function convertToHeader(
    protectedHeaderSerialized: Buffer,
    unprotectedHeader: Map<string | number, unknown>
  ): CWTHeader {
    let protectedObj = mapToObject(
      decode(protectedHeaderSerialized)
    ) as CWTHeaderProtected;
    let unprotectedObj = mapToObject(unprotectedHeader) as CWTHeaderUnprotected;

    return {
      protected: protectedObj,
      unprotected: unprotectedObj,
    };
  }

  function mapToObject(map: Map<string | number, unknown>) {
    let obj = {};

    for (const [key, value] of map.entries()) {
      let identifier;

      if ("number" === typeof key) {
        identifier = idToKey(key);
      } else {
        identifier = key;
      }

      if (undefined === identifier) {
        identifier = key;
      }

      obj = {
        [identifier]: value,
        ...obj,
      };
    }

    return obj;
  }

  function objectToMap(obj: Object) {
    const map = new Map<string | number, unknown>();

    for (const [key, value] of Object.entries(obj)) {
      let identifier: string | number | undefined = keyToId(key);

      if (undefined === identifier) {
        identifier = key;
      }

      map.set(identifier, value);
    }

    return map;
  }

  function keyToId(key: string) {
    switch (key) {
      case "alg":
        return 1;
      default:
        return undefined;
    }
  }

  function idToKey(id: number) {
    switch (id) {
      case 1:
        return "alg";
      default:
        return undefined;
    }
  }
}
