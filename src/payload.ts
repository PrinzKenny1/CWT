import { decode, encode } from "cbor-x";

export type CWTPayload = {
  iss?: string;
  sub?: string;
  aud?: string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  cti?: string;
  [x: string]: unknown;
};

export namespace CWTPayload {
  export function convertToMap(payload: CWTPayload): Buffer {
    return encode(objectToMap(payload));
  }

  export function convertToPayload(buffer: Buffer): CWTPayload {
    return mapToObject(decode(buffer));
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
      case "iss":
        return 1;
      case "sub":
        return 2;
      case "aud":
        return 3;
      case "exp":
        return 4;
      case "nbf":
        return 5;
      case "iat":
        return 6;
      case "cti":
        return 7;
      default:
        return undefined;
    }
  }

  function idToKey(id: number) {
    switch (id) {
      case 1:
        return "iss";
      case 2:
        return "sub";
      case 3:
        return "aud";
      case 4:
        return "exp";
      case 5:
        return "nbf";
      case 6:
        return "iat";
      case 7:
        return "cti";
      default:
        return undefined;
    }
  }
}
