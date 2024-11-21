import { encode } from "cbor-x";
import { strictEqual } from "node:assert";
import { describe, it } from "node:test";
import { CWTPayload } from "../src/payload.js";

describe("Payload Check", () => {
  it("Unknown Payload Key", () => {
    strictEqual(
      CWTPayload.convertToPayload(encode(new Map([[-1000000, undefined]])))[
        -1000000
      ],
      undefined
    );
  });
});
