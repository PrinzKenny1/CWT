import { strictEqual, throws } from "node:assert";
import { describe, it } from "node:test";
import { CWTAlgorithms } from "../src/algorithms.js";

describe("Header Check", () => {
  it("should return the correct algorithm name", () => {
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.HS256), "HS256");
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.HS384), "HS384");
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.HS512), "HS512");
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.ES256), "ES256");
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.ES384), "ES384");
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.ES512), "ES512");
    strictEqual(CWTAlgorithms.toName(CWTAlgorithms.EdDSA), "EdDSA");
  });

  it("should throw an error for unsupported algorithms", () => {
    throws(
      () => CWTAlgorithms.toName("unsupported" as any),
      /This alg "unsupported" is not supported/
    );
    throws(
      () => CWTAlgorithms.toName(null as any),
      /This alg "null" is not supported/
    );
    throws(
      () => CWTAlgorithms.toName(undefined as any),
      /This alg "undefined" is not supported/
    );
  });
});
