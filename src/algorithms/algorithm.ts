import { CWTAlgorithms } from "../algorithms.js";

export interface Algorithm {
  sign(message: Buffer): Buffer;
  verify(message: Buffer, signature: Buffer): boolean;

  getAlgorithm(): CWTAlgorithms;
}
