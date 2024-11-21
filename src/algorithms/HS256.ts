import * as crypto from "crypto";
import * as fs from "fs";
import { CWTAlgorithms } from "../algorithms.js";
import { Algorithm } from "./algorithm.js";

export class HS256 implements Algorithm {
  private readonly secretOrPath: string;

  constructor(secretOrPath: string) {
    this.secretOrPath = secretOrPath;

    if (fs.existsSync(secretOrPath)) {
      this.secretOrPath = fs.readFileSync(secretOrPath, "utf-8");
    }
  }

  sign(message: Buffer): Buffer {
    return crypto
      .createHmac("SHA256", this.secretOrPath)
      .update(message)
      .digest();
  }

  verify(message: Buffer, signature: Buffer): boolean {
    return crypto.timingSafeEqual(this.sign(message), signature);
  }

  getAlgorithm() {
    return CWTAlgorithms.HS256;
  }
}
