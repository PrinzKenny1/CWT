import * as crypto from "crypto";
import * as fs from "fs";
import { CWTAlgorithms } from "../algorithms.js";
import { Algorithm } from "./algorithm.js";

export class PS512 implements Algorithm {
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly passphrase?: string;

  constructor(
    privateKeyOrPath: string,
    publicKeyOrPath: string,
    passphrase?: string
  ) {
    this.privateKey = privateKeyOrPath;
    this.publicKey = publicKeyOrPath;

    if (fs.existsSync(privateKeyOrPath)) {
      this.privateKey = fs.readFileSync(privateKeyOrPath, "utf-8");
    }

    if (fs.existsSync(publicKeyOrPath)) {
      this.publicKey = fs.readFileSync(publicKeyOrPath, "utf-8");
    }

    this.passphrase = passphrase;
  }

  sign(message: Buffer): Buffer {
    return crypto.sign("RSA-SHA512", message, {
      key: this.privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      passphrase: this.passphrase,
    });
  }

  verify(message: Buffer, signature: Buffer): boolean {
    return crypto.verify(
      "RSA-SHA512",
      message,
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      signature
    );
  }

  getAlgorithm() {
    return CWTAlgorithms.PS512;
  }

  static generateKeyPair(): { publicKey: string; privateKey: string } {
    return crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });
  }
}
