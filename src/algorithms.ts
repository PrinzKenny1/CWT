//https://www.iana.org/assignments/cose/cose.xhtml under COSE Algorithms
export enum CWTAlgorithms {
  "HS256" = 5,
  "HS384" = 6,
  "HS512" = 7,
  "ES256" = -7,
  "ES384" = -35,
  "ES512" = -36,
  "PS256" = -37,
  "PS384" = -38,
  "PS512" = -39,
  "RS256" = -257,
  "RS384" = -258,
  "RS512" = -259,
  "EdDSA" = -8,
}

export namespace CWTAlgorithms {
  export function toName(alg: CWTAlgorithms): string {
    switch (alg) {
      case CWTAlgorithms.HS256:
        return "HS256";
      case CWTAlgorithms.HS384:
        return "HS384";
      case CWTAlgorithms.HS512:
        return "HS512";
      case CWTAlgorithms.ES256:
        return "ES256";
      case CWTAlgorithms.ES384:
        return "ES384";
      case CWTAlgorithms.ES512:
        return "ES512";
      case CWTAlgorithms.PS256:
        return "PS256";
      case CWTAlgorithms.PS384:
        return "PS384";
      case CWTAlgorithms.PS512:
        return "PS512";
      case CWTAlgorithms.RS256:
        return "RS256";
      case CWTAlgorithms.RS384:
        return "RS384";
      case CWTAlgorithms.RS512:
        return "RS512";
      case CWTAlgorithms.EdDSA:
        return "EdDSA";
      default:
        throw new Error(`This alg "${alg}" is not supported`);
    }
  }
}
