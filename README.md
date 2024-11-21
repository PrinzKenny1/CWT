# CWT (Concise Binary Object Representation Web Token)

An implementation approach for the [CBOR Web Token](https://datatracker.ietf.org/doc/html/rfc8392). The CWT aims to be efficient and simple. It can be used in different applications like IoT or Web Authentification.

## Supported Algorithms

| Algorithm | CWT Alg Key Id | More detailed                   |
| --------- | -------------- | ------------------------------- |
| EdDSA     | -8             | EdDSA                           |
| ES256     | -7             | ECDSA w/ SHA-256                |
| ES384     | -35            | ECDSA w/ SHA-384                |
| ES512     | -36            | ECDSA w/ SHA-512                |
| H256      | 5              | HMAC w/ SHA-256                 |
| H384      | 6              | HMAC w/ SHA-384                 |
| H512      | 7              | HMAC w/ SHA-512                 |
| PS256     | -37            | RSASSA-PSS w/ SHA-256           |
| PS384     | -38            | RSASSA-PSS w/ SHA-384           |
| PS512     | -39            | RSASSA-PSS w/ SHA-512           |
| RS256     | -257           | RSASSA-PKCS1-v1_5 using SHA-256 |
| RS384     | -258           | RSASSA-PKCS1-v1_5 using SHA-384 |
| RS512     | -259           | RSASSA-PKCS1-v1_5 using SHA-512 |

## Examples

### CWT Signing with EdDSA

```TS
const privateKey = "./keys/ed-25519-private.key";
const publicKey = "./keys/ed-25519-public.key";

const eddsaAlgorithm = new EdDSA(privateKey, publicKey); // Public key could be omitted, if only signing/decoding is required

const tokenBuffer = CWT.sign(
  { // Header
    protected: {
      alg: CWTAlgorithms.EdDSA,
    },
    unprotected: {},
  },
  { // Payload
    exp: Math.floor(Date.now() / 1000) + 3600, // Token expires in 1 hour
  },
  eddsaAlgorithm
);

const token = tokenBuffer.toString("base64"); //If you need the token as string
```

NOTE: All time related settings have to be in seconds

#### Header

| Section     | Key               | Value              |
| ----------- | ----------------- | ------------------ |
| Protected   | alg               | Enum CWTAlgorithms |
| Protected   | string (optional) | some value         |
| Unprotected | string (optional) | some value         |

The difference between protected and unprotected header lies in the signature. The protected header isn't manipulatable after creation because it's protected by the signature. The unprotected header on the other hand is mutable, which might be of use in especially IoT related areas.

#### Payload

| Key    | Value                 | Description                                          |
| ------ | --------------------- | ---------------------------------------------------- |
| iss    | string (optional)     | The issuer of the token                              |
| sub    | string (optional)     | The subject of the token                             |
| aud    | string[] (optional)   | The audience of the token                            |
| exp    | number (optional)     | The expiration date in seconds                       |
| nbf    | number (optional)     | The date in seconds at which the token becomes valid |
| iat    | number (optional)     | The date in seconds the token got issued             |
| cti    | string (optional)     | The token id                                         |
| string | some value (optional) | Some custom value                                    |

The payload is also protected by the signature and thus not mutable after creation.

### CWT Decoding

This decodes the token without verifying it's integrity

```TS
const token = ...; //If you get the token as string

// const tokenBuffer = ...; //If you get the buffer directly
const tokenBuffer = new Buffer(token, "base64");

const {header, payload, signature} = CWT.decode(tokenBuffer);
```

### CWT Verify

This decodes the token with verifying it's integrity (correct settings for the validation options have to be set)

```TS
const privateKey = "./keys/ed-25519-private.key";
const publicKey = "./keys/ed-25519-public.key";

const eddsaAlgorithm = new EdDSA(privateKey, publicKey); // Private key could be omitted if only verifying is required

const token = ...; //If you get the token as string

// const tokenBuffer = ...; //If you get the buffer directly
const tokenBuffer = new Buffer(token, "base64");

const { header, payload, signature } = CWT.verify(tokenBuffer, eddsaAlgorithm, {
  expNeeded: true,
});
```

#### Verify Options

| Key                 | Value              | Description                                                                     |
| ------------------- | ------------------ | ------------------------------------------------------------------------------- |
| iss                 | string (optional)  | The expected issuer of the token                                                |
| aud                 | string (optional)  | The audience to check if the token is for them                                  |
| clockSkewSeconds    | number (optional)  | The clock skew in seconds                                                       |
| expNeeded           | boolean (optional) | If the token needs to have an expiration date                                   |
| subNeeded           | boolean (optional) | If the token needs to have a subject                                            |
| nbfNeeded           | boolean (optional) | If the token needs to have a "not valid before" date                            |
| iatNeeded           | boolean (optional) | If the token needs to have an "issued at" date                                  |
| ctiNeeded           | boolean (optional) | If the token needs to have a token id                                           |
| overrideCurrentDate | Date (optional)    | Override the current date (e.g. if you use the token across multiple timezones) |
