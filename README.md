# VC Wallet service

> [!WARNING]
> This service is currently under development and cannot be used in a production context yet

## Generating DIDs did:web

While being developed, this service has the ability to generate DIDs of different types. This section lists the different supported types.

### did:web

`did:web`s can be generated using a `POST` to the `/generate-did-web` endpoint with a body like this:

```json
{
  "did": "https://example.com/dids/johndoe",
  "mode": "CryptoLD" // "Gaia-x" or "JWK" or default/anything else "CryptoLD"
}
```

The value of `did` in the body can be either `did` formatted, or can be the url that corresponds to it. In this case, an example url that hosts the key under `https://example.com/dids/johndoe/did.json`. Using this url is equivalent to its did form `did:web:example:com:dids:johndoe`. an url without paths will look for the did under `.well-known/did.json`, e.g. `did:web:johndoe:example` will look for `https://johndoe.example/.well-known/did.json`.

The value of `mode` can be

- `CryptoLD` (default), in which case you will receive a `did:web` with an Ed25519 verification key and a X25519 agreement key.
- `JWK`, in which case you will receive a `did:web` with a `jose`-generated EdSDSA key in jwk format
- `Gaia-x`, in which case you will receive a `did:web` with the X509 public key that you specified in the `X509_PUBLIC_KEY` environment variable as a JWK public key

`CryptoLD` is the default and recommended value.

The response will be a json object with the following format:

```json
{
  "did": "did:web:the:did:you:requested",
  "didDocument": {
    // your new did:web document including your chosen verificationMethod
  },
  "publicKey": "your public key", // in case of JWK
  "privateKey": "your private key" // in case of JWK
  "verificationKey": { // in case of CryptoLD
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "your public key",
    "privateKeyMultibase": "your private key",
  },
  "agreementKey": { // in case of CryptoLD
    "type": "X25519KeyAgreementKey2020",
    "publicKeyMultibase": "your public key",
    "privateKeyMultibase": "your private key",
  }
  // note that there will be no private or public key returned in case of gaia-x as we only have the public key in that case
}
```

This service needs a public x509 certificate to work properly. You can generate this (and its corresponding private key) using `openssl req -new -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out public_cert.pem -keyout private_cert.pem `

### did:key

`did:key`s can be generated using a `POST` to the `/generate-did-key` endpoint without any body.

The result will be a document of the format:

```json
{
  "did": "did:key:yourdidkey",
  "didDocument": {
    // your new resolved did:key document
  },
  "publicKey": "your public key",
  "privateKey": "your private key"
}
```

The verification method will be a `jose` generated Ed25519 JWK.

## Exposing did:webs

As we're still very much in a development stage, we don't have a server to host the `did:web` yet, this is also why we're exporting them using these endpoints for now. However, it is fairly straight forward to pick e.g. a running ember frontend in the lblod ecosystem and place the keys in a mounted folder like so:

```yaml
frontend:
  volumes:
    - ./decide-keys:/data/assets/decide-keys
```

and then place your key called `did:web:your.application.domain:assets:decide-keys:johndoe` in `./decide-keys/johndoe/did.json`. The frontend will then happily host your `did:web` document. Be sure to only host the `didDocument` returned by the server and to keep your private key secure.
