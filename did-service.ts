import * as jose from 'jose';
import { createDidDocument } from '@gaia-x/did-web-generator';
import {
  driver,
  didUrlToHttpsUrl,
  httpsUrlToDidUrl,
} from '@digitalbazaar/did-method-web';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { getResolver, util } from '@cef-ebsi/key-did-resolver';
import { JsonWebKey, Resolver } from 'did-resolver';

export async function generateJoseKey(algorithm) {
  const { publicKey, privateKey } = await jose.generateKeyPair(algorithm, {
    extractable: true,
  });

  const publicPem = await jose.exportSPKI(publicKey);
  console.log(publicPem);
  const privatePem = await jose.exportPKCS8(privateKey);
  console.log(privatePem);
  return { publicKey, privateKey, privatePem, publicPem };
}

export async function createDidWebGaiaX() {
  /**
   * Warning because of the use of x509 certificate, which we can't easily generate,
   * there can only be one gaia-x web did per hostname and you have to provide this service with the public key
   */
  const publicKey = process.env.X509_PUBLIC_KEY || '';
  const hostname = process.env.DOMAIN_NAME || 'localhost';
  const result = await createDidDocument(
    `https://${hostname}`,
    'public_cert.pem',
    publicKey,
  );
  return { did: result.id, didDocument: result };
}

const didWebDriver = driver();
didWebDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from,
});
didWebDriver.use({
  multibaseMultikeyHeader: 'z6LS',
  fromMultibase: X25519KeyAgreementKey2020.from,
});
export async function createDidWebCryptoLD(did) {
  const verificationKey = await Ed25519VerificationKey2020.generate();
  const agreementKey = await X25519KeyAgreementKey2020.generate();
  const didDocument = await didWebDriver.fromKeyPair({
    url: did.startsWith('did:web:') ? didUrlToHttpsUrl(did).fullUrl : did,
    verificationKeyPair: verificationKey,
    keyAgreementKeyPair: agreementKey,
  });

  console.log(JSON.stringify(didDocument, null, 2));

  return {
    did,
    didDocument: didDocument.didDocument,
    verificationKey: verificationKey.export({
      publicKey: true,
      privateKey: true,
    }),
    agreementKey: agreementKey.export({ publicKey: true, privateKey: true }),
  };
}

export async function getJoseKeysAndJWK(algorithm) {
  const { publicKey, privateKey, privatePem, publicPem } =
    await generateJoseKey(algorithm);
  const publicJwk = await jose.exportJWK(publicKey);
  publicJwk.alg = algorithm;
  console.log(publicJwk.alg);
  console.log(publicJwk);
  return { publicKey, privateKey, privatePem, publicPem, publicJwk };
}

export async function generateKeyDid() {
  const algorithm = 'EdDSA';
  const keyResolver = getResolver();
  const { privateKey, privatePem, publicPem, publicJwk } =
    await getJoseKeysAndJWK(algorithm);

  // for testing
  const jws = await new jose.CompactSign(
    new TextEncoder().encode(
      'It’s a dangerous business, Frodo, going out your door.',
    ),
  )
    .setProtectedHeader({ alg: algorithm })
    .sign(privateKey);

  console.log(jws);

  const didResolver = new Resolver(keyResolver);
  const did = util.createDid(publicJwk as unknown as JsonWebKey);
  const resolved = await didResolver.resolve(did);
  console.log(`resolved did: ${JSON.stringify(resolved)}`);
  const importedFromDid = await jose.importJWK(
    resolved.didDocument!.verificationMethod![0].publicKeyJwk as jose.JWK,
    algorithm,
  );
  const { payload, protectedHeader } = await jose.compactVerify(
    jws,
    importedFromDid,
  );
  console.log(protectedHeader);
  console.log(new TextDecoder().decode(payload));

  console.log('valid: ', did);
  return {
    did,
    didDocument: resolved.didDocument,
    publicKey: publicPem,
    privateKey: privatePem,
  };
}

export async function createDidWebJWK(did) {
  const algorithm = 'EdDSA';
  if (!did.startsWith('did:web:') && did.startsWith('https://')) {
    did = httpsUrlToDidUrl(did).did;
  } else if (!did.startsWith('did:web:')) {
    throw new Error('DID must start with did:web:');
  }
  const { privatePem, publicPem, publicJwk } =
    await getJoseKeysAndJWK(algorithm);
  // as per FIWARE https://github.com/FIWARE/tutorials.Verifiable-Credentials/tree/NGSI-LD
  const keyId = `${did}#owner`;
  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
  return {
    did,
    didDocument,
    publicKey: publicPem,
    privateKey: privatePem,
  };
}

export async function getDidWeb(did: string) {
  const forceJsonContent = async (_request, _options, response) => {
    const modifiedResponse = new Response(response.body, response);
    modifiedResponse.headers.set('Content-Type', 'application/json');
    return modifiedResponse;
  };
  const didDocument = await didWebDriver.get({
    did,
    fetchOptions: {
      hooks: {
        afterResponse: [forceJsonContent],
      },
    },
  });
  return didDocument;
}

export async function getAuthenticationPksFromDid(didDocument) {
  const didId = didDocument.id;
  const auth = didDocument.authentication;
  const verificationMap = {};
  (didDocument.verificationMethod || []).forEach((verification) => {
    verificationMap[verification.id] = verification;
  });

  const authenticationMethodes = auth.map((a) => {
    if (typeof a === 'string') {
      return verificationMap[a];
    } else {
      return a;
    }
  });

  const pks = await Promise.all(
    authenticationMethodes.map(async (method) => {
      if (method.controller != didId) {
        // ignore, not the owner's did
        return null;
      }
      if (method.type === 'JsonWebKey2020' && method.publicKeyJwk) {
        return jose.importJWK(method.publicKeyJwk as unknown as jose.JWK);
      }
      if (
        method.type === 'Ed25519VerificationKey2020' &&
        method.publicKeyMultibase
      ) {
        const key = Ed25519VerificationKey2020.from(method.publicKeyMultibase);
        const jsonWebKey = await (await key).toJwk({ publicKey: true });
        return jose.importJWK(jsonWebKey);
      }

      return null;
    }),
  );
  return pks.filter((pk) => pk !== null);
}

export async function joseSign(
  plaintext: string,
  privateKey: string,
  alg: string,
) {
  const pk = await jose.importPKCS8(privateKey, alg);
  const jws = await new jose.CompactSign(new TextEncoder().encode(plaintext))
    .setProtectedHeader({ alg })
    .sign(pk);
  return jws;
}

export async function joseVerify(jws: string, pk: jose.CryptoKey) {
  const { payload, protectedHeader } = await jose.compactVerify(jws, pk);
  return { payload: new TextDecoder().decode(payload), protectedHeader };
}
