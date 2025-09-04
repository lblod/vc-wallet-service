import bodyParser from 'body-parser';
import { ErrorRequestHandler } from 'express';
import { app } from 'mu';
import {
  createDidWebCryptoLD,
  createDidWebGaiaX,
  createDidWebJWT,
  joseSign,
  generateKeyDid,
  getDidWeb,
  getAuthenticationPksFromDid,
} from './did-service';

import Router from 'express-promise-router';

const router = Router();
app.use(
  bodyParser.json({
    limit: '500mb',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type: function (req: any) {
      return /^application\/json/.test(req.get('content-type') as string);
    },
  }),
);

app.use(router);
router.get('/status', function (req, res) {
  res.send({
    service: 'vc-issuer-service',
    status: 'ok',
  });
});

router.post('/generate-web-did', async function (req, res) {
  let result;
  if (req.body.mode === 'JWT') {
    result = await createDidWebJWT(req.body.did);
  } else if (req.body.mode === 'Gaia-x') {
    /**
     * Warning because of the use of x509 certificate, which we can't easily generate,
     * there can only be one gaia-x web did per hostname and you have to provide this service with the public key
     */
    const publicKey = process.env.X509_PUBLIC_KEY;
    result = await createDidWebGaiaX(publicKey);
  } else {
    result = await createDidWebCryptoLD(req.body.did);
  }
  res.send(result);
});

router.post('/generate-key-did', async function (req, res) {
  const result = await generateKeyDid();
  res.send(result);
});

router.post('/check-did-signature', async function (req, res) {
  const didDocument = await getDidWeb(req.body.did);
  const publicKeys = getAuthenticationPksFromDid(didDocument);
  if (publicKeys.length === 0) {
    throw new Error('No authentication public keys found in DID document');
  }
  // check each key in the list
  // eslint-disable-next-line no-restricted-syntax
  for (const publicKey of publicKeys) {
    try {
      const verified = await joseSign(
        req.body.text,
        publicKey,
        req.body.alg || 'EdDSA',
        true,
      );
      if (verified) {
        return res.send({ didDocument, verified: true });
      }
    } catch (e) {
      // try next key
    }
  }

  const signature = req.body.signature;
  // verify signature
  res.send({ didDocument });
});

// only for testing!
router.post('/encrypt-text', async function (req, res) {
  const result = await joseSign(
    req.body.text,
    req.body.privateKey,
    req.body.alg || 'EdDSA',
  );
  res.send({ result });
});

const errorHandler: ErrorRequestHandler = function (err, _req, res, _next) {
  // custom error handler to have a default 500 error code instead of 400 as in the template
  res.status(err.status || 500);
  res.json({
    errors: [{ title: err.message, description: err.description?.join('\n') }],
  });
};

app.use(errorHandler);
