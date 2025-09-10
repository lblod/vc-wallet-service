import bodyParser from 'body-parser';
import { ErrorRequestHandler } from 'express';
import { app } from 'mu';
import {
  createDidWebCryptoLD,
  createDidWebGaiaX,
  createDidWebJWK,
  generateKeyDid,
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
    service: 'vc-wallet-service',
    status: 'ok',
  });
});

router.post('/generate-did-web', async function (req, res) {
  let result;
  if (req.body.mode === 'JWK') {
    result = await createDidWebJWK(req.body.did);
  } else if (req.body.mode === 'Gaia-x') {
    result = await createDidWebGaiaX();
  } else {
    result = await createDidWebCryptoLD(req.body.did);
  }
  res.send(result);
});

router.post('/generate-did-key', async function (req, res) {
  const result = await generateKeyDid();
  res.send(result);
});

const errorHandler: ErrorRequestHandler = function (err, _req, res, _next) {
  // custom error handler to have a default 500 error code instead of 400 as in the template
  res.status(err.status || 500);
  res.json({
    errors: [{ title: err.message, description: err.description?.join('\n') }],
  });
};

app.use(errorHandler);
