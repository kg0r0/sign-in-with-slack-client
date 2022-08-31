import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import { Issuer, TokenSet, generators } from 'openid-client';
import * as https from 'https';
import * as fs from 'fs';
const config: Config = require('../config.json');

interface Config {
  client_id: string;
  client_secret: string;
  redirect_uri: string;
}

declare module 'express-session' {
  export interface SessionData {
    tokenSet: TokenSet;
    state: string;
    nonce: string;
    originalUrl: string;
    isRedirected: boolean;
    isLoggedIn: boolean;
  }
}

const app: express.Express = express();
const privateKey = fs.readFileSync('cert/server.key', 'utf8');
const certificate = fs.readFileSync('cert/server.crt', 'utf8');
const httpsServer = https.createServer({ key: privateKey, cert: certificate }, app);
const PORT = 3000;

app.use(session({
  name: 'SESSION',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: false,
  saveUninitialized: true
}))

/**
 * routes
 */
app.get('/*', async (req: express.Request, res: express.Response) => {
  if (req.session.isLoggedIn && req.session.isRedirected) {
    console.log('received and validated tokens %j', req.session.tokenSet);
    return res.send('OK');
  }
  const issuer = await Issuer.discover('https://slack.com/.well-known/openid-configuration')
  const client = new issuer.Client({
    client_id: config.client_id,
    client_secret: config.client_secret,
    redirect_uris: [config.redirect_uri],
    response_types: ['code']
  })
  if (req.session.isRedirected) {
    const state = req.session.state;
    const nonce = req.session.nonce;
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
      config.redirect_uri,
      params,
      {
        state,
        nonce,
      });
    req.session.tokenSet = tokenSet;
    req.session.isLoggedIn = true;
    return res.redirect(req.session.originalUrl!);
  }
  const state = generators.state();
  req.session.state = state;
  const nonce = generators.nonce();
  req.session.nonce = nonce;

  const url = client.authorizationUrl({
    scope: 'openid',
    state,
    nonce,
  })
  req.session.originalUrl = req.originalUrl;
  req.session.isRedirected = true;
  return res.redirect(url);
});

httpsServer.listen(PORT);