const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { randomUUID } = require('crypto');

const app = express();

// Body parsers - order matters
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  if (!req.body) req.body = {};
  next();
});

const PRIVATE_KEY = fs.readFileSync('./liferay-private.pem', 'utf8');
const CLIENT_ID = 'liferay-sso-client';
const ESIGNET_TOKEN_URL = 'http://host.docker.internal:8088/v1/esignet/oauth/v2/token';

app.post('/token', async (req, res) => {
  console.log('Content-Type:', req.headers['content-type']);
  console.log('Token request body:', req.body);
  
  try {
    const now = Math.floor(Date.now() / 1000);
    const clientAssertion = jwt.sign(
      {
        iss: CLIENT_ID,
        sub: CLIENT_ID,
        aud: ESIGNET_TOKEN_URL,
        jti: randomUUID(),
        iat: now,
        exp: now + 60
      },
      PRIVATE_KEY,
      { algorithm: 'RS256' }
    );

    const params = new URLSearchParams({
      grant_type: req.body.grant_type || 'authorization_code',
      code: req.body.code || '',
      redirect_uri: req.body.redirect_uri || '',
      client_id: CLIENT_ID,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: clientAssertion,
    });

    if (req.body.code_verifier) {
      params.append('code_verifier', req.body.code_verifier);
    }

    console.log('Forwarding to eSignet:', ESIGNET_TOKEN_URL);
    console.log('Params:', params.toString());

    const response = await axios.post(ESIGNET_TOKEN_URL, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    console.log('eSignet response:', response.data);
    res.json(response.data);
  } catch (err) {
    console.error('Proxy error:', err.response?.data || err.message);
    res.status(err.response?.status || 500).json(err.response?.data || { error: 'proxy_error' });
  }
});

app.listen(8089, '0.0.0.0', () => {
  console.log('✅ Token proxy running on port 8089');
});
