const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { randomUUID } = require('crypto');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  if (!req.body) req.body = {};
  next();
});

const PRIVATE_KEY = fs.readFileSync('./liferay-private.pem', 'utf8');
const CLIENT_ID = 'liferay-sso-client';
const ESIGNET_TOKEN_URL = 'http://host.docker.internal:8088/v1/esignet/oauth/v2/token';
const ESIGNET_AUD = 'http://localhost:3000/v1/esignet/oauth/v2/token';

// Serve modified well-known so Liferay uses our proxy token endpoint
app.get('/.well-known/openid-configuration', async (req, res) => {
  const response = await axios.get('http://host.docker.internal:3000/.well-known/openid-configuration');
  const config = response.data;
  config.token_endpoint = 'http://host.docker.internal:8089/token';
  config.issuer = 'http://localhost:3000/v1/esignet';
  config.jwks_uri = 'http://host.docker.internal:3000/.well-known/jwks.json';  // ADD THIS
  config.userinfo_endpoint = 'http://host.docker.internal:8089/userinfo';  // ADD THIS
  res.json(config);
});

app.post('/token', async (req, res) => {
  console.log('Content-Type:', req.headers['content-type']);
  console.log('Token request body:', req.body);
  try {
    const now = Math.floor(Date.now() / 1000);
    const clientAssertion = jwt.sign(
      {
        iss: CLIENT_ID,
        sub: CLIENT_ID,
	aud: ESIGNET_AUD,        
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

app.get('/userinfo', async (req, res) => {
  try {
    const response = await axios.get('http://host.docker.internal:3000/v1/esignet/oidc/userinfo', {
      headers: { Authorization: req.headers.authorization }
    });
    const data = response.data;
    console.log('Userinfo raw response:', JSON.stringify(data));
    console.log('Userinfo type:', typeof data);
    if (typeof data === 'string') {
      const parts = data.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      console.log('Userinfo decoded payload:', JSON.stringify(payload));
     if (payload.name) {
  const nameParts = payload.name.split(' ');
  payload.given_name = nameParts[0];
  payload.family_name = nameParts.slice(1).join(' ') || nameParts[0];
} else {
  payload.given_name = payload.email ? payload.email.split('@')[0] : 'User';
  payload.family_name = 'eSignet';
}
res.json(payload);
    } else {
      console.log('Userinfo JSON data:', JSON.stringify(data));
      if (data.name) {
  const nameParts = data.name.split(' ');
  data.given_name = nameParts[0];
  data.family_name = nameParts.slice(1).join(' ') || nameParts[0];
} else {
  data.given_name = data.email ? data.email.split('@')[0] : 'User';
  data.family_name = 'eSignet';
}
res.json(data);
    }
  } catch (err) {
    console.error('Userinfo error:', err.response?.data || err.message);
    res.status(err.response?.status || 500).json(err.response?.data || { error: 'proxy_error' });
  }
});

app.listen(8089, '0.0.0.0', () => {
  console.log('✅ Token proxy running on port 8089');
});