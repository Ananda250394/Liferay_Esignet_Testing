const crypto = require('crypto');
const fs = require('fs');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

fs.writeFileSync('liferay-private.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }));
fs.writeFileSync('liferay-public.pem', publicKey.export({ type: 'spki', format: 'pem' }));

const jwk = publicKey.export({ format: 'jwk' });
const fullJwk = { ...jwk, use: 'sig', alg: 'RS256', kid: 'liferay-key-1' };

fs.writeFileSync('liferay-public.jwk.json', JSON.stringify(fullJwk, null, 2));

console.log('\n✅ Keys generated!\n');
console.log(JSON.stringify(fullJwk, null, 2));
