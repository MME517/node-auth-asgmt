const cryptoJwt = require('crypto');

function base64urlEncode(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const body = { ...payload, exp };

  const encodedHeader = base64urlEncode(header);
  const encodedPayload = base64urlEncode(body);
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const sig = cryptoJwt
    .createHmac('sha256', secret)
    .update(unsignedToken)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${encodedHeader}.${encodedPayload}.${sig}`;
}

function verifyJWT(token, secret) {
  const [header, payload, sig] = token.split('.');
  const data = `${header}.${payload}`;

  const expected = cryptoJwt
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (sig !== expected) {
    throw new Error('Invalid signature.');
  }

  const decoded = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));

  if (decoded.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('JWT has expired.');
  }

  return decoded;
}

module.exports = {
  signJWT,
  verifyJWT,
};
