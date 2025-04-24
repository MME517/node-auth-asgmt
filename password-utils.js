const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hashed = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return `${salt}:${hashed.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [salt, storedHash] = stored.split(':');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return hash === storedHash;
}

module.exports = {
  hashPassword,
  verifyPassword,
};
