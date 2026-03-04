const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;

function signToken(userId, email) {
  return jwt.sign({ userId, email }, SECRET, { expiresIn: '7d' });
}

function verifyToken(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  try {
    return jwt.verify(header.slice(7), SECRET);
  } catch {
    return null;
  }
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

module.exports = { signToken, verifyToken, cors };
