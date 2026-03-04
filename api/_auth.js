const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;

const ROLES = {
  SYSADMIN: 'sysadmin',
  ADMIN: 'admin',
  USER: 'user'
};

function signToken(userId, email, role) {
  return jwt.sign({ userId, email, role: role || ROLES.USER }, SECRET, { expiresIn: '7d' });
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

function requireRole(...allowedRoles) {
  return function(req, res, next) {
    const decoded = verifyToken(req);
    if (!decoded) return res.status(401).json({ error: 'Unauthorized' });
    if (!allowedRoles.includes(decoded.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    req.user = decoded;
    return next ? next() : decoded;
  };
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

module.exports = { signToken, verifyToken, cors, requireRole, ROLES };
