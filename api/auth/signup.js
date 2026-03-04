const bcrypt = require('bcryptjs');
const { getPool } = require('../_db');
const { signToken, cors } = require('../_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const pool = getPool();
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, role, data) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
      [email.toLowerCase(), hash, 'user', JSON.stringify({ clients: [], activeClientId: null })]
    );

    const user = result.rows[0];
    const token = signToken(user.id, user.email, user.role);
    res.status(201).json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
