const { getPool } = require('./_db');
const { verifyToken, cors } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized. Please sign in again.' });

  const pool = getPool();

  if (req.method === 'GET') {
    try {
      const result = await pool.query('SELECT data FROM users WHERE id = $1', [decoded.userId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
      res.status(200).json(result.rows[0].data || { clients: [], activeClientId: null });
    } catch (err) {
      console.error('Load error:', err);
      res.status(500).json({ error: 'Failed to load data.' });
    }
  } else if (req.method === 'PUT') {
    try {
      const { clients, activeClientId } = req.body || {};
      const data = { clients: clients || [], activeClientId: activeClientId || null, updatedAt: new Date().toISOString() };
      await pool.query('UPDATE users SET data = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(data), decoded.userId]);
      res.status(200).json({ success: true });
    } catch (err) {
      console.error('Save error:', err);
      res.status(500).json({ error: 'Failed to save data.' });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
