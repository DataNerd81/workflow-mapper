const { getPool } = require('./_db');
const { verifyToken, cors } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const pool = getPool();

  // GET /api/invites?token=xxx — public, get invite info
  if (req.method === 'GET') {
    const token = req.query.token;
    if (!token) return res.status(400).json({ error: 'Token required' });

    try {
      const result = await pool.query(
        `SELECT i.id, i.client_name, i.client_id, i.expires_at, u.email as owner_email
         FROM client_invites i JOIN users u ON i.owner_id = u.id
         WHERE i.id = $1 AND (i.expires_at IS NULL OR i.expires_at > NOW())`,
        [token]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Invite not found or expired.' });
      const inv = result.rows[0];
      res.status(200).json({ clientName: inv.client_name, ownerEmail: inv.owner_email, token: inv.id });
    } catch (err) {
      console.error('Invite lookup error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
    return;
  }

  // POST /api/invites — authenticated, create invite
  if (req.method === 'POST') {
    const decoded = verifyToken(req);
    if (!decoded) return res.status(401).json({ error: 'Unauthorized' });

    const { clientId } = req.body || {};
    if (!clientId) return res.status(400).json({ error: 'clientId required' });

    try {
      // Get client name from user's data
      const userResult = await pool.query('SELECT data FROM users WHERE id = $1', [decoded.userId]);
      if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
      const userData = userResult.rows[0].data || {};
      const client = (userData.clients || []).find(c => c.id === clientId);
      if (!client) return res.status(404).json({ error: 'Client not found' });

      const token = require('crypto').randomUUID();
      await pool.query(
        `INSERT INTO client_invites (id, owner_id, client_id, client_name)
         VALUES ($1, $2, $3, $4)`,
        [token, decoded.userId, clientId, client.name]
      );

      res.status(201).json({ token, clientName: client.name });
    } catch (err) {
      console.error('Create invite error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
    return;
  }

  res.status(405).json({ error: 'Method not allowed' });
};
