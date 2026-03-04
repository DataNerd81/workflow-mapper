const { getPool } = require('./_db');
const { verifyToken, cors } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' });

  const pool = getPool();
  const ownerId = req.query.ownerId || (req.body && req.body.ownerId);
  const clientId = req.query.clientId || (req.body && req.body.clientId);

  if (!ownerId || !clientId) return res.status(400).json({ error: 'ownerId and clientId required' });

  // Verify the user has access
  const accessCheck = await pool.query(
    `SELECT role FROM client_access WHERE owner_id = $1 AND client_id = $2 AND member_id = $3`,
    [ownerId, clientId, decoded.userId]
  );
  if (accessCheck.rows.length === 0) return res.status(403).json({ error: 'Access denied' });

  if (req.method === 'GET') {
    try {
      const result = await pool.query('SELECT data FROM users WHERE id = $1', [ownerId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Owner not found' });
      const data = result.rows[0].data || {};
      const client = (data.clients || []).find(c => c.id === clientId);
      if (!client) return res.status(404).json({ error: 'Client not found' });
      res.status(200).json(client);
    } catch (err) {
      console.error('Shared data load error:', err);
      res.status(500).json({ error: 'Failed to load data.' });
    }
  } else if (req.method === 'PUT') {
    const role = accessCheck.rows[0].role;
    if (role !== 'editor') return res.status(403).json({ error: 'Read-only access' });

    try {
      const { workflows } = req.body || {};
      if (!workflows) return res.status(400).json({ error: 'workflows required' });

      // Update the owner's data for this specific client
      const result = await pool.query('SELECT data FROM users WHERE id = $1', [ownerId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Owner not found' });
      const data = result.rows[0].data || {};
      const clients = data.clients || [];
      const idx = clients.findIndex(c => c.id === clientId);
      if (idx === -1) return res.status(404).json({ error: 'Client not found' });

      clients[idx].workflows = workflows;
      data.clients = clients;
      data.updatedAt = new Date().toISOString();

      await pool.query('UPDATE users SET data = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(data), ownerId]);
      res.status(200).json({ success: true });
    } catch (err) {
      console.error('Shared data save error:', err);
      res.status(500).json({ error: 'Failed to save data.' });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
