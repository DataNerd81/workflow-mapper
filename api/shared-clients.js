const { getPool } = require('./_db');
const { verifyToken, cors } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' });

  const pool = getPool();
  try {
    // Get all clients shared with this user
    const accessResult = await pool.query(
      `SELECT ca.owner_id, ca.client_id, ca.client_name, ca.role, u.email as owner_email
       FROM client_access ca JOIN users u ON ca.owner_id = u.id
       WHERE ca.member_id = $1`,
      [decoded.userId]
    );

    // For each shared client, fetch the actual client data from the owner's data
    const sharedClients = [];
    for (const row of accessResult.rows) {
      const ownerData = await pool.query('SELECT data FROM users WHERE id = $1', [row.owner_id]);
      if (ownerData.rows.length === 0) continue;
      const data = ownerData.rows[0].data || {};
      const client = (data.clients || []).find(c => c.id === row.client_id);
      if (client) {
        sharedClients.push({
          ...client,
          _shared: true,
          _ownerId: row.owner_id,
          _ownerEmail: row.owner_email,
          _role: row.role
        });
      }
    }

    res.status(200).json({ sharedClients });
  } catch (err) {
    console.error('Shared clients error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
};
