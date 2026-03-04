const { getPool } = require('./_db');
const { verifyToken, cors } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized. Please sign in first.' });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Invite token required' });

  const pool = getPool();
  try {
    // Look up the invite
    const invResult = await pool.query(
      `SELECT id, owner_id, client_id, client_name FROM client_invites
       WHERE id = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
      [token]
    );
    if (invResult.rows.length === 0) return res.status(404).json({ error: 'Invite not found or expired.' });
    const invite = invResult.rows[0];

    // Don't let owner join their own client
    if (invite.owner_id === decoded.userId) {
      return res.status(400).json({ error: 'You are already the owner of this client.' });
    }

    // Create access (upsert)
    await pool.query(
      `INSERT INTO client_access (owner_id, client_id, client_name, member_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (owner_id, client_id, member_id) DO NOTHING`,
      [invite.owner_id, invite.client_id, invite.client_name, decoded.userId]
    );

    res.status(200).json({
      success: true,
      clientName: invite.client_name,
      ownerId: invite.owner_id,
      clientId: invite.client_id
    });
  } catch (err) {
    console.error('Accept invite error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
};
