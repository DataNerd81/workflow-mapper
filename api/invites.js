const { getPool } = require('./_db');
const { verifyToken, cors, ROLES } = require('./_auth');

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
        `SELECT i.id, i.client_name, i.client_id, i.expires_at, i.invite_role, i.org_id,
                u.email as owner_email
         FROM client_invites i JOIN users u ON i.owner_id = u.id
         WHERE i.id = $1 AND (i.expires_at IS NULL OR i.expires_at > NOW())`,
        [token]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Invite not found or expired.' });
      const inv = result.rows[0];
      res.status(200).json({
        clientName: inv.client_name,
        ownerEmail: inv.owner_email,
        token: inv.id,
        inviteRole: inv.invite_role || 'user',
        orgId: inv.org_id
      });
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

    const { clientId, inviteRole } = req.body || {};
    if (!clientId) return res.status(400).json({ error: 'clientId required' });

    // Determine what role the inviter can assign
    const targetRole = inviteRole || 'user';

    // RBAC: Only sysadmin can invite admins, only sysadmin/admin can invite users
    if (targetRole === 'admin' && decoded.role !== ROLES.SYSADMIN) {
      return res.status(403).json({ error: 'Only system administrators can invite admins.' });
    }
    if (targetRole === 'user' && decoded.role !== ROLES.SYSADMIN && decoded.role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'Only admins can invite users to an organization.' });
    }

    try {
      // Get client name from user's data
      const userResult = await pool.query('SELECT data FROM users WHERE id = $1', [decoded.userId]);
      if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
      const userData = userResult.rows[0].data || {};
      const client = (userData.clients || []).find(c => c.id === clientId);
      if (!client) return res.status(404).json({ error: 'Client not found' });

      // If admin is inviting a user, find their org
      let orgId = null;
      if (decoded.role === ROLES.ADMIN) {
        const orgResult = await pool.query(
          'SELECT id FROM organizations WHERE admin_id = $1 LIMIT 1',
          [decoded.userId]
        );
        if (orgResult.rows.length > 0) orgId = orgResult.rows[0].id;
      }

      const token = require('crypto').randomUUID();
      await pool.query(
        `INSERT INTO client_invites (id, owner_id, client_id, client_name, invite_role, org_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [token, decoded.userId, clientId, client.name, targetRole, orgId]
      );

      res.status(201).json({ token, clientName: client.name, inviteRole: targetRole });
    } catch (err) {
      console.error('Create invite error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
    return;
  }

  res.status(405).json({ error: 'Method not allowed' });
};
