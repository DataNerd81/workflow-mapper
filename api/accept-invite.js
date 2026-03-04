const { getPool } = require('./_db');
const { verifyToken, signToken, cors } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized. Please sign in first.' });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Invite token required' });

  const pool = getPool();
  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    // Look up the invite
    const invResult = await dbClient.query(
      `SELECT id, owner_id, client_id, client_name, invite_role, org_id FROM client_invites
       WHERE id = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
      [token]
    );
    if (invResult.rows.length === 0) return res.status(404).json({ error: 'Invite not found or expired.' });
    const invite = invResult.rows[0];
    const inviteRole = invite.invite_role || 'user';

    // Don't let owner join their own client
    if (invite.owner_id === decoded.userId) {
      return res.status(400).json({ error: 'You are already the owner of this client.' });
    }

    // If being invited as admin, upgrade user role and create org
    if (inviteRole === 'admin') {
      // Update user's role to admin
      await dbClient.query(
        'UPDATE users SET role = $1 WHERE id = $2 AND role = $3',
        ['admin', decoded.userId, 'user']
      );

      // Create organization for this admin (using client as the org)
      const orgId = require('crypto').randomUUID();
      await dbClient.query(
        `INSERT INTO organizations (id, name, admin_id)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [orgId, invite.client_name, decoded.userId]
      );

      // Add admin as org member too
      await dbClient.query(
        `INSERT INTO org_members (org_id, user_id, role)
         VALUES ($1, $2, 'admin')
         ON CONFLICT (org_id, user_id) DO NOTHING`,
        [orgId, decoded.userId]
      );

      // Create access with editor role (admins can edit)
      await dbClient.query(
        `INSERT INTO client_access (owner_id, client_id, client_name, member_id, role, org_id)
         VALUES ($1, $2, $3, $4, 'editor', $5)
         ON CONFLICT (owner_id, client_id, member_id) DO UPDATE SET org_id = $5`,
        [invite.owner_id, invite.client_id, invite.client_name, decoded.userId, orgId]
      );
    }

    // If being invited as user, add to org and grant access
    if (inviteRole === 'user') {
      const orgId = invite.org_id;

      if (orgId) {
        // Add user as org member
        await dbClient.query(
          `INSERT INTO org_members (org_id, user_id, role)
           VALUES ($1, $2, 'user')
           ON CONFLICT (org_id, user_id) DO NOTHING`,
          [orgId, decoded.userId]
        );
      }

      // Create access with editor role (users can edit workflows)
      await dbClient.query(
        `INSERT INTO client_access (owner_id, client_id, client_name, member_id, role, org_id)
         VALUES ($1, $2, $3, $4, 'editor', $5)
         ON CONFLICT (owner_id, client_id, member_id) DO NOTHING`,
        [invite.owner_id, invite.client_id, invite.client_name, decoded.userId, orgId]
      );
    }

    await dbClient.query('COMMIT');

    // Get updated user role for new token
    const userResult = await pool.query('SELECT role FROM users WHERE id = $1', [decoded.userId]);
    const updatedRole = userResult.rows[0]?.role || decoded.role;
    const newToken = signToken(decoded.userId, decoded.email, updatedRole);

    res.status(200).json({
      success: true,
      clientName: invite.client_name,
      ownerId: invite.owner_id,
      clientId: invite.client_id,
      role: inviteRole,
      token: newToken,
      user: { id: decoded.userId, email: decoded.email, role: updatedRole }
    });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    console.error('Accept invite error:', err);
    res.status(500).json({ error: 'Server error.' });
  } finally {
    dbClient.release();
  }
};
