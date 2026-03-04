const { getPool } = require('./_db');
const { verifyToken, cors, ROLES } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' });

  const pool = getPool();

  // GET - list organizations
  if (req.method === 'GET') {
    try {
      let result;
      if (decoded.role === ROLES.SYSADMIN) {
        // Sysadmin sees all orgs
        result = await pool.query(
          `SELECT o.id, o.name, o.created_at, u.email as admin_email, u.id as admin_id,
                  (SELECT COUNT(*) FROM org_members om WHERE om.org_id = o.id) as member_count
           FROM organizations o
           JOIN users u ON o.admin_id = u.id
           ORDER BY o.created_at DESC`
        );
      } else if (decoded.role === ROLES.ADMIN) {
        // Admin sees their own org
        result = await pool.query(
          `SELECT o.id, o.name, o.created_at, u.email as admin_email, u.id as admin_id,
                  (SELECT COUNT(*) FROM org_members om WHERE om.org_id = o.id) as member_count
           FROM organizations o
           JOIN users u ON o.admin_id = u.id
           WHERE o.admin_id = $1
           ORDER BY o.created_at DESC`,
          [decoded.userId]
        );
      } else {
        // Regular users see orgs they belong to
        result = await pool.query(
          `SELECT o.id, o.name, o.created_at, u.email as admin_email, u.id as admin_id,
                  (SELECT COUNT(*) FROM org_members om WHERE om.org_id = o.id) as member_count
           FROM organizations o
           JOIN users u ON o.admin_id = u.id
           JOIN org_members om ON om.org_id = o.id
           WHERE om.user_id = $1
           ORDER BY o.created_at DESC`,
          [decoded.userId]
        );
      }

      res.status(200).json({ organizations: result.rows });
    } catch (err) {
      console.error('Org list error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
    return;
  }

  // DELETE - remove a member from org (admin or sysadmin only)
  if (req.method === 'DELETE') {
    if (decoded.role !== ROLES.ADMIN && decoded.role !== ROLES.SYSADMIN) {
      return res.status(403).json({ error: 'Only admins can remove members.' });
    }

    const { orgId, userId } = req.body || {};
    if (!orgId || !userId) return res.status(400).json({ error: 'orgId and userId required' });

    try {
      // Verify the requester owns this org (or is sysadmin)
      if (decoded.role === ROLES.ADMIN) {
        const orgCheck = await pool.query(
          'SELECT id FROM organizations WHERE id = $1 AND admin_id = $2',
          [orgId, decoded.userId]
        );
        if (orgCheck.rows.length === 0) return res.status(403).json({ error: 'Not your organization.' });
      }

      // Remove from org_members
      await pool.query(
        'DELETE FROM org_members WHERE org_id = $1 AND user_id = $2',
        [orgId, userId]
      );

      // Remove client_access for this org
      await pool.query(
        'DELETE FROM client_access WHERE org_id = $1 AND member_id = $2',
        [orgId, userId]
      );

      res.status(200).json({ success: true });
    } catch (err) {
      console.error('Remove member error:', err);
      res.status(500).json({ error: 'Server error.' });
    }
    return;
  }

  res.status(405).json({ error: 'Method not allowed' });
};
