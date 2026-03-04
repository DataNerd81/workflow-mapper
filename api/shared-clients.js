const { getPool } = require('./_db');
const { verifyToken, cors, ROLES } = require('./_auth');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'GET only' });

  const decoded = verifyToken(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' });

  const pool = getPool();
  try {
    let accessRows;

    if (decoded.role === ROLES.SYSADMIN) {
      // Sysadmin sees all shared clients across all orgs
      const result = await pool.query(
        `SELECT ca.owner_id, ca.client_id, ca.client_name, ca.role, ca.org_id,
                u.email as owner_email,
                o.name as org_name
         FROM client_access ca
         JOIN users u ON ca.owner_id = u.id
         LEFT JOIN organizations o ON ca.org_id = o.id`
      );
      accessRows = result.rows;
    } else {
      // Regular users/admins see their own shared clients
      const result = await pool.query(
        `SELECT ca.owner_id, ca.client_id, ca.client_name, ca.role, ca.org_id,
                u.email as owner_email,
                o.name as org_name
         FROM client_access ca
         JOIN users u ON ca.owner_id = u.id
         LEFT JOIN organizations o ON ca.org_id = o.id
         WHERE ca.member_id = $1`,
        [decoded.userId]
      );
      accessRows = result.rows;
    }

    // For each shared client, fetch the actual client data from the owner's data
    const sharedClients = [];
    for (const row of accessRows) {
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
          _role: row.role,
          _orgId: row.org_id,
          _orgName: row.org_name
        });
      }
    }

    // Also get org members if user is admin
    let orgMembers = [];
    if (decoded.role === ROLES.ADMIN || decoded.role === ROLES.SYSADMIN) {
      let memberQuery;
      if (decoded.role === ROLES.SYSADMIN) {
        memberQuery = await pool.query(
          `SELECT om.org_id, om.role as member_role, u.id as user_id, u.email, u.role as global_role,
                  o.name as org_name
           FROM org_members om
           JOIN users u ON om.user_id = u.id
           JOIN organizations o ON om.org_id = o.id`
        );
      } else {
        memberQuery = await pool.query(
          `SELECT om.org_id, om.role as member_role, u.id as user_id, u.email, u.role as global_role,
                  o.name as org_name
           FROM org_members om
           JOIN users u ON om.user_id = u.id
           JOIN organizations o ON om.org_id = o.id
           WHERE o.admin_id = $1`,
          [decoded.userId]
        );
      }
      orgMembers = memberQuery.rows;
    }

    res.status(200).json({
      sharedClients,
      orgMembers,
      userRole: decoded.role
    });
  } catch (err) {
    console.error('Shared clients error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
};
