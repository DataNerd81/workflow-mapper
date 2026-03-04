const { getPool } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const pool = getPool();
  const client = await pool.connect();
  try {
    // Drop all tables in correct order (respecting foreign keys)
    await client.query(`
      DROP TABLE IF EXISTS client_access CASCADE;
      DROP TABLE IF EXISTS client_invites CASCADE;
      DROP TABLE IF EXISTS shared_workflows CASCADE;
      DROP TABLE IF EXISTS org_members CASCADE;
      DROP TABLE IF EXISTS organizations CASCADE;
      DROP TABLE IF EXISTS users CASCADE;
    `);

    // Recreate all tables
    await client.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        data JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE organizations (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        admin_id INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE org_members (
        id SERIAL PRIMARY KEY,
        org_id VARCHAR(36) REFERENCES organizations(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        role VARCHAR(20) DEFAULT 'user',
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(org_id, user_id)
      );
    `);

    await client.query(`
      CREATE TABLE shared_workflows (
        id VARCHAR(36) PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        client_name VARCHAR(255) NOT NULL,
        workflow_data JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ
      );
    `);

    await client.query(`
      CREATE TABLE client_invites (
        id VARCHAR(36) PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        client_id VARCHAR(36) NOT NULL,
        client_name VARCHAR(255) NOT NULL,
        invite_role VARCHAR(20) DEFAULT 'user',
        org_id VARCHAR(36),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days')
      );
    `);

    await client.query(`
      CREATE TABLE client_access (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        client_id VARCHAR(36) NOT NULL,
        client_name VARCHAR(255) NOT NULL,
        member_id INTEGER REFERENCES users(id),
        role VARCHAR(20) DEFAULT 'editor',
        org_id VARCHAR(36),
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(owner_id, client_id, member_id)
      );
    `);

    res.status(200).json({ success: true, message: 'Database reset complete. All tables dropped and recreated. Sign up fresh!' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
};
