const { getPool } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const pool = getPool();
  const client = await pool.connect();
  try {
    // Users table with role column
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        data JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Add role column if it doesn't exist (migration for existing DBs)
    await client.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';
    `);

    // Seed system admin
    await client.query(`
      UPDATE users SET role = 'sysadmin'
      WHERE email = 'daniel.spiteri@sesg.co' AND role != 'sysadmin';
    `);

    // Organizations table (tenants)
    await client.query(`
      CREATE TABLE IF NOT EXISTS organizations (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        admin_id INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Organization members (users within a tenant)
    await client.query(`
      CREATE TABLE IF NOT EXISTS org_members (
        id SERIAL PRIMARY KEY,
        org_id VARCHAR(36) REFERENCES organizations(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        role VARCHAR(20) DEFAULT 'user',
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(org_id, user_id)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS shared_workflows (
        id VARCHAR(36) PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        client_name VARCHAR(255) NOT NULL,
        workflow_data JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ
      );
    `);

    // Client invites - now with invite_role to distinguish admin vs user invites
    await client.query(`
      CREATE TABLE IF NOT EXISTS client_invites (
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

    // Add new columns to client_invites if they don't exist (migration)
    await client.query(`
      ALTER TABLE client_invites ADD COLUMN IF NOT EXISTS invite_role VARCHAR(20) DEFAULT 'user';
    `);
    await client.query(`
      ALTER TABLE client_invites ADD COLUMN IF NOT EXISTS org_id VARCHAR(36);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS client_access (
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

    // Add org_id column to client_access if not exists (migration)
    await client.query(`
      ALTER TABLE client_access ADD COLUMN IF NOT EXISTS org_id VARCHAR(36);
    `);

    res.status(200).json({ success: true, message: 'Tables created/updated successfully' });
  } catch (err) {
    console.error('Setup error:', err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
};
