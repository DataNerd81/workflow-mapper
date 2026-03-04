const { getPool } = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        data JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
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

    await client.query(`
      CREATE TABLE IF NOT EXISTS client_invites (
        id VARCHAR(36) PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        client_id VARCHAR(36) NOT NULL,
        client_name VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days')
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS client_access (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        client_id VARCHAR(36) NOT NULL,
        client_name VARCHAR(255) NOT NULL,
        member_id INTEGER REFERENCES users(id),
        role VARCHAR(20) DEFAULT 'editor',
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(owner_id, client_id, member_id)
      );
    `);

    res.status(200).json({ success: true, message: 'Tables created successfully' });
  } catch (err) {
    console.error('Setup error:', err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
};
