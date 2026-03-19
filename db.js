const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool(config.db);

// Initialize tables (same as before)
const initTables = async () => {
  const client = await pool.connect();
  try {
    console.log('📡 Connected to PostgreSQL');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password_hash TEXT NOT NULL,
        role VARCHAR(10) DEFAULT 'user',
        is_active BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        email VARCHAR(100),
        service VARCHAR(50) NOT NULL,
        details TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
      );
    `);

    console.log('✅ Tables ready');
  } catch (err) {
    console.error('❌ Database init error:', err);
    process.exit(1);
  } finally {
    client.release();
  }
};

initTables();

module.exports = pool;