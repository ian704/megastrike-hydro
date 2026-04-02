// config.js
require('dotenv').config();

const requiredEnv = ['DATABASE_URL', 'JWT_SECRET', 'PORT', 'RESEND_API_KEY'];

requiredEnv.forEach((key) => {
  if (!process.env[key]) {
    console.error(`❌ Missing environment variable: ${key}`);
    process.exit(1);
  }
});

module.exports = {
  env: process.env.NODE_ENV || 'development',

  db: {
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for Render Postgres
  },

  jwtSecret: process.env.JWT_SECRET,
  port: process.env.PORT || 5000
};