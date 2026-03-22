require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const config = require('./config');
const { authenticateToken } = require('./middleware/auth');
const morgan = require('morgan');
const helmet = require('helmet');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();

// ==========================
// EMAIL CONFIGURATION
// ==========================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate 6-digit reset code
function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==========================
// STARTUP LOGS
// ==========================
console.log('=== SERVER STARTUP ===');
console.log('Time:', new Date().toISOString());
console.log('NODE_ENV:', process.env.NODE_ENV || 'not set');
console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('JWT_SECRET exists:', !!process.env.JWT_SECRET);
console.log('EMAIL_USER exists:', !!process.env.EMAIL_USER);

// ==========================
// DATABASE MIGRATIONS
// ==========================
async function runMigrations() {
  let client;
  try {
    client = await pool.connect();
    console.log('✅ Database connected');

    // Test connection
    const testResult = await client.query('SELECT NOW()');
    console.log('Database time:', testResult.rows[0].now);

    // Create users table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        is_active BOOLEAN DEFAULT TRUE,
        profile_picture TEXT,
        reset_code VARCHAR(10),
        reset_code_expires TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Users table ready');

    // Create consultations table if not exists - WITH name column
    await client.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        email VARCHAR(255),
        name VARCHAR(200) NOT NULL DEFAULT '',
        location VARCHAR(500) NOT NULL,
        land_size DECIMAL(10,2),
        service_type VARCHAR(100) NOT NULL,
        budget DECIMAL(15,2),
        description TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Consultations table ready');

    // Add missing columns to users table
    const userColumns = await client.query(`
      SELECT column_name FROM information_schema.columns WHERE table_name = 'users'
    `);
    const existingUserCols = userColumns.rows.map(r => r.column_name);
    
    if (!existingUserCols.includes('reset_code')) {
      await client.query(`ALTER TABLE users ADD COLUMN reset_code VARCHAR(10)`);
      console.log('✅ Added reset_code to users');
    }
    if (!existingUserCols.includes('reset_code_expires')) {
      await client.query(`ALTER TABLE users ADD COLUMN reset_code_expires TIMESTAMP`);
      console.log('✅ Added reset_code_expires to users');
    }
    if (!existingUserCols.includes('profile_picture')) {
      await client.query(`ALTER TABLE users ADD COLUMN profile_picture TEXT`);
      console.log('✅ Added profile_picture to users');
    }

    // Verify consultations table structure
    const consultColumns = await client.query(`
      SELECT column_name FROM information_schema.columns WHERE table_name = 'consultations'
    `);
    const existingConsultCols = consultColumns.rows.map(r => r.column_name);
    console.log('Consultations columns:', existingConsultCols);

    // Add missing columns to consultations if needed
    const requiredCols = [
      { name: 'user_id', type: 'INTEGER NOT NULL DEFAULT 0' },
      { name: 'email', type: 'VARCHAR(255)' },
      { name: 'name', type: 'VARCHAR(200) NOT NULL DEFAULT \'\'' },
      { name: 'location', type: 'VARCHAR(500) NOT NULL DEFAULT \'\'' },
      { name: 'land_size', type: 'DECIMAL(10,2)' },
      { name: 'service_type', type: 'VARCHAR(100) NOT NULL DEFAULT \'\'' },
      { name: 'budget', type: 'DECIMAL(15,2)' },
      { name: 'description', type: 'TEXT NOT NULL DEFAULT \'\'' },
      { name: 'status', type: 'VARCHAR(50) DEFAULT \'pending\'' },
      { name: 'created_at', type: 'TIMESTAMP DEFAULT NOW()' }
    ];

    for (const col of requiredCols) {
      if (!existingConsultCols.includes(col.name)) {
        console.log(`Adding missing column: ${col.name}`);
        await client.query(`ALTER TABLE consultations ADD COLUMN ${col.name} ${col.type}`);
      }
    }

    // Remove defaults after columns exist
    try {
      await client.query(`ALTER TABLE consultations ALTER COLUMN location DROP DEFAULT`);
      await client.query(`ALTER TABLE consultations ALTER COLUMN user_id DROP DEFAULT`);
      await client.query(`ALTER TABLE consultations ALTER COLUMN service_type DROP DEFAULT`);
      await client.query(`ALTER TABLE consultations ALTER COLUMN description DROP DEFAULT`);
      await client.query(`ALTER TABLE consultations ALTER COLUMN name DROP DEFAULT`);
    } catch (e) {
      // Defaults might already be removed
    }

    console.log('✅ All migrations complete');

  } catch (err) {
    console.error('❌ Migration error:', err.message);
    console.error(err.stack);
    throw err;
  } finally {
    if (client) client.release();
  }
}

// ==========================
// SECURITY MIDDLEWARE
// ==========================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "blob:"],
        scriptSrcElem: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "https://megastrike-hydro.onrender.com", "https://*.onrender.com"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
  })
);

app.use(cors({
  origin: ['https://megastrike-hydro.onrender.com', 'http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan('combined'));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ==========================
// AUTH ROUTES
// ==========================

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  console.log('Signup attempt:', req.body.email);
  try {
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ success: false, error: 'All fields required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    const { rows: existingUsers } = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ success: false, error: 'Email already registered' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const { rows } = await pool.query(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, first_name, last_name, email, phone, role`,
      [firstName, lastName, email.toLowerCase().trim(), phone || null, passwordHash]
    );

    const userId = rows[0].id;
    const user = rows[0];

    const token = jwt.sign(
      { userId, email, role: user.role, firstName: user.first_name, lastName: user.last_name },
      config.jwtSecret,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'Account created',
      token,
      user: { 
        id: userId, 
        firstName: user.first_name, 
        lastName: user.last_name, 
        email: user.email, 
        phone: user.phone, 
        role: user.role 
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, error: 'Server error during registration' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt:', req.body.email);
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_active = TRUE',
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = rows[0];

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    await pool.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name
      },
      config.jwtSecret,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// GET CURRENT USER
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    console.log('Get user:', req.user.userId);
    
    if (!req.user || !req.user.userId) {
      return res.status(401).json({ success: false, error: 'Invalid user data' });
    }

    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, email, phone, role, created_at, profile_picture 
       FROM users WHERE id = $1`,
      [req.user.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user: rows[0] });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// UPDATE PROFILE
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone } = req.body;
    const userId = req.user.userId;

    const { rows } = await pool.query(
      `UPDATE users 
       SET first_name = $1, last_name = $2, phone = $3 
       WHERE id = $4 
       RETURNING id, first_name, last_name, email, phone, role`,
      [firstName, lastName, phone, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user: rows[0] });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// PROFILE PICTURE
app.post('/api/auth/profile-picture', authenticateToken, async (req, res) => {
  try {
    const { profilePictureUrl } = req.body;
    
    const { rows } = await pool.query(
      `UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING profile_picture`,
      [profilePictureUrl, req.user.userId]
    );

    res.json({ success: true, profilePictureUrl: rows[0].profile_picture });
  } catch (error) {
    console.error('Profile picture error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ==========================
// FORGOT PASSWORD ROUTES
// ==========================

// Request password reset - send code to email
app.post('/api/auth/forgot-password', async (req, res) => {
  console.log('Forgot password request:', req.body.email);
  
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required' });
    }

    const { rows } = await pool.query(
      'SELECT id, first_name, email FROM users WHERE email = $1 AND is_active = TRUE',
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      return res.json({ 
        success: true, 
        message: 'If an account exists, a reset code has been sent' 
      });
    }

    const user = rows[0];
    const resetCode = generateResetCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      `UPDATE users SET reset_code = $1, reset_code_expires = $2 WHERE id = $3`,
      [resetCode, expiresAt, user.id]
    );

    const mailOptions = {
      from: `"Megastrike Hydro" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Password Reset Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #0a1628;">Password Reset Request</h2>
          <p>Hello ${user.first_name},</p>
          <p>You requested a password reset for your Megastrike Hydro account.</p>
          <div style="background: #f4a261; color: #0a1628; padding: 20px; text-align: center; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px;">Your reset code is:</p>
            <h1 style="margin: 10px 0; font-size: 48px; letter-spacing: 10px;">${resetCode}</h1>
          </div>
          <p>This code expires in <strong>15 minutes</strong>.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <hr style="border: none; border-top: 1px solid #e0e1dd; margin: 20px 0;">
          <p style="color: #778da9; font-size: 12px;">
            Megastrike Hydro Drilling Solutions<br>
            This is an automated email, please do not reply.
          </p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Reset email sent to:', user.email);

    res.json({ 
      success: true, 
      message: 'If an account exists, a reset code has been sent'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, error: 'Failed to send reset code' });
  }
});

// Verify reset code
app.post('/api/auth/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({ success: false, error: 'Email and code required' });
    }

    const { rows } = await pool.query(
      `SELECT id, reset_code, reset_code_expires 
       FROM users 
       WHERE email = $1 AND is_active = TRUE`,
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid email or code' });
    }

    const user = rows[0];

    if (user.reset_code !== code) {
      return res.status(400).json({ success: false, error: 'Invalid code' });
    }

    if (new Date() > new Date(user.reset_code_expires)) {
      return res.status(400).json({ success: false, error: 'Code has expired' });
    }

    const tempToken = jwt.sign(
      { userId: user.id, purpose: 'password-reset' },
      config.jwtSecret,
      { expiresIn: '10m' }
    );

    res.json({ 
      success: true, 
      message: 'Code verified',
      tempToken: tempToken
    });

  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { tempToken, newPassword } = req.body;
    
    if (!tempToken || !newPassword) {
      return res.status(400).json({ success: false, error: 'Token and new password required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    let decoded;
    try {
      decoded = jwt.verify(tempToken, config.jwtSecret);
    } catch (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }

    if (decoded.purpose !== 'password-reset') {
      return res.status(401).json({ success: false, error: 'Invalid token purpose' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(newPassword, salt);

    await pool.query(
      `UPDATE users 
       SET password_hash = $1, reset_code = NULL, reset_code_expires = NULL 
       WHERE id = $2`,
      [passwordHash, decoded.userId]
    );

    res.json({ 
      success: true, 
      message: 'Password reset successful' 
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ==========================
// CONSULTATIONS
// ==========================

// Create consultation - FIXED: Added name column
app.post('/api/consultations', authenticateToken, async (req, res) => {
  console.log('Consultation create - User:', req.user.userId);
  
  let client;
  try {
    const { location, land_size, service_type, budget, description } = req.body;
    const userId = req.user?.userId;
    const userEmail = req.user?.email;
    const firstName = req.user?.firstName || '';
    const lastName = req.user?.lastName || '';
    const fullName = `${firstName} ${lastName}`.trim() || 'Unknown';

    if (!userId) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    if (!location || !service_type || !description) {
      return res.status(400).json({ 
        success: false, 
        error: 'Location, service type, and description are required' 
      });
    }

    client = await pool.connect();

    // FIXED: Added name column to INSERT
    const { rows } = await client.query(
      `INSERT INTO consultations 
       (user_id, email, name, location, land_size, service_type, budget, description, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW())
       RETURNING *`,
      [
        userId, 
        userEmail || null, 
        fullName,  // Added name from JWT token
        location.trim(), 
        land_size ? parseFloat(land_size) : null, 
        service_type, 
        budget ? parseFloat(budget) : null, 
        description.trim()
      ]
    );

    console.log('Consultation created:', rows[0].id);

    res.status(201).json({
      success: true,
      message: 'Consultation submitted successfully',
      consultation: rows[0]
    });

  } catch (error) {
    console.error('Consultation create error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to submit consultation: ' + error.message 
    });
  } finally {
    if (client) client.release();
  }
});

// Get all user's consultations
app.get('/api/consultations', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM consultations 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    res.json({ success: true, consultations: rows });

  } catch (error) {
    console.error('Get consultations error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single consultation
app.get('/api/consultations/:id', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM consultations 
       WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Consultation not found' });
    }

    res.json({ success: true, consultation: rows[0] });

  } catch (error) {
    console.error('Get consultation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// ADMIN ROUTES
// ==========================

// Get all consultations (admin only)
app.get('/api/admin/consultations', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { rows } = await pool.query(
      `SELECT c.*, u.first_name, u.last_name, u.phone as user_phone
       FROM consultations c
       LEFT JOIN users u ON c.user_id = u.id
       ORDER BY c.created_at DESC`
    );

    res.json({ success: true, consultations: rows });

  } catch (error) {
    console.error('Get all consultations error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, email, phone, role, is_active, created_at, last_login 
       FROM users 
       ORDER BY created_at DESC`
    );

    res.json({ success: true, users: rows });

  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update consultation status (admin only)
app.put('/api/admin/consultations/:id/status', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { status } = req.body;
    const { id } = req.params;

    if (!['pending', 'in-progress', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }

    const { rows } = await pool.query(
      `UPDATE consultations 
       SET status = $1, updated_at = NOW() 
       WHERE id = $2 
       RETURNING *`,
      [status, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Consultation not found' });
    }

    res.json({ success: true, consultation: rows[0] });

  } catch (error) {
    console.error('Update status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// DASHBOARD
// ==========================
app.get('/api/user/dashboard', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM consultations 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    res.json({ 
      success: true, 
      user: req.user, 
      consultations: rows 
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// HEALTH & TEST
// ==========================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date(),
    db: 'connected'
  });
});

app.get('/api/test-db', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() as time');
    res.json({ 
      success: true, 
      dbTime: rows[0].time
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================
// STATIC FILES
// ==========================
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==========================
// ERROR HANDLING
// ==========================
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==========================
// START SERVER
// ==========================
const PORT = process.env.PORT || 3000;

runMigrations()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Health: http://localhost:${PORT}/api/health`);
    });
  })
  .catch(err => {
    console.error('❌ Failed to start:', err);
    process.exit(1);
  });