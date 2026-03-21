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

const app = express();

// ==========================
// DATABASE MIGRATIONS (Auto-fix missing columns)
// ==========================
async function runMigrations() {
  try {
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS profile_picture TEXT
    `);
    console.log('✅ Migration complete: profile_picture column added');
  } catch (err) {
    console.error('Migration error:', err.message);
  }
}
// ==========================
// Security Middleware with Updated CSP
// ==========================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "blob:", "https://fonts.googleapis.com"],
        scriptSrcAttr: ["'unsafe-inline'"], // ADD THIS - allows inline event handlers
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "https://megastrike-hydro.onrender.com"],
      },
    },
  })
);
// Restrict CORS (for production)
app.use(cors({
  origin: 'https://megastrike-hydro.onrender.com',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// ==========================
// AUTH ROUTES
// ==========================

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ success: false, error: 'All fields required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    // CHECK EXISTING USER
    const { rows: existingUsers } = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ success: false, error: 'Email already registered' });
    }

    // HASH PASSWORD
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // INSERT USER
    const { rows } = await pool.query(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [firstName, lastName, email, phone || null, passwordHash]
    );

    const userId = rows[0].id;

    // CREATE TOKEN
    const token = jwt.sign(
      { userId, email, role: 'user', firstName, lastName },
      config.jwtSecret,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'Account created',
      token,
      user: { id: userId, firstName, lastName, email, phone, role: 'user' }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, error: 'Server error during registration' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND is_active = TRUE',
      [email]
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

// PROFILE PICTURE UPLOAD
app.post('/api/auth/profile-picture', authenticateToken, async (req, res) => {
  try {
    const { profilePictureUrl } = req.body;
    
    const { rows } = await pool.query(
      `UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING profile_picture`,
      [profilePictureUrl, req.user.userId]
    );

    res.json({ success: true, profilePictureUrl: rows[0].profile_picture });
  } catch (error) {
    console.error('Profile picture update error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ==========================
// CONSULTATIONS (AUTHENTICATED)
// ==========================

// CREATE NEW CONSULTATION
app.post('/api/consultations', authenticateToken, async (req, res) => {
  try {
    const { location, land_size, service_type, budget, description } = req.body;
    const userId = req.user.userId;
    const userEmail = req.user.email;

    // Validation
    if (!location || !service_type || !description) {
      return res.status(400).json({ 
        success: false, 
        error: 'Location, service type, and description are required' 
      });
    }

    const { rows } = await pool.query(
      `INSERT INTO consultations 
       (user_id, email, location, land_size, service_type, budget, description, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())
       RETURNING *`,
      [userId, userEmail, location, land_size || null, service_type, budget || null, description]
    );

    res.status(201).json({
      success: true,
      message: 'Consultation submitted successfully',
      consultation: rows[0]
    });

  } catch (error) {
    console.error('Consultation creation error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit consultation' });
  }
});

// GET ALL USER'S CONSULTATIONS
app.get('/api/consultations', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM consultations 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    res.json({ 
      success: true, 
      consultations: rows 
    });

  } catch (error) {
    console.error('Get consultations error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET SINGLE CONSULTATION
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
// HEALTH CHECK
// ==========================
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// ==========================
// STATIC FILES
// ==========================
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html for the root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==========================
// 404
// ==========================
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ==========================
// START SERVER
// ==========================
const PORT = process.env.PORT || 3000;

runMigrations().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
});