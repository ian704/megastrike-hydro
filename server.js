require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const config = require('./config');
const { authenticateToken } = require('./middleware/auth');
const morgan = require('morgan');
const helmet = require('helmet');

const app = express();

// ==========================
// Middleware
// ==========================
app.use(helmet());

// Restrict CORS ( for production)
app.use(cors({
  origin: 'https://megastrike-hydro.onrender.com', //  live frontend URL
  credentials: true // allow cookies/auth headers
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
    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, email, phone, role, created_at 
       FROM users WHERE id = $1`,
      [req.user.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, user: rows[0] });

  } catch (error) {
    console.error('Get user error:', error);
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
       WHERE email = $1 OR user_id = $2 
       ORDER BY created_at DESC`,
      [req.user.email, req.user.userId]
    );

    res.json({ success: true, user: req.user, consultations: rows });

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

app.post('/api/consultations', async (req, res) => {
  try {
    const { name, phone, email, service, details } = req.body;

    const { rows } = await pool.query(
      `INSERT INTO consultations (name, phone, email, service, details)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, phone, email, service, details]
    );

    res.json({ success: true, consultation: rows[0] });

  } catch (error) {
    console.error('Consultation error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit consultation' });
  }
});

// ==========================
// STATIC FILES
// ==========================
const path = require('path');

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
const PORT = process.env.PORT || 3000; // Render assigns PORT automatically

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});