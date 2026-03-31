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
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate 6-digit code
function generateCode() {
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

    // Create users table with email verification fields
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        is_active BOOLEAN DEFAULT FALSE,
        is_verified BOOLEAN DEFAULT FALSE,
        verification_code VARCHAR(10),
        verification_code_expires TIMESTAMP,
        profile_picture TEXT,
        reset_code VARCHAR(10),
        reset_code_expires TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Users table ready');

    // Add new columns if they don't exist
    const userColumns = await client.query(`
      SELECT column_name FROM information_schema.columns WHERE table_name = 'users'
    `);
    const existingUserCols = userColumns.rows.map(r => r.column_name);
    
    const columnsToAdd = [
      { name: 'is_verified', type: 'BOOLEAN DEFAULT FALSE' },
      { name: 'verification_code', type: 'VARCHAR(10)' },
      { name: 'verification_code_expires', type: 'TIMESTAMP' },
      { name: 'reset_code', type: 'VARCHAR(10)' },
      { name: 'reset_code_expires', type: 'TIMESTAMP' },
      { name: 'profile_picture', type: 'TEXT' }
    ];

    for (const col of columnsToAdd) {
      if (!existingUserCols.includes(col.name)) {
        await client.query(`ALTER TABLE users ADD COLUMN ${col.name} ${col.type}`);
        console.log(`✅ Added ${col.name} to users`);
      }
    }

    // Create consultations table
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

    // Create contact messages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        subject VARCHAR(255),
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Contact messages table ready');

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
// EMAIL VERIFICATION ROUTES
// ==========================

// SIGNUP - Modified to require email verification
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
      'SELECT id, is_verified FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    // If user exists but not verified, allow resending code
    if (existingUsers.length > 0 && !existingUsers[0].is_verified) {
      // Resend verification code
      const verificationCode = generateCode();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      await pool.query(
        `UPDATE users SET verification_code = $1, verification_code_expires = $2 WHERE id = $3`,
        [verificationCode, expiresAt, existingUsers[0].id]
      );

      // Send verification email
      const mailOptions = {
        from: `"Megastrike Hydro" <${process.env.EMAIL_USER}>`,
        to: email.toLowerCase().trim(),
        subject: 'Verify Your Email - Megastrike Hydro',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 20px;">
            <div style="background: #0a1628; padding: 30px; text-align: center;">
              <h1 style="color: #e9c46a; margin: 0; font-size: 28px;">MEGASTRIKE</h1>
              <p style="color: #e0e1dd; margin: 5px 0 0 0; font-size: 14px;">Hydro Drilling Solutions</p>
            </div>
            <div style="background: white; padding: 40px; border-radius: 0 0 8px 8px;">
              <h2 style="color: #0a1628; margin-bottom: 20px;">Verify Your Email</h2>
              <p style="color: #64748b; line-height: 1.6;">Hello ${firstName},</p>
              <p style="color: #64748b; line-height: 1.6;">Thank you for signing up! Please use the verification code below to activate your account:</p>
              
              <div style="background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%); padding: 30px; text-align: center; margin: 30px 0; border-radius: 8px;">
                <p style="color: #e9c46a; margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; letter-spacing: 2px;">Your Verification Code</p>
                <h1 style="color: #e9c46a; margin: 0; font-size: 48px; letter-spacing: 15px; font-weight: 700;">${verificationCode}</h1>
              </div>
              
              <p style="color: #64748b; line-height: 1.6; font-size: 14px;">This code will expire in <strong>24 hours</strong>.</p>
              <p style="color: #64748b; line-height: 1.6; font-size: 14px;">If you didn't create an account, please ignore this email.</p>
              
              <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">
              <p style="color: #94a3b8; font-size: 12px; text-align: center;">
                Megastrike Hydro Drilling Solutions Ltd<br>
                Kitale, Kenya<br>
                This is an automated email, please do not reply.
              </p>
            </div>
          </div>
        `
      };

      await transporter.sendMail(mailOptions);
      console.log('Verification email resent to:', email);

      return res.status(200).json({
        success: true,
        message: 'Verification code resent to your email',
        requiresVerification: true,
        email: email.toLowerCase().trim()
      });
    }

    // If user exists and is verified
    if (existingUsers.length > 0 && existingUsers[0].is_verified) {
      return res.status(409).json({ success: false, error: 'Email already registered' });
    }

    // New user - create unverified account
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
    const verificationCode = generateCode();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const { rows } = await pool.query(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, is_active, is_verified, verification_code, verification_code_expires)
       VALUES ($1, $2, $3, $4, $5, FALSE, FALSE, $6, $7)
       RETURNING id, first_name, last_name, email, phone, role, is_verified`,
      [firstName, lastName, email.toLowerCase().trim(), phone || null, passwordHash, verificationCode, expiresAt]
    );

    const userId = rows[0].id;
    const user = rows[0];

    // Send verification email
    const mailOptions = {
      from: `"Megastrike Hydro" <${process.env.EMAIL_USER}>`,
      to: email.toLowerCase().trim(),
      subject: 'Verify Your Email - Megastrike Hydro',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 20px;">
          <div style="background: #0a1628; padding: 30px; text-align: center;">
            <h1 style="color: #e9c46a; margin: 0; font-size: 28px;">MEGASTRIKE</h1>
            <p style="color: #e0e1dd; margin: 5px 0 0 0; font-size: 14px;">Hydro Drilling Solutions</p>
          </div>
          <div style="background: white; padding: 40px; border-radius: 0 0 8px 8px;">
            <h2 style="color: #0a1628; margin-bottom: 20px;">Verify Your Email</h2>
            <p style="color: #64748b; line-height: 1.6;">Hello ${firstName},</p>
            <p style="color: #64748b; line-height: 1.6;">Thank you for signing up! Please use the verification code below to activate your account:</p>
            
            <div style="background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%); padding: 30px; text-align: center; margin: 30px 0; border-radius: 8px;">
              <p style="color: #e9c46a; margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; letter-spacing: 2px;">Your Verification Code</p>
              <h1 style="color: #e9c46a; margin: 0; font-size: 48px; letter-spacing: 15px; font-weight: 700;">${verificationCode}</h1>
            </div>
            
            <p style="color: #64748b; line-height: 1.6; font-size: 14px;">This code will expire in <strong>24 hours</strong>.</p>
            <p style="color: #64748b; line-height: 1.6; font-size: 14px;">If you didn't create an account, please ignore this email.</p>
            
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">
            <p style="color: #94a3b8; font-size: 12px; text-align: center;">
              Megastrike Hydro Drilling Solutions Ltd<br>
              Kitale, Kenya<br>
              This is an automated email, please do not reply.
            </p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Verification email sent to:', email);

    res.status(201).json({
      success: true,
      message: 'Account created. Please check your email for verification code.',
      requiresVerification: true,
      email: email.toLowerCase().trim(),
      userId: userId
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, error: 'Server error during registration' });
  }
});

// VERIFY EMAIL CODE
app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ success: false, error: 'Email and verification code required' });
    }

    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, email, phone, role, is_verified, 
              verification_code, verification_code_expires, password_hash
       FROM users WHERE email = $1`,
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const user = rows[0];

    if (user.is_verified) {
      return res.status(400).json({ success: false, error: 'Account already verified' });
    }

    if (user.verification_code !== code) {
      return res.status(400).json({ success: false, error: 'Invalid verification code' });
    }

    if (new Date() > new Date(user.verification_code_expires)) {
      return res.status(400).json({ success: false, error: 'Verification code has expired' });
    }

    // Activate account
    await pool.query(
      `UPDATE users 
       SET is_verified = TRUE, is_active = TRUE, verification_code = NULL, 
           verification_code_expires = NULL, last_login = NOW() 
       WHERE id = $1`,
      [user.id]
    );

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role, firstName: user.first_name, lastName: user.last_name },
      config.jwtSecret,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Email verified successfully! Welcome to Megastrike Hydro.',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        isVerified: true
      }
    });

  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({ success: false, error: 'Server error during verification' });
  }
});

// RESEND VERIFICATION CODE - SECURE VERSION
app.post('/api/auth/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required' });
    }

    const { rows } = await pool.query(
      'SELECT id, first_name, is_verified FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    // SECURITY FIX: Always return same generic message
    // Don't reveal if email exists, is verified, or not
    if (rows.length === 0 || rows[0].is_verified) {
      return res.json({ 
        success: true, 
        message: 'If an account exists with this email, a verification code has been sent' 
      });
    }

    const user = rows[0];
    const verificationCode = generateCode();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await pool.query(
      `UPDATE users SET verification_code = $1, verification_code_expires = $2 WHERE id = $3`,
      [verificationCode, expiresAt, user.id]
    );

    // Send email
    const mailOptions = {
      from: `"Megastrike Hydro" <${process.env.EMAIL_USER}>`,
      to: email.toLowerCase().trim(),
      subject: 'Verify Your Email - Megastrike Hydro',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 20px;">
          <div style="background: #0a1628; padding: 30px; text-align: center;">
            <h1 style="color: #e9c46a; margin: 0; font-size: 28px;">MEGASTRIKE</h1>
            <p style="color: #e0e1dd; margin: 5px 0 0 0; font-size: 14px;">Hydro Drilling Solutions</p>
          </div>
          <div style="background: white; padding: 40px; border-radius: 0 0 8px 8px;">
            <h2 style="color: #0a1628; margin-bottom: 20px;">Verify Your Email</h2>
            <p style="color: #64748b; line-height: 1.6;">Hello ${user.first_name},</p>
            <p style="color: #64748b; line-height: 1.6;">Here is your new verification code:</p>
            
            <div style="background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%); padding: 30px; text-align: center; margin: 30px 0; border-radius: 8px;">
              <p style="color: #e9c46a; margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; letter-spacing: 2px;">Your Verification Code</p>
              <h1 style="color: #e9c46a; margin: 0; font-size: 48px; letter-spacing: 15px; font-weight: 700;">${verificationCode}</h1>
            </div>
            
            <p style="color: #64748b; line-height: 1.6; font-size: 14px;">This code will expire in <strong>24 hours</strong>.</p>
            
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">
            <p style="color: #94a3b8; font-size: 12px; text-align: center;">
              Megastrike Hydro Drilling Solutions Ltd<br>
              Kitale, Kenya
            </p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Verification email resent to:', email);

    // Return same generic message even when email is actually sent
    res.json({ 
      success: true, 
      message: 'If an account exists with this email, a verification code has been sent' 
    });

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ success: false, error: 'Failed to process request' });
  }
});

// ==========================
// LOGIN - Modified to check verification
// ==========================
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt:', req.body.email);
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = rows[0];

    // Check if email is verified
    if (!user.is_verified) {
      return res.status(403).json({ 
        success: false, 
        error: 'Please verify your email before logging in',
        requiresVerification: true,
        email: user.email
      });
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      return res.status(403).json({ success: false, error: 'Account is deactivated' });
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
        role: user.role,
        isVerified: true
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
      `SELECT id, first_name, last_name, email, phone, role, is_verified, created_at, profile_picture 
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
       RETURNING id, first_name, last_name, email, phone, role, is_verified`,
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
      'SELECT id, first_name, email FROM users WHERE email = $1 AND is_active = TRUE AND is_verified = TRUE',
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      return res.json({ 
        success: true, 
        message: 'If an account exists, a reset code has been sent' 
      });
    }

    const user = rows[0];
    const resetCode = generateCode();
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
// CONTACT FORM
// ==========================
app.post('/api/contact', async (req, res) => {
  console.log('Contact form submission:', req.body);

  try {
    const { name, email, phone, subject, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({
        success: false,
        error: 'Name, email, and message are required'
      });
    }

    const { rows } = await pool.query(
      `INSERT INTO contact_messages (name, email, phone, subject, message)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        name.trim(),
        email.toLowerCase().trim(),
        phone || null,
        subject || 'General Inquiry',
        message.trim()
      ]
    );

    const mailOptions = {
      from: `"Website Contact" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: `New Contact Message: ${subject || 'No Subject'}`,
      html: `
        <h2>New Contact Message</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone || 'N/A'}</p>
        <p><strong>Subject:</strong> ${subject || 'N/A'}</p>
        <p><strong>Message:</strong></p>
        <p>${message}</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      contact: rows[0]
    });

  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send message'
    });
  }
});

// ==========================
// CONSULTATIONS
// ==========================

// Create consultation
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

    const { rows } = await client.query(
      `INSERT INTO consultations 
       (user_id, email, name, location, land_size, service_type, budget, description, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW())
       RETURNING *`,
      [
        userId, 
        userEmail || null, 
        fullName,
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
      `SELECT id, first_name, last_name, email, phone, role, is_active, is_verified, created_at, last_login 
       FROM users 
       ORDER BY created_at DESC`
    );

    res.json({ success: true, users: rows });

  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE USER (admin only)
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { id } = req.params;
    const adminId = req.user.userId;

    // Prevent admin from deleting themselves
    if (parseInt(id) === adminId) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }

    // Check if user exists
    const { rows: userCheck } = await pool.query(
      'SELECT id, role FROM users WHERE id = $1',
      [id]
    );

    if (userCheck.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Prevent deleting other admins (optional safety measure)
    if (userCheck[0].role === 'admin') {
      return res.status(403).json({ success: false, error: 'Cannot delete admin accounts' });
    }

    // Delete user's consultations first (foreign key constraint handling)
    await pool.query('DELETE FROM consultations WHERE user_id = $1', [id]);
    
    // Delete user
    const { rows } = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id, first_name, last_name, email',
      [id]
    );

    res.json({ 
      success: true, 
      message: 'User deleted successfully',
      deletedUser: rows[0]
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, error: 'Server error during deletion' });
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