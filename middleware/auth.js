const jwt = require('jsonwebtoken');
const config = require('../config');

function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ success: false, error: 'Invalid token format' });
    }

    const decoded = jwt.verify(token, config.jwtSecret);

    // 🔥 CRITICAL FIX: Match exactly what frontend expects
    req.user = {
      userId: decoded.userId,
      id: decoded.userId,
      email: decoded.email,
      role: decoded.role || 'user', // Default fallback
      firstName: decoded.firstName,
      lastName: decoded.lastName
    };

    console.log('✅ Auth middleware - user:', req.user);

    next();
  } catch (err) {
    console.error('❌ JWT ERROR:', err.message);
    return res.status(403).json({ success: false, error: 'Invalid or expired token' });
  }
}

module.exports = { authenticateToken };