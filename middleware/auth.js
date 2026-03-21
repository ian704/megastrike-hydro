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

    // 🔥 THIS IS CRITICAL
    req.user = decoded;

    next();
  } catch (err) {
    console.error('JWT ERROR:', err.message);
    return res.status(403).json({ success: false, error: 'Invalid or expired token' });
  }
}

module.exports = { authenticateToken };