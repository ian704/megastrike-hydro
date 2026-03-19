const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const pool = require('../db');

router.post('/', authenticateToken, async (req, res) => {
    try {
        const { name, phone, email, service, details } = req.body;
        if (!name || !phone || !service) {
            return res.status(400).json({ success: false, error: 'Name, phone, and service are required' });
        }

        const [result] = await pool.execute(
            `INSERT INTO consultations 
            (name, phone, email, service, details, status, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, 'pending', NOW(), ?)`,
            [name, phone, email || '', service, details || '', req.user.userId]
        );

        res.status(201).json({
            success: true,
            message: 'Consultation request received',
            data: { id: result.insertId, name, phone, email, service, details, status: 'pending', created_at: new Date().toISOString(), user_id: req.user.userId }
        });
    } catch (error) {
        console.error('❌ Error creating consultation:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

module.exports = router;