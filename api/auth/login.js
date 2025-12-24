// api/auth/login.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const router = express.Router();

// Configure Neon PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        require: true,
        rejectUnauthorized: false
    }
});

// JWT secret key (store in environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        // Query the database for user
        const result = await pool.query(
            'SELECT id, user_id, email, name, password_hash FROM users WHERE email = $1 OR user_id = $1',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        const user = result.rows[0];
        
        // Verify password (you need bcrypt installed)
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        // Create JWT token
        const token = jwt.sign(
            { 
                userId: user.id,
                email: user.email,
                user_id: user.user_id
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Remove password from response
        const { password_hash, ...userWithoutPassword } = user;
        
        res.json({
            success: true,
            token: token,
            user: userWithoutPassword
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

module.exports = router;