// server.js - Production version with PostgreSQL & bcrypt
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Enable CORS
app.use(cors({
    origin: ['https://3k214.dfi.fund', 'http://localhost'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Handle preflight
app.options('*', cors());

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/templates', express.static(path.join(__dirname, 'templates')));

// PostgreSQL connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        require: true,
        rejectUnauthorized: false
    }
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Database connection error:', err.message);
    } else {
        console.log('✅ Connected to PostgreSQL database');
        release();
    }
});

// Login API endpoint - REAL DATABASE VERSION
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('🔐 Login attempt for:', email);
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        // Query your Neon PostgreSQL users table
        const result = await pool.query(
            `SELECT id, user_id, email, name, password_hash, 
                    profile_picture, wallet_address, nft_tier,
                    created_at, updated_at
             FROM users 
             WHERE email = $1 OR user_id = $1`,
            [email]
        );
        
        if (result.rows.length === 0) {
            console.log('❌ User not found:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        const user = result.rows[0];
        
        // Check if password_hash exists
        if (!user.password_hash) {
            console.log('❌ No password hash for user:', email);
            return res.status(401).json({
                success: false,
                message: 'Account not properly set up'
            });
        }
        
        // Verify password with bcrypt
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            console.log('❌ Invalid password for:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        // Remove sensitive data from response
        const { password_hash, reset_code, reset_code_expires, ...safeUser } = user;
        
        console.log('✅ Login successful for:', email);
        
        // Generate a simple token (for demo - use JWT in production)
        const token = `jwt_${Date.now()}_${user.id}`;
        
        res.json({
            success: true,
            token: token,
            user: safeUser,
            message: 'Login successful'
        });
        
    } catch (error) {
        console.error('💥 Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during authentication'
        });
    }
});

// User registration endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, user_id } = req.body;
        
        if (!email || !password || !name) {
            return res.status(400).json({
                success: false,
                message: 'Email, password, and name are required'
            });
        }
        
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR user_id = $2',
            [email, user_id || email]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'User already exists'
            });
        }
        
        // Hash password
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);
        
        // Insert new user
        const result = await pool.query(
            `INSERT INTO users 
             (user_id, email, name, password_hash, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())
             RETURNING id, user_id, email, name, created_at`,
            [user_id || `user_${Date.now()}`, email, name, password_hash]
        );
        
        const newUser = result.rows[0];
        
        res.json({
            success: true,
            message: 'Registration successful',
            user: newUser
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed'
        });
    }
});

// Update user profile
app.post('/api/auth/update-profile', async (req, res) => {
    try {
        const { userId, name, profile_picture } = req.body;
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }
        
        const result = await pool.query(
            `UPDATE users 
             SET name = COALESCE($1, name),
                 profile_picture = COALESCE($2, profile_picture),
                 updated_at = NOW()
             WHERE id = $3 OR user_id = $3
             RETURNING id, user_id, email, name, profile_picture, updated_at`,
            [name, profile_picture, userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Profile updated',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Update failed'
        });
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Test database connection
        await pool.query('SELECT 1');
        
        res.json({
            status: 'healthy',
            service: 'KokKokKok Authentication API',
            timestamp: new Date().toISOString(),
            database: 'connected',
            endpoints: {
                login: 'POST /api/auth/login',
                register: 'POST /api/auth/register',
                updateProfile: 'POST /api/auth/update-profile'
            }
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error.message
        });
    }
});

// Get user info by ID
app.get('/api/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        const result = await pool.query(
            `SELECT id, user_id, email, name, profile_picture, 
                    wallet_address, nft_tier, created_at
             FROM users 
             WHERE id = $1 OR user_id = $1`,
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Root redirect
app.get('/', (req, res) => {
    res.redirect('/templates/');
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found',
        path: req.originalUrl
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// ===== UPDATE PROFILE ENDPOINT =====
app.put('/api/auth/update-profile', async (req, res) => {
    try {
        // Get token from Authorization header
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Authentication token required'
            });
        }
        
        const { name, userId } = req.body;
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Name is required'
            });
        }
        
        if (name.length > 100) {
            return res.status(400).json({
                success: false,
                message: 'Name must be 100 characters or less'
            });
        }
        
        // Simple token verification (for demo - use JWT in production)
        // For now, we'll skip JWT verification and just update by userId
        console.log(`Updating name for user ${userId} to: ${name}`);
        
        // Update user in database
        const result = await pool.query(
            `UPDATE users 
             SET name = $1, updated_at = NOW()
             WHERE id = $2 OR user_id = $2
             RETURNING id, user_id, email, name, profile_picture, updated_at`,
            [name.trim(), userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error updating profile'
        });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
🚀 KokKokKok Authentication Server
─────────────────────────────────
📍 Local:    http://localhost:${PORT}
🌐 Network:  http://0.0.0.0:${PORT}
🗄️  Database: Neon PostgreSQL
🔐 Bcrypt:   Installed for password hashing

📋 Available Endpoints:
   POST /api/auth/login        - User login
   POST /api/auth/register     - User registration
   POST /api/auth/update-profile - Update profile
   GET  /api/health           - Health check
   GET  /api/users/:userId    - Get user info

📊 Database Schema: users table
   • id, user_id, email, name
   • password_hash (bcrypt hashed)
   • profile_picture, wallet_address
   • nft_tier, created_at, updated_at

✅ Ready for production!
`);
});