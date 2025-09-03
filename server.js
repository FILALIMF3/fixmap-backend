// --- FixMap Backend Server --- FINAL COMPLETE VERSION ---

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

app.use(express.json());
app.use(cors());

cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const upload = multer({ dest: 'uploads/' });

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authorizeRole = (requiredRole) => {
    return (req, res, next) => {
        if (!req.user || req.user.role !== requiredRole) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        next();
    };
};

app.post('/api/upload', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'No image file.' });
        const result = await cloudinary.uploader.upload(req.file.path);
        res.status(200).json({ imageUrl: result.secure_url });
    } catch (error) {
        res.status(500).json({ message: 'Error uploading image.' });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const result = await pool.query('INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, role', [name, email, passwordHash]);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        if (error.code === '23505') return res.status(400).json({ message: 'Email already exists.' });
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'All fields are required.' });
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const payload = { userId: user.id, name: user.name, role: user.role };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token: token });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/reports', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, imageUrl } = req.body;
        const userId = req.user.userId;
        if (!latitude || !longitude || !imageUrl) return res.status(400).json({ message: 'All fields are required.' });
        const result = await pool.query('INSERT INTO reports (user_id, latitude, longitude, image_url) VALUES ($1, $2, $3, $4) RETURNING *;', [userId, latitude, longitude, imageUrl]);
        res.status(201).json({ message: 'Report submitted successfully!', report: result.rows[0] });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/my-reports', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const result = await pool.query('SELECT * FROM reports WHERE user_id = $1 ORDER BY created_at DESC;', [userId]);
        res.status(200).json(result.rows);
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// THIS IS THE ENDPOINT THAT WAS MISSING FROM YOUR LIVE SERVER
app.get('/api/reports/public', authenticateToken, async (req, res) => {
    try {
        const query = `SELECT id, latitude, longitude, status, image_url FROM reports WHERE status = 'Submitted';`;
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (error) {
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});

app.get('/api/reports-all', authenticateToken, authorizeRole('municipal_official'), async (req, res) => {
    try {
        const query = `SELECT r.*, u.name as citizen_name, u.email as citizen_email FROM reports r JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC;`;
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.patch('/api/reports/:id', authenticateToken, authorizeRole('municipal_official'), async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const { status } = req.body;
        if (!status) return res.status(400).json({ message: 'Status is required.' });
        const result = await pool.query('UPDATE reports SET status = $1 WHERE id = $2 RETURNING *;', [status, id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Report not found.' });
        res.status(200).json({ message: 'Report updated.', report: result.rows[0] });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`FixMap server is running on port ${PORT}`);
});