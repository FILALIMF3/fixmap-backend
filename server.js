// --- FixMap Backend Server --- FINAL SECURE VERSION ---

// Load environment variables from .env file
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

// Configure Cloudinary with environment variables
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const upload = multer({ dest: 'uploads/' });

// Configure Database Connection with environment variables
const pool = new Pool({
    connectionString: DATABASE_URL,
    // SSL is required for Render, but might cause issues on some local setups
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ... (The rest of your server.js file remains exactly the same) ...

// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`FixMap server is running on port ${PORT}`);
});