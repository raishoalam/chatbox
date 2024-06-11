const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const app = express();
const port = 3000;

// MySQL Connection Pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root', // Your MySQL username
  password: 'password', // Your MySQL password
  database: 'my_database' // Your MySQL database name
});

// Middleware for parsing JSON body
app.use(express.json());

// Register a new user
app.post('/api/register', async (req, res) => {
  const { userId, deviceId, name, phone, availCoins, password } = req.body;

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into database
    const [result] = await pool.query(
      'INSERT INTO users (userId, deviceId, name, phone, availCoins, password) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, deviceId, name, phone, availCoins, hashedPassword]
    );

    res.status(201).send('User registered successfully');
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).send('Error registering user');
  }
});

// User login
app.post('/api/login', async (req, res) => {
  const { userId, password } = req.body;

  try {
    // Fetch user from database
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE userId = ?',
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).send('User not found');
    }

    const user = rows[0];

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.userId }, 'secret_key', { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).send('Error logging in');
  }
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.status(401).send('Unauthorized');
  }

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      return res.status(403).send('Invalid token');
    }

    req.user = user;
    next();
  });
}

// Example protected route
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json(req.user);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
