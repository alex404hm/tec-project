// Improved version of the given Express.js app

import express from 'express';
import path from 'path';
import cors from 'cors';
import morgan from 'morgan';
import compression from 'compression';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'url';
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

dotenv.config();

const requiredEnvVars = [
  'BASE_URL', 'MONGODB_URI', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_APP_PASSWORD',
  'SESSION_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'
];
requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});

process.env.BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Improved MongoDB connection with proper error handling
(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
})();

// Define user schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String },
  sessionID: { type: String },
  isVerified: { type: Boolean, default: false },
  lastLogin: { type: Date },
  role: { type: String, default: 'user' }, // Added role field to differentiate users and admins
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Utility functions
const generateToken = (user) => jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
const generateSessionID = () => crypto.randomBytes(16).toString('hex');

// Configure email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD
  }
});

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.CORS_ORIGIN || process.env.BASE_URL,
  credentials: true
}));
app.use(morgan(process.env.LOG_FORMAT || 'combined'));
app.use(compression());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth setup
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.BASE_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = await User.create({
        googleId: profile.id,
        email: profile.emails[0].value,
        isVerified: true,
        role: 'user'
      });
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Rate limiter for authentication routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many attempts, please try again later.'
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
  if (!token) {
    return res.redirect('/auth/login');
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.redirect('/auth/login');
    }
    req.user = decodedUser;
    next();
  });
};

const redirectIfAuthenticated = (req, res, next) => {
  const token = req.cookies.token || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err) => {
      if (!err) {
        return res.redirect('/dashboard');
      }
    });
  }
  next();
};

// Middleware to check if user is admin
const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.token || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
  if (!token) {
    return res.redirect('/admin/login');
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      return res.redirect('/admin/login');
    }
    req.user = decodedUser;
    next();
  });
};

// Define static routes with optional authentication redirection
const definedRoutes = [
  { route: '/auth/login', file: 'auth/login.html', redirectIfAuthenticated: true },
  { route: '/auth/signup', file: 'auth/signup.html', redirectIfAuthenticated: true },
  { route: '/', file: 'index.html' },
  { route: '/admin/login', file: 'admin/login.html', redirectIfAuthenticated: true }
];

definedRoutes.forEach(({ route, file, redirectIfAuthenticated: redirectIfAuth }) => {
  if (redirectIfAuth) {
    app.get(route, redirectIfAuthenticated, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  } else {
    app.get(route, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  }
});

// Additional routes for public pages
app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'dashboard.html'));
});

app.get('/find', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'find.html'));
});

app.get('/profile', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'profile.html'));
});

// Authentication routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/auth/login' }), (req, res) => {
  const token = generateToken(req.user);
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  });
  res.redirect('/dashboard');
});

// User registration endpoint
app.post('/api/signup', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.password) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10);
    const sessionID = generateSessionID();

    let user;
    if (existingUser) {
      existingUser.password = hashedPassword;
      existingUser.sessionID = sessionID;
      user = await existingUser.save();
    } else {
      user = new User({ email, password: hashedPassword, sessionID, role: 'user' });
      await user.save();
    }

    const verifyToken = generateToken(user);
    const verifyLink = `${process.env.BASE_URL}/api/verify-email?token=${verifyToken}`;
    const verifyMailOptions = {
      from: `"No Reply" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Verify Your Email',
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Verify Your Email</h2>
          <p>Please click the link below to verify your email address and activate your account:</p>
          <a href="${verifyLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
          <p>If you did not sign up for this account, you can ignore this email.</p>
        </div>
      `
    };
    await transporter.sendMail(verifyMailOptions);

    res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// Verification email endpoint
app.post('/api/send-verification-email', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'User is already verified' });
    }

    const verifyToken = generateToken(user);
    const verifyLink = `${process.env.BASE_URL}/api/verify-email?token=${verifyToken}`;

    const mailOptions = {
      from: `"No Reply" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Verify Your Email',
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Verify Your Email</h2>
          <p>Please click the link below to verify your email address and activate your account:</p>
          <a href="${verifyLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
          <p>If you did not sign up for this account, you can ignore this email.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Verification email sent successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error. Could not send verification email.' });
  }
});

// Email verification endpoint
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ error: 'Invalid verification link' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.redirect('/dashboard');
    }

    user.isVerified = true;
    await user.save();
    res.sendFile(path.join(__dirname, 'public', 'auth', 'verified.html'));
  } catch (error) {
    res.status(500).json({ error: 'Server error. Could not verify email.' });
  }
});

// Logout endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.status(200).json({ message: 'Logout successful' });
});

// Login endpoint
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !user.password) {
      return res.status(404).json({ error: 'User does not exist. Please sign up.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);
    const sessionID = generateSessionID();
    user.sessionID = sessionID;
    user.lastLogin = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: 'Login successful',
      userInfo: {
        email: user.email,
        lastLogin: user.lastLogin,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    });
  } catch (err) {
    console.error('Error logging in user:', err);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// Admin route
app.get('/admin', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user.isVerified) {
      return res.redirect('/verify');
    }
    res.sendFile(path.join(__dirname, 'public', 'admin', 'admin.html'));
  } catch (err) {
    res.redirect('/admin/login');
  }
});

// Error handling for missing routes
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
});

// General error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
