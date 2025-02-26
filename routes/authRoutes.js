const express = require('express');
const { 
  register, 
  login, 
  refreshToken, 
  logout, 
  forgotPassword, 
  resetPassword 
} = require('../controllers/authController');

const router = express.Router();

// Register route
router.post('/register', register);

// Login route
router.post('/login', login);

// Refresh token route
router.post('/refresh-token', refreshToken);

// Logout route
router.post('/logout', logout);

// Forgot Password route
router.post('/forgot-password', forgotPassword);

// Reset Password route
router.post('/reset-password', resetPassword);

module.exports = router;
