const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    // Get token from header or query parameter
    let token = req.header('Authorization')?.replace('Bearer ', '');
    
    // Alternative: Get token from query parameter (for specific use cases)
    if (!token && req.query.token) {
      token = req.query.token;
    }

    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Access denied. No token provided.' 
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_fallback_jwt_secret');
    
    // Find user and exclude password
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Token is not valid - user not found' 
      });
    }

    // Check if user account is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated. Please contact support.'
      });
    }

    // Attach user to request
    req.user = user;
    req.token = token;
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);

    // Handle specific JWT errors
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid token' 
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        message: 'Token has expired' 
      });
    }

    res.status(401).json({ 
      success: false,
      message: 'Authentication failed' 
    });
  }
};

// Optional: Admin middleware (extends auth)
const adminAuth = async (req, res, next) => {
  try {
    // First run regular auth
    await auth(req, res, () => {});

    // Check if user is admin
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Admin privileges required.'
      });
    }

    next();
  } catch (error) {
    console.error('Admin auth middleware error:', error);
    res.status(403).json({
      success: false,
      message: 'Admin authentication failed'
    });
  }
};

// Optional: Optional auth middleware (doesn't fail if no token, just doesn't set user)
const optionalAuth = async (req, res, next) => {
  try {
    let token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token && req.query.token) {
      token = req.query.token;
    }

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_fallback_jwt_secret');
      const user = await User.findById(decoded.id).select('-password');
      
      if (user && user.isActive) {
        req.user = user;
        req.token = token;
      }
    }

    next();
  } catch (error) {
    // For optional auth, we don't block the request on token errors
    // Just continue without setting user
    next();
  }
};

// Export all middleware functions
module.exports = {
  auth,
  adminAuth,
  optionalAuth
};
