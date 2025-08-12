import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';
import 'dotenv/config';

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      // Get token from header (e.g., "Bearer <token>")
      token = req.headers.authorization.split(' ')[1];

      // Verify the token using the secret key
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Find the user by the ID from the token and attach it to the request object
      // We exclude the password field for security
      req.user = await User.findById(decoded.id).select('-password');

      // 👇 THIS IS THE FIX 👇
      // If the user associated with the token is not found in the database,
      // deny access. This prevents errors in downstream controllers.
      if (!req.user) {
        return res.status(401).json({ message: 'Not authorized, user not found' });
      }

      // Move on to the next middleware or the actual route controller
      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

export { protect };
