import User from '../models/userModel.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import 'dotenv/config';
import { sendVerificationEmail } from '../config/email.js';
import admin from 'firebase-admin';

// --- Firebase Admin SDK Setup ---
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const serviceAccount = require('../firebase-adminsdk.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
// ---------------------------------

// Helper function to generate a unique username
const generateUniqueUsername = async (fullName) => {
  let username = fullName.toLowerCase().replace(/\s+/g, '').replace(/[^a-z0-9]/gi, '');
  if (username.length < 3) {
    username = `user${Math.floor(1000 + Math.random() * 9000)}`;
  }
  let existingUser = await User.findOne({ username });
  let attempts = 0;
  while (existingUser && attempts < 5) {
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const newUsername = `${username}${randomSuffix}`;
    existingUser = await User.findOne({ username: newUsername });
    if (!existingUser) {
      username = newUsername;
      break;
    }
    attempts++;
  }
  if (existingUser) {
      username = `user${Date.now()}`;
  }
  return username;
};


// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
export const registerUser = async (req, res) => {
  // Now correctly accepts 'username' from the frontend form
  const { fullName, username, email, password, role, location } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const usernameExists = await User.findOne({ username });
    if (usernameExists) {
        return res.status(400).json({ message: 'Username is already taken.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      fullName,
      username, // Saves the username from the form
      email,
      role,
      location,
      password: hashedPassword,
      isVerified: false,
    });

    if (user) {
      await admin.auth().createUser({
        uid: user._id.toString(),
        email: user.email,
        password: password,
        emailVerified: false,
        displayName: user.fullName,
      });

      const verificationLink = await admin.auth().generateEmailVerificationLink(email);
      sendVerificationEmail(email, verificationLink);

      res.status(201).json({
        message: 'Registration successful! Please check your email to verify your account.'
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    console.error("Error during registration:", error);
    await User.deleteOne({ email });
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Verify Firebase ID token and log user in
// @route   POST /api/auth/verify-token
// @access  Public
export const verifyToken = async (req, res) => {
  const { idToken } = req.body;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const user = await User.findById(decodedToken.uid);

    if (!user) {
      return res.status(404).json({ message: "User not found in our database." });
    }

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      role: user.role,
      profilePictureUrl: user.profilePictureUrl,
      location: user.location,
      token: generateToken(user._id),
    });

  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(401).json({ message: 'Authentication failed. Invalid token.' });
  }
};


// @desc    Google Sign-In/Up
// @route   POST /api/auth/google
// @access  Public
export const googleAuth = async (req, res) => {
  const { idToken } = req.body;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name } = decodedToken; 

    let user = await User.findOne({ email });
    let isNewUser = false;

    if (!user) {
      isNewUser = true;
      // 👇 THIS IS THE FIX 👇
      // Generate a unique username for the new Google user.
      const username = await generateUniqueUsername(name);
      
      user = await User.create({
        fullName: name,
        username: username, // 👈 Save the new username
        email: email,
        role: 'Creator',
        isVerified: true,
      });
    }
    
    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      role: user.role,
      location: user.location,
      profilePictureUrl: user.profilePictureUrl,
      token: generateToken(user._id),
      isNewUser: isNewUser,
    });

  } catch (error) {
    console.error("Error during Google Auth:", error);
    res.status(401).json({ message: 'Google authentication failed. Invalid token.' });
  }
};

// @desc    Change user password
// @route   PUT /api/auth/change-password
// @access  Private
export const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user._id;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (user.password && !(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();
    
    await admin.auth().updateUser(userId.toString(), {
      password: newPassword
    });

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Change user email
// @route   PUT /api/auth/change-email
// @access  Private
export const changeEmail = async (req, res) => {
  const { newEmail, password } = req.body;
  const userId = req.user._id;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.password || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Password is incorrect' });
    }

    const emailExists = await User.findOne({ email: newEmail });
    if (emailExists && emailExists._id.toString() !== userId.toString()) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    user.email = newEmail;
    await user.save();
    
    await admin.auth().updateUser(userId.toString(), {
      email: newEmail
    });

    res.status(200).json({ message: 'Email updated successfully', newEmail: user.email });
  } catch (error) {
    console.error("Error changing email:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Delete user account
// @route   DELETE /api/auth/delete-account
// @access  Private
export const deleteAccount = async (req, res) => {
  const { password } = req.body;
  const userId = req.user._id;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.password && !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Password is incorrect' });
    }
    
    await admin.auth().deleteUser(userId.toString());
    await user.deleteOne();

    res.status(200).json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};


// Helper function to generate a JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};
