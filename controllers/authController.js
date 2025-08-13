import User from '../models/userModel.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import 'dotenv/config';
import { sendVerificationEmail } from '../config/email.js';
import admin from 'firebase-admin';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const serviceAccount = require('../firebase-adminsdk.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
export const registerUser = async (req, res) => {
  const { fullName, username, email, password, role, location } = req.body;

  try {
    let userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists with this email.' });
    }
    userExists = await User.findOne({ username });
    if (userExists) {
        return res.status(400).json({ message: 'This username is already taken.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      fullName,
      username,
      email,
      role,
      location,
      password: hashedPassword,
      isVerified: false,
      isNewUser: false, // They have completed the form, so they are not "new" in the context of needing to complete a profile.
    });

    if (user) {
      await admin.auth().createUser({
        uid: user._id.toString(),
        email: user.email,
        password,
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

// @desc    Authenticate a user
// @route   POST /api/auth/login
// @access  Public
export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    let firebaseUser;
    try {
      firebaseUser = await admin.auth().getUser(user._id.toString());
    } catch (fbErr) {
      if (fbErr.code === 'auth/user-not-found') {
        return res.status(400).json({ message: 'User not found in authentication system.' });
      }
      throw fbErr;
    }

    if (!firebaseUser.emailVerified) {
      return res.status(401).json({ message: 'Please verify your email address to log in.' });
    }

    let passwordMatches = false;
    if (user.password) {
      passwordMatches = await bcrypt.compare(password, user.password);
    }

    if (!passwordMatches) {
      try {
        await admin.auth().verifyIdToken(
          (await admin.auth().createCustomToken(firebaseUser.uid)).toString()
        );
      } catch {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();
    }

    const needsProfileCompletion = !user.username;

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
      profilePictureUrl: user.profilePictureUrl,
      location: user.location,
      token: generateToken(user._id),
      needsProfileCompletion,
    });

  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Google Sign-In/Up
// @route   POST /api/auth/google
// @access  Public
export const googleAuth = async (req, res) => {
  const { idToken } = req.body;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture, uid } = decodedToken;

    let user = await User.findOne({ email });
    let isNewUser = false;

    if (!user) {
      isNewUser = true;
      const tempUsername = `user_${uid.substring(0, 12)}`;

      user = await User.create({
        fullName: name,
        email,
        username: tempUsername,
        role: 'Creator',
        isVerified: true,
        // ** THIS IS THE FIX **
        // The 'picture' variable from Google is no longer used.
        // It will now always use the default placeholder defined in your userModel.
        profilePictureUrl: 'https://placehold.co/150x150/1a202c/ffffff?text=Avatar',
        isNewUser: true,
      });

      // Ensure a Firebase Auth user exists with the correct UID from the token
      try {
        await admin.auth().getUser(uid);
      } catch (error) {
        if (error.code === 'auth/user-not-found') {
          await admin.auth().createUser({
            uid: uid,
            email: email,
            displayName: name,
            photoURL: picture,
            emailVerified: true,
          });
        } else {
          throw error;
        }
      }
    }

    const needsProfileCompletion = isNewUser;

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
      location: user.location,
      profilePictureUrl: user.profilePictureUrl,
      token: generateToken(user._id),
      needsProfileCompletion,
    });

  } catch (error) {
    console.error("Error during Google Auth:", error);
    if (error.code && error.code.startsWith('auth/')) {
      return res.status(401).json({ message: 'Google authentication failed. Invalid token.' });
    }
    res.status(500).json({ message: 'Server Error during Google authentication.', error: error.message });
  }
};

// @desc    Verify user token and get user data
// @route   POST /api/auth/verify-token
// @access  Public (but requires a token)
export const verifyToken = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const needsProfileCompletion = user.isNewUser;

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      role: user.role,
      location: user.location,
      profilePictureUrl: user.profilePictureUrl,
      token: token,
      needsProfileCompletion,
    });

  } catch (error) {
    res.status(401).json({ message: 'Token is not valid or has expired' });
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

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};
