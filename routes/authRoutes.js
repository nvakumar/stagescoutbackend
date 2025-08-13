import express from 'express';
import { 
  registerUser, 
  loginUser, // 👈 Corrected import: 'loginUser'
  googleAuth, // 👈 Corrected import: 'googleAuth'
  changePassword, 
  changeEmail,    
  deleteAccount   
} from '../controllers/authController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// --- PUBLIC ROUTES ---

// Handles new user registration with email/password
router.post('/register', registerUser);

// Handles both sign-in and sign-up with a Google account
router.post('/google', googleAuth);

// 👇 THIS IS THE NEW LOGIN ROUTE 👇
// Handles email/password login by verifying a Firebase ID token from the frontend
router.post('/login', loginUser); // 👈 Corrected route handler

// --- PROTECTED ROUTES (require a valid JWT) ---

// Handles changing a user's password
router.put('/change-password', protect, changePassword);

// Handles changing a user's email
router.put('/change-email', protect, changeEmail);

// Handles deleting a user's account
router.delete('/delete-account', protect, deleteAccount);


export default router;
