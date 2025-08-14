import express from 'express';
import { 
  getUserProfile, 
  searchUsers,
  followUser,    
  unfollowUser,
  updateUserProfile,
  updateNewUserProfile,
  updateUsername,
  uploadUserAvatar,
  uploadUserResume,
  uploadUserCoverPhoto,
  getUsersByIds // 👈 IMPORT the new controller function
} from '../controllers/userController.js';
import { protect } from '../middleware/authMiddleware.js';
import multer from 'multer';
import { avatarStorage, resumeStorage, coverPhotoStorage } from '../config/cloudinary.js';

// Set up multer instances for routes
const uploadAvatarMiddleware = multer({ storage: avatarStorage });
const uploadResumeMiddleware = multer({ storage: resumeStorage });
const uploadCoverMiddleware = multer({ storage: coverPhotoStorage });


const router = express.Router();

// --- USER PROFILE & SEARCH ROUTES ---

// Route for searching users
router.route('/search').get(protect, searchUsers);

// Route to update a user's full profile
router.route('/me').put(protect, updateUserProfile); 

// Route to update a new user's profile after Google Sign-Up
router.route('/profile').put(protect, updateNewUserProfile);

// Route for updating the username
router.route('/username').put(protect, updateUsername);

// 👇 THIS IS THE NEW, REQUIRED ROUTE 👇
// Handles fetching multiple users' data in a single request for follower/following lists.
router.route('/bulk').post(protect, getUsersByIds);

// Route to get a user's profile by their ID (must be last to avoid conflicts with other routes)
router.route('/:id').get(getUserProfile); 

// --- FOLLOW / UNFOLLOW ROUTES ---

// Route to follow a user
router.route('/:id/follow').post(protect, followUser); 

// Route to unfollow a user
router.route('/:id/follow').delete(protect, unfollowUser); 

// --- FILE UPLOAD ROUTES ---

// Route to upload user avatar
router.route('/upload/avatar').post(protect, uploadAvatarMiddleware.single('avatar'), uploadUserAvatar);

// Route to upload user resume
router.route('/upload/resume').post(protect, uploadResumeMiddleware.single('resume'), uploadUserResume);

// Route for uploading cover photos
router.route('/upload/cover').post(protect, uploadCoverMiddleware.single('cover'), uploadUserCoverPhoto);


export default router;
