import express from 'express';
import { 
  getUserProfile, 
  searchUsers,
  followUser,    
  unfollowUser,
  updateUserProfile,
  updateNewUserProfile,
  updateUsername, // 👈 Import the new username controller function
  uploadUserAvatar,
  uploadUserResume,
  uploadUserCoverPhoto
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

// 👇 ADD THIS NEW ROUTE FOR UPDATING THE USERNAME 👇
router.route('/username').put(protect, updateUsername);

// Route to get a user's profile by their ID (publicly accessible)
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
