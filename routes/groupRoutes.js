import express from 'express';
import multer from 'multer';
import { groupCoverStorage } from '../config/cloudinary.js'; // 👈 Import groupCoverStorage
import {
  createGroup,
  getAllGroups,
  getGroupDetails,
  joinGroup,
  leaveGroup,
  updateGroupCover,
  removeMember,
  deleteGroup,
} from '../controllers/groupController.js';
import { getGroupPosts } from '../controllers/postController.js';
import { protect } from '../middleware/authMiddleware.js';

// Set up multer with the specific group cover storage
const uploadGroupCover = multer({ storage: groupCoverStorage }); // 👈 Use groupCoverStorage here

const router = express.Router();

// Routes for getting all groups and creating a new one
router.route('/').get(protect, getAllGroups).post(protect, createGroup);

// Routes for a specific group (GET details, DELETE group)
router.route('/:id').get(protect, getGroupDetails).delete(protect, deleteGroup);

// Routes for group actions
router.route('/:id/join').post(protect, joinGroup);
router.route('/:id/leave').post(protect, leaveGroup);
router.route('/:id/posts').get(protect, getGroupPosts);
router.route('/:id/cover').put(protect, uploadGroupCover.single('coverImage'), updateGroupCover); // 👈 Use uploadGroupCover
router.route('/:id/remove-member').post(protect, removeMember);

export default router;
