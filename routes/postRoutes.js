import express from 'express';
import { 
  createPost, 
  getPosts, 
  likePost, 
  addComment,
  deleteComment,
  reactToPost, 
  deletePost, 
  updatePost,
  upload,
  getGroupPosts // This is included for completeness
} from '../controllers/postController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Route to get all posts and create a new post (with file upload)
router
  .route('/')
  .get(protect, getPosts)
  .post(protect, upload.single('file'), createPost);

// Routes for a specific post by ID (update and delete)
router
  .route('/:id')
  .put(protect, updatePost)
  .delete(protect, deletePost);

// Route to like/unlike a post
router.route('/:id/like').put(protect, likePost);

// Route to add a comment to a post
router.route('/:id/comment').post(protect, addComment);

// Route to react to a post with an emoji
router.route('/:id/react').post(protect, reactToPost);

// Route to delete a comment
router.route('/:postId/comment/:commentId').delete(protect, deleteComment);

// Note: The getGroupPosts route is typically handled in groupRoutes.js
// to follow a clean RESTful pattern, like GET /api/groups/:id/posts.
// router.route('/group/:id/posts').get(protect, getGroupPosts); 

export default router;
