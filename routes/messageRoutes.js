import express from 'express';
import {
  newConversation,
  getConversations,
  addMessage,
  getMessages,
} from '../controllers/messageController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Route for starting and getting conversations
router.route('/conversations').post(protect, newConversation);
router.route('/conversations').get(protect, getConversations);

// Route for adding a new message
router.route('/').post(protect, addMessage);

// Route for getting messages from a specific conversation
router.route('/:conversationId').get(protect, getMessages);

export default router;
