import express from 'express';
import { getNotifications } from '../controllers/notificationController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Define the route for getting all notifications for the logged-in user
router.route('/').get(protect, getNotifications);

export default router;
