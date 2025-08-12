import express from 'express';
import { 
  createCastingCall, 
  getCastingCalls, 
  applyToCastingCall,
  getNotifications // 👈 Import the new getNotifications function
} from '../controllers/castingCallController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Define the routes for getting all casting calls and creating a new one
router
  .route('/')
  .get(protect, getCastingCalls)
  .post(protect, createCastingCall);

// Define the route for applying to a casting call
router.route('/:id/apply').post(protect, applyToCastingCall);

// Define the route for fetching notifications for the logged-in user
router.route('/notifications').get(protect, getNotifications); // 👈 Add the new notifications route

export default router;
