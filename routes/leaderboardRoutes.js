import express from 'express';
import { getLeaderboard } from '../controllers/leaderboardController.js';
import { protect } from '../middleware/authMiddleware.js'; // Protect if you want only logged-in users to see it

const router = express.Router();

// Route to get the leaderboard data
// We'll make this protected for now, as it's part of the authenticated dashboard
router.route('/').get(protect, getLeaderboard);

export default router;
