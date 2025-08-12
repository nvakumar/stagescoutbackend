import Notification from '../models/notificationModel.js';

// @desc    Get all notifications for the logged-in user
// @route   GET /api/notifications
// @access  Private
const getNotifications = async (req, res) => {
  try {
    // Find all notifications where the recipient is the current user
    const notifications = await Notification.find({ recipient: req.user._id })
      .sort({ createdAt: -1 }) // Sort by newest first
      // Populate related data to show useful information on the frontend
      .populate({
        path: 'applicant',
        select: 'fullName role avatar', // Get the applicant's details
      })
      .populate({
        path: 'castingCall',
        select: 'projectTitle roleType', // Get the casting call's details
      });

    res.status(200).json(notifications);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

export { getNotifications };
