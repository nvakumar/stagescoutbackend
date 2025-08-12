import CastingCall from '../models/castingCallModel.js';
import Notification from '../models/notificationModel.js';
import User from '../models/userModel.js'; // Import User model to populate applicant details

// @desc    Create a new casting call
// @route   POST /api/casting-calls
// @access  Private
const createCastingCall = async (req, res) => {
  try {
    const allowedRoles = ['Director', 'Filmmaker', 'Production House'];
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'You are not authorized to post casting calls.' });
    }

    const newCastingCall = new CastingCall({
      ...req.body,
      user: req.user._id,
    });

    const createdCastingCall = await newCastingCall.save();
    res.status(201).json(createdCastingCall);
  } catch (error) {
    res.status(400).json({ message: 'Failed to create casting call', error: error.message });
  }
};

// @desc    Get all active casting calls
// @route   GET /api/casting-calls
// @access  Private
const getCastingCalls = async (req, res) => {
  try {
    const castingCalls = await CastingCall.find({ isActive: true })
      .populate('user', 'fullName role')
      .sort({ createdAt: -1 });
      
    res.status(200).json(castingCalls);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Apply to a casting call
// @route   POST /api/casting-calls/:id/apply
// @access  Private
const applyToCastingCall = async (req, res) => {
    try {
        const castingCall = await CastingCall.findById(req.params.id);

        if (!castingCall) {
            return res.status(404).json({ message: 'Casting call not found' });
        }

        // Check if the user has already applied to this casting call
        const existingApplication = await Notification.findOne({
            applicant: req.user._id,
            castingCall: castingCall._id,
        });

        if (existingApplication) {
            return res.status(400).json({ message: 'You have already applied to this casting call.' });
        }

        // Create a new notification for the casting call owner
        await Notification.create({
            applicant: req.user._id,
            recipient: castingCall.user, // The user who posted the call
            castingCall: castingCall._id,
            type: 'application',
        });

        res.status(201).json({ message: 'Application submitted successfully' });

    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Get notifications for the logged-in user (e.g., applications received)
// @route   GET /api/notifications
// @access  Private
const getNotifications = async (req, res) => {
  try {
    // Find notifications where the logged-in user is the recipient
    const notifications = await Notification.find({ recipient: req.user._id })
      .populate('applicant', 'fullName role avatar') // Populate applicant's details
      .populate('castingCall', 'projectTitle projectType roleType') // Populate casting call details
      .sort({ createdAt: -1 }); // Sort by newest first

    res.status(200).json(notifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

export { createCastingCall, getCastingCalls, applyToCastingCall, getNotifications };
