import User from '../models/userModel.js';
import Post from '../models/postModel.js';

// @desc    Get user profile by ID
// @route   GET /api/users/:id
// @access  Public
const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('fullName username email role bio skills profilePictureUrl resumeUrl followers following location coverPhotoUrl');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const posts = await Post.find({ user: req.params.id })
      .sort({ createdAt: -1 })
      .populate('user', 'fullName role avatar');

    res.status(200).json({
      user,
      posts,
    });

  } catch (error) {
    if (error.kind === 'ObjectId') {
        return res.status(404).json({ message: 'User not found' });
    }
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Search for users by name or role
// @route   GET /api/users/search?q=query&role=roleFilter&location=locationFilter
// @access  Private
const searchUsers = async (req, res) => {
    const query = req.query.q;
    const roleFilter = req.query.role;
    const locationFilter = req.query.location;

    if (!query && (!roleFilter || roleFilter === 'All Roles') && !locationFilter) {
        return res.status(400).json({ message: 'Search query or specific filters are required' });
    }

    try {
        let findQuery = {};

        if (query) {
            const searchQuery = new RegExp(query, 'i');
            findQuery.$or = [
                { fullName: searchQuery },
                { role: searchQuery }
            ];
        }

        if (roleFilter && roleFilter !== 'All Roles') {
            findQuery.role = roleFilter;
        }

        if (locationFilter) {
            findQuery.location = new RegExp(locationFilter, 'i');
        }

        const users = await User.find(findQuery)
                                .select('fullName role profilePictureUrl location')
                                .sort({ fullName: 1 });

        res.status(200).json(users);

    } catch (error) {
        console.error("Error searching users:", error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Follow a user
// @route   POST /api/users/:id/follow
// @access  Private
const followUser = async (req, res) => {
  try {
    const userToFollowId = req.params.id;
    const currentUserId = req.user._id;

    if (userToFollowId.toString() === currentUserId.toString()) {
      return res.status(400).json({ message: 'You cannot follow yourself' });
    }

    const userToFollow = await User.findById(userToFollowId);
    if (!userToFollow) {
      return res.status(404).json({ message: 'User to follow not found' });
    }

    const currentUser = await User.findById(currentUserId);

    if (currentUser.following.includes(userToFollowId)) {
      return res.status(400).json({ message: 'You are already following this user' });
    }

    currentUser.following.push(userToFollowId);
    await currentUser.save();

    userToFollow.followers.push(currentUserId);
    await userToFollow.save();

    res.status(200).json({ message: 'User followed successfully', followersCount: userToFollow.followers.length });

  } catch (error) {
    console.error("Error following user:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Unfollow a user
// @route   DELETE /api/users/:id/follow
// @access  Private
const unfollowUser = async (req, res) => {
  try {
    const userToUnfollowId = req.params.id;
    const currentUserId = req.user._id;

    const userToUnfollow = await User.findById(userToUnfollowId);
    if (!userToUnfollow) {
      return res.status(404).json({ message: 'User to unfollow not found' });
    }

    const currentUser = await User.findById(currentUserId);

    if (!currentUser.following.includes(userToUnfollowId)) {
      return res.status(400).json({ message: 'You are not following this user' });
    }

    currentUser.following = currentUser.following.filter(
      (id) => id.toString() !== userToUnfollowId.toString()
    );
    await currentUser.save();

    userToUnfollow.followers = userToUnfollow.followers.filter(
      (id) => id.toString() !== currentUserId.toString()
    );
    await userToUnfollow.save();

    res.status(200).json({ message: 'User unfollowed successfully', followersCount: userToUnfollow.followers.length });

  } catch (error) {
    console.error("Error unfollowing user:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Update user's full profile (excluding username)
// @route   PUT /api/users/me
// @access  Private
const updateUserProfile = async (req, res) => {
  try {
    const userId = req.user._id;
    const { fullName, bio, skills, profilePictureUrl, resumeUrl, location, coverPhotoUrl } = req.body;

    const user = await User.findById(userId);

    if (user) {
      user.fullName = fullName !== undefined ? fullName : user.fullName;
      user.bio = bio !== undefined ? bio : user.bio;
      user.skills = skills !== undefined ? skills : user.skills;
      user.profilePictureUrl = profilePictureUrl !== undefined ? profilePictureUrl : user.profilePictureUrl;
      user.resumeUrl = resumeUrl !== undefined ? resumeUrl : user.resumeUrl;
      user.location = location !== undefined ? location : user.location;
      user.coverPhotoUrl = coverPhotoUrl !== undefined ? coverPhotoUrl : user.coverPhotoUrl;

      const updatedUser = await user.save();

      res.status(200).json(updatedUser);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};


// @desc    Update a new user's profile after Google Sign-Up
// @route   PUT /api/users/profile
// @access  Private
const updateNewUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (user) {
      const { role, location, username } = req.body;

      if (username) {
        const usernameExists = await User.findOne({ username });
        if (usernameExists && usernameExists._id.toString() !== user._id.toString()) {
          return res.status(400).json({ message: 'Username is already taken.' });
        }
        user.username = username;
      }
      
      user.role = role || user.role;
      user.location = location || user.location;

      const updatedUser = await user.save();

      res.status(200).json({
        _id: updatedUser._id,
        fullName: updatedUser.fullName,
        email: updatedUser.email,
        username: updatedUser.username,
        role: updatedUser.role,
        location: updatedUser.location,
        profilePictureUrl: updatedUser.profilePictureUrl,
      });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error("Error updating new user profile:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Update username
// @route   PUT /api/users/username
// @access  Private
const updateUsername = async (req, res) => {
  const { username } = req.body;
  const userId = req.user._id;

  try {
    if (!username || username.length < 3) {
      return res.status(400).json({ message: 'Username must be at least 3 characters long.' });
    }
    if (!/^[a-z0-9_]+$/.test(username)) {
        return res.status(400).json({ message: 'Username can only contain lowercase letters, numbers, and underscores.' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser && existingUser._id.toString() !== userId.toString()) {
      return res.status(400).json({ message: 'Username is already taken.' });
    }

    const user = await User.findById(userId);

    if (user.usernameLastChanged) {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      if (user.usernameLastChanged > thirtyDaysAgo) {
        return res.status(400).json({ message: 'You can only change your username once every 30 days.' });
      }
    }

    user.username = username;
    user.usernameLastChanged = new Date();
    await user.save();

    res.status(200).json({ message: 'Username updated successfully', username: user.username });

  } catch (error) {
    console.error("Error updating username:", error);
    res.status(500).json({ message: 'Server Error' });
  }
};


// @desc    Upload user avatar
// @route   POST /api/users/upload/avatar
// @access  Private
const uploadUserAvatar = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const userId = req.user._id;
    const user = await User.findById(userId);

    if (user) {
      user.profilePictureUrl = req.file.path;
      await user.save();
      res.status(200).json({ message: 'Avatar uploaded successfully', profilePictureUrl: user.profilePictureUrl });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error("Error uploading avatar:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Upload user resume
// @route   POST /api/users/upload/resume
// @access  Private
const uploadUserResume = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const userId = req.user._id;
    const user = await User.findById(userId);

    if (user) {
      user.resumeUrl = req.file.path;
      await user.save();
      res.status(200).json({ message: 'Resume uploaded successfully', resumeUrl: user.resumeUrl });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error("Error uploading resume:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Upload user cover photo
// @route   POST /api/users/upload/cover
// @access  Private
const uploadUserCoverPhoto = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const userId = req.user._id;
    const user = await User.findById(userId);

    if (user) {
      user.coverPhotoUrl = req.file.path;
      await user.save();
      res.status(200).json({ message: 'Cover photo uploaded successfully', coverPhotoUrl: user.coverPhotoUrl });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error("Error uploading cover photo:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Get multiple users by their IDs
// @route   POST /api/users/bulk
// @access  Private
const getUsersByIds = async (req, res) => {
  const { ids } = req.body;

  if (!ids || !Array.isArray(ids)) {
    return res.status(400).json({ message: 'User IDs must be provided in an array.' });
  }

  try {
    const users = await User.find({ '_id': { $in: ids } }).select(
      'fullName username role profilePictureUrl location'
    );
    
    res.status(200).json(users);

  } catch (error) {
    console.error("Error fetching users by IDs:", error);
    res.status(500).json({ message: 'Server Error' });
  }
};

// 👇 THIS IS THE FIX 👇
// The `export` keyword is removed from each function definition above.
// All functions are now exported in a single block at the end for consistency.
export {
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
  getUsersByIds // The new function is included here, but only once.
};
