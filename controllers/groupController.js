import Group from '../models/groupModel.js';
import User from '../models/userModel.js';
import Post from '../models/postModel.js'; // Import Post model for cascading deletes

// @desc    Create a new group (with user limit)
// @route   POST /api/groups
// @access  Private
const createGroup = async (req, res) => {
  const { name, description, isPrivate } = req.body;

  try {
    // BUSINESS RULE: Limit users to creating 2 groups
    const existingGroupsCount = await Group.countDocuments({ admin: req.user._id });
    if (existingGroupsCount >= 2) {
      return res.status(400).json({ message: 'You have reached the maximum limit of 2 groups.' });
    }

    const groupExists = await Group.findOne({ name });
    if (groupExists) {
      return res.status(400).json({ message: 'A group with this name already exists.' });
    }

    const group = await Group.create({
      name,
      description,
      isPrivate,
      admin: req.user._id,
    });

    res.status(201).json(group);
  } catch (error) {
    res.status(400).json({ message: 'Failed to create group', error: error.message });
  }
};

// @desc    Get all public groups
// @route   GET /api/groups
// @access  Private
const getAllGroups = async (req, res) => {
  try {
    const groups = await Group.find({ isPrivate: false })
      .populate('admin', 'fullName')
      .sort({ createdAt: -1 });
    res.status(200).json(groups);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Get details of a single group
// @route   GET /api/groups/:id
// @access  Private
const getGroupDetails = async (req, res) => {
  try {
    const group = await Group.findById(req.params.id)
      .populate('admin', 'fullName avatar')
      .populate('members', 'fullName avatar role');

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    res.status(200).json(group);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Join a group
// @route   POST /api/groups/:id/join
// @access  Private
const joinGroup = async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) return res.status(404).json({ message: 'Group not found' });
        if (group.members.includes(req.user._id)) return res.status(400).json({ message: 'You are already a member of this group.' });
        group.members.push(req.user._id);
        await group.save();
        res.status(200).json({ message: 'Successfully joined the group.' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Leave a group
// @route   POST /api/groups/:id/leave
// @access  Private
const leaveGroup = async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) return res.status(404).json({ message: 'Group not found' });
        if (!group.members.includes(req.user._id)) return res.status(400).json({ message: 'You are not a member of this group.' });
        if (group.admin.toString() === req.user._id.toString()) return res.status(400).json({ message: 'Admin cannot leave the group.' });
        group.members = group.members.filter(memberId => memberId.toString() !== req.user._id.toString());
        await group.save();
        res.status(200).json({ message: 'Successfully left the group.' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Update group cover image (Admin only)
// @route   PUT /api/groups/:id/cover
// @access  Private
const updateGroupCover = async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) return res.status(404).json({ message: 'Group not found' });
        if (group.admin.toString() !== req.user._id.toString()) return res.status(403).json({ message: 'User not authorized to update this group' });
        if (!req.file) return res.status(400).json({ message: 'Please upload an image file' });
        group.coverImage = req.file.path;
        const updatedGroup = await group.save();
        res.status(200).json(updatedGroup);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Remove a member from a group (Admin only)
// @route   POST /api/groups/:id/remove-member
// @access  Private
const removeMember = async (req, res) => {
    const { memberId } = req.body;
    try {
        const group = await Group.findById(req.params.id);
        if (!group) return res.status(404).json({ message: 'Group not found' });
        if (group.admin.toString() !== req.user._id.toString()) return res.status(403).json({ message: 'Only the group admin can remove members.' });
        if (group.admin.toString() === memberId) return res.status(400).json({ message: 'Admin cannot be removed from the group.' });
        group.members = group.members.filter(id => id.toString() !== memberId);
        await group.save();
        res.status(200).json({ message: 'Member removed successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Delete a group (Admin only)
// @route   DELETE /api/groups/:id
// @access  Private
const deleteGroup = async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) return res.status(404).json({ message: 'Group not found' });
        if (group.admin.toString() !== req.user._id.toString()) return res.status(403).json({ message: 'Only the group admin can delete the group.' });
        
        // Also delete all posts associated with this group
        await Post.deleteMany({ group: req.params.id });
        await group.remove();

        res.status(200).json({ message: 'Group and all associated posts have been deleted.' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

export { createGroup, getAllGroups, getGroupDetails, joinGroup, leaveGroup, updateGroupCover, removeMember, deleteGroup };
