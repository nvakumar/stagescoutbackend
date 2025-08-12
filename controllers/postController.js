import multer from 'multer';
import { postStorage } from '../config/cloudinary.js';
import Post from '../models/postModel.js';
import User from '../models/userModel.js';
import Group from '../models/groupModel.js';

// Set up multer with the Cloudinary storage engine for posts
const upload = multer({ storage: postStorage });

// @desc    Upload a media file for a post
// @route   POST /api/posts/upload
// @access  Private
const uploadPostMedia = (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded.' });
  }
  res.status(201).json({
    message: 'File uploaded successfully.',
    mediaUrl: req.file.path,
    mediaType: req.file.mimetype.startsWith('video') ? 'Video' : 'Photo',
  });
};


// @desc    Create a new post
// @route   POST /api/posts
// @access  Private
const createPost = async (req, res) => {
  const { title, description, groupId } = req.body;

  if (!title) {
    return res.status(400).json({ message: 'Title content is required.' });
  }

  try {
    if (groupId) {
      const group = await Group.findById(groupId);
      if (!group || !group.members.includes(req.user._id)) {
        return res.status(403).json({ message: 'You are not a member of this group.' });
      }
    }

    let mediaUrl = null;
    let mediaType = null;

    if (req.file) {
      // multer-storage-cloudinary puts Cloudinary URL in req.file.path
      mediaUrl = req.file.path;
      mediaType = req.file.mimetype.startsWith('video') ? 'Video' : 'Photo';
    }

    const newPostData = {
      user: req.user._id,
      title,
      description,
      mediaUrl,
      mediaType,
      ...(groupId && { group: groupId }),
    };

    const newPost = new Post(newPostData);
    const createdPost = await newPost.save();
    const populatedPost = await Post.findById(createdPost._id)
      .populate('user', 'fullName role avatar profilePictureUrl');

    res.status(201).json(populatedPost);
  } catch (error) {
    console.error("Error creating post:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Get all posts for the main feed (posts not in a group)
// @route   GET /api/posts
// @access  Private
const getPosts = async (req, res) => {
  try {
    const posts = await Post.find({ group: { $exists: false } })
      .sort({ createdAt: -1 })
      .populate('user', 'fullName role avatar profilePictureUrl')
      .populate('comments.user', 'fullName avatar profilePictureUrl')
      .lean(); // Use .lean() to get plain JavaScript objects for easier manipulation

    // 👇 THIS IS THE FIX 👇
    // Manually map the response to ensure the mediaUrl and mediaType fields are always present,
    // even if they are null or undefined in the database.
    const formattedPosts = posts.map(post => ({
      ...post,
      mediaUrl: post.mediaUrl || null,
      mediaType: post.mediaType || null,
    }));

    res.status(200).json(formattedPosts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Get all posts for a specific group
// @route   GET /api/groups/:id/posts
// @access  Private
const getGroupPosts = async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) {
            return res.status(404).json({ message: 'Group not found' });
        }
        if (group.isPrivate && !group.members.includes(req.user._id)) {
            return res.status(403).json({ message: 'You do not have permission to view posts in this private group.' });
        }
        const posts = await Post.find({ group: req.params.id })
            .sort({ createdAt: -1 })
            .populate('user', 'fullName role avatar profilePictureUrl')
            .populate('comments.user', 'fullName avatar profilePictureUrl')
            .lean(); // Also use lean here for consistency

        const formattedPosts = posts.map(post => ({
            ...post,
            mediaUrl: post.mediaUrl || null,
            mediaType: post.mediaType || null,
        }));

        res.status(200).json(formattedPosts);
    } catch (error) {
        console.error("Error fetching group posts:", error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Like/unlike a post
// @route   PUT /api/posts/:id/like
// @access  Private
const likePost = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: 'Post not found' });
    if (post.likes.includes(req.user._id)) {
      post.likes = post.likes.filter(id => id.toString() !== req.user._id.toString());
    } else {
      post.likes.push(req.user._id);
    }
    await post.save();
    res.status(200).json({ likes: post.likes });
  } catch (error) {
    console.error("Error liking post:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    React to a post with an emoji
// @route   POST /api/posts/:id/react
// @access  Private
const reactToPost = async (req, res) => {
    const { emoji } = req.body;
    if (!emoji) {
        return res.status(400).json({ message: 'Emoji is required.' });
    }
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ message: 'Post not found' });

        const existingReactionIndex = post.reactions.findIndex(
            reaction => reaction.user.toString() === req.user._id.toString()
        );

        if (existingReactionIndex > -1) {
            post.reactions[existingReactionIndex].emoji = emoji;
        } else {
            post.reactions.push({ user: req.user._id, emoji });
        }
        
        await post.save();
        const populatedPost = await Post.findById(post._id).populate('reactions.user', 'fullName');
        res.status(200).json(populatedPost.reactions);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
};

// @desc    Add a comment to a post
// @route   POST /api/posts/:id/comment
// @access  Private
const addComment = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: 'Post not found' });
    const newComment = { user: req.user._id, text: req.body.text };
    post.comments.push(newComment);
    await post.save();
    const populatedPost = await Post.findById(post._id).populate('comments.user', 'fullName avatar profilePictureUrl');
    res.status(201).json(populatedPost.comments);
  } catch (error) {
    console.error("Error adding comment:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Delete a comment from a post
// @route   DELETE /api/posts/:postId/comment/:commentId
// @access  Private
const deleteComment = async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const post = await Post.findById(postId).populate('group', 'admin');
    if (!post) return res.status(404).json({ message: 'Post not found' });
    const comment = post.comments.id(commentId);
    if (!comment) return res.status(404).json({ message: 'Comment not found' });
    const isGroupAdmin = post.group && post.group.admin.toString() === req.user._id.toString();
    if (
      comment.user.toString() !== req.user._id.toString() &&
      post.user.toString() !== req.user._id.toString() &&
      !isGroupAdmin
    ) {
      return res.status(401).json({ message: 'Not authorized to delete this comment' });
    }
    comment.deleteOne();
    await post.save();
    res.status(200).json({ message: 'Comment removed' });
  } catch (error) {
    console.error("Error deleting comment:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Delete a post
// @route   DELETE /api/posts/:id
// @access  Private
const deletePost = async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId).populate('group', 'admin');
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }
    const isPostOwner = post.user.toString() === req.user._id.toString();
    const isGroupAdmin = post.group && post.group.admin.toString() === req.user._id.toString();
    if (!isPostOwner && !isGroupAdmin) {
      return res.status(401).json({ message: 'Not authorized to delete this post' });
    }
    await post.deleteOne();
    res.status(200).json({ message: 'Post removed successfully' });
  } catch (error) {
    console.error("Error deleting post:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Update a post
// @route   PUT /api/posts/:id
// @access  Private
const updatePost = async (req, res) => {
  try {
    const postId = req.params.id;
    const { title, description, mediaUrl, mediaType } = req.body;
    const post = await Post.findById(postId).populate('group', 'admin');
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }
    const isPostOwner = post.user.toString() === req.user._id.toString();
    const isGroupAdmin = post.group && post.group.admin.toString() === req.user._id.toString();
    if (!isPostOwner && !isGroupAdmin) {
      return res.status(401).json({ message: 'Not authorized to update this post' });
    }
    post.title = title !== undefined ? title : post.title;
    post.description = description !== undefined ? description : post.description;
    post.mediaUrl = mediaUrl !== undefined ? mediaUrl : post.mediaUrl;
    post.mediaType = mediaType !== undefined ? mediaType : post.mediaType;
    const updatedPost = await post.save();
    const populatedUpdatedPost = await Post.findById(updatedPost._id).populate('user', 'fullName role avatar profilePictureUrl');
    res.status(200).json(populatedUpdatedPost);
  } catch (error) {
    console.error("Error updating post:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

export { 
  createPost, 
  getPosts, 
  getGroupPosts, 
  likePost, 
  reactToPost,
  addComment, 
  deleteComment, 
  deletePost, 
  updatePost, 
  uploadPostMedia,
  upload 
};
