import Conversation from '../models/conversationModel.js';
import Message from '../models/messageModel.js';
import User from '../models/userModel.js';

// @desc    Start a new conversation
// @route   POST /api/messages/conversations
// @access  Private
const newConversation = async (req, res) => {
  const { receiverId } = req.body;
  const senderId = req.user._id;

  try {
    const existingConversation = await Conversation.findOne({
      participants: { $all: [senderId, receiverId] },
    });

    if (existingConversation) {
      const populatedConversation = await Conversation.findById(existingConversation._id)
        .populate('participants', 'fullName avatar role');
      return res.status(200).json(populatedConversation);
    }

    const newConversation = new Conversation({
      participants: [senderId, receiverId],
    });

    const savedConversation = await newConversation.save();
    
    const populatedSavedConversation = await Conversation.findById(savedConversation._id)
      .populate('participants', 'fullName avatar role');

    res.status(201).json(populatedSavedConversation);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Get all conversations for a user
// @route   GET /api/messages/conversations
// @access  Private
const getConversations = async (req, res) => {
  try {
    const conversations = await Conversation.find({
      participants: { $in: [req.user._id] },
    })
    .populate('participants', 'fullName avatar role');
    
    res.status(200).json(conversations);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Add a new message
// @route   POST /api/messages
// @access  Private
const addMessage = async (req, res) => {
  const { conversationId, receiver, text } = req.body;
  const sender = req.user._id;

  const newMessage = new Message({
    conversationId,
    sender,
    receiver,
    text,
  });

  try {
    const savedMessage = await newMessage.save();
    // Populate the sender's details including avatar before sending back
    const populatedMessage = await Message.findById(savedMessage._id)
      .populate('sender', 'fullName avatar role'); // 👈 Ensure avatar is populated here
    res.status(201).json(populatedMessage);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

// @desc    Get messages for a conversation
// @route   GET /api/messages/:conversationId
// @access  Private
const getMessages = async (req, res) => {
  try {
    const messages = await Message.find({
      conversationId: req.params.conversationId,
    })
    .populate('sender', 'fullName avatar role'); // 👈 Ensure avatar is populated here
    
    res.status(200).json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};


export { newConversation, getConversations, addMessage, getMessages };
