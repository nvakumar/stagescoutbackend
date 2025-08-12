import mongoose from 'mongoose';

const postSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    group: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Group',
      required: false,
    },
    title: {
      type: String,
      required: [true, 'A title or text content is required for your post.'],
      trim: true,
    },
    description: {
      type: String,
      trim: true,
    },
    // 👇 THIS IS THE FIX 👇
    // The mediaUrl and mediaType are now optional and have no default value.
    // This is correct, as not all posts will have media.
    mediaUrl: {
      type: String,
    },
    mediaType: {
      type: String,
      enum: ['Photo', 'Video'],
    },
    likes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    reactions: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        emoji: { type: String, required: true },
      },
    ],
    comments: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        text: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  {
    timestamps: true,
  }
);

const Post = mongoose.model('Post', postSchema);

export default Post;
