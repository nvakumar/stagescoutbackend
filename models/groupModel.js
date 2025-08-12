import mongoose from 'mongoose';

const groupSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Group name is required'],
      trim: true,
      unique: true,
    },
    description: {
      type: String,
      required: [true, 'Group description is required'],
      trim: true,
    },
    coverImage: {
      type: String, // URL to the cover image from Cloudinary
      default: 'https://placehold.co/1200x400/1a202c/4f46e5?text=StageScout+Group',
    },
    // The user who created the group
    admin: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    // A list of all members in the group
    members: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    // For future use, can add more admins
    moderators: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
        }
    ],
    isPrivate: {
        type: Boolean,
        default: false, // Public by default
    }
  },
  {
    timestamps: true,
  }
);

// When a new group is created, automatically add the admin to the members list
groupSchema.pre('save', function (next) {
  if (this.isNew) {
    this.members.push(this.admin);
  }
  next();
});


const Group = mongoose.model('Group', groupSchema);

export default Group;
