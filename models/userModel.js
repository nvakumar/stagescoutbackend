// models/User.js
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, 'Please provide your full name'],
    },

    username: {
      type: String,
      unique: true,
      sparse: true,
      lowercase: true,
      trim: true,
      minlength: 3,
      match: [/^[a-z0-9_]+$/, 'Username can only contain lowercase letters, numbers, and underscores.'],
      required: function () {
        return !this.isNewUser;
      }
    },

    email: {
      type: String,
      required: [true, 'Please provide an email'],
      unique: true,
      lowercase: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        'Please provide a valid email',
      ],
    },

    password: {
      type: String,
      minlength: 6,
    },

    role: {
      type: String,
      enum: [
        'Actor', 'Model', 'Filmmaker', 'Director', 'Writer',
        'Photographer', 'Editor', 'Musician', 'Creator', 'Student', 'Production House'
      ],
      required: function () {
        return !this.isNewUser;
      },
    },

    usernameLastChanged: {
      type: Date,
    },

    bio: {
      type: String,
      maxlength: 500,
      default: ''
    },

    skills: {
      type: [String],
      default: []
    },

    profilePictureUrl: {
      type: String,
      default: 'https://placehold.co/150x150/1a202c/ffffff?text=Avatar'
    },

    // ** THIS IS THE FIX **
    // The missing field is now added to the schema.
    coverPhotoUrl: {
      type: String,
      default: ''
    },

    resumeUrl: {
      type: String,
      default: ''
    },

    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],

    isVerified: {
      type: Boolean,
      default: false,
    },

    isNewUser: {
      type: Boolean,
      default: true, // Google users will have this true initially
    }
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model('User', userSchema);

export default User;
