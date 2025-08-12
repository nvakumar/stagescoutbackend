// src/config/cloudinary.js
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import 'dotenv/config';

// -------------------------
// Cloudinary Configuration
// -------------------------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// -------------------------
// Post Media Storage
// -------------------------
// Handles both images & videos for general posts
const postStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    return {
      folder: 'StageScout/posts',
      allowed_formats: ['jpeg', 'png', 'jpg', 'mp4', 'mov'],
      resource_type: 'auto', // Let Cloudinary detect automatically
      // Use a unique, safe public_id without spaces or special chars
      public_id: `${Date.now()}-${file.originalname
        .replace(/\.[^/.]+$/, '') // remove file extension
        .replace(/\s+/g, '_')     // replace spaces with underscores
        .replace(/[^a-zA-Z0-9_-]/g, '')}`, // remove special chars
    };
  },
});

// -------------------------
// Avatar Storage
// -------------------------
// Profile pictures only
const avatarStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'StageScout/avatars',
    allowed_formats: ['jpeg', 'png', 'jpg'],
    resource_type: 'image',
    public_id: (req, file) => `avatar-${req.user._id}`,
    overwrite: true,
  },
});

// -------------------------
// Resume Storage
// -------------------------
const resumeStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'StageScout/resumes',
    allowed_formats: ['pdf', 'doc', 'docx'],
    resource_type: 'raw',
    public_id: (req, file) => `resume-${req.user._id}`,
    overwrite: true,
  },
});

// -------------------------
// Group Cover Storage
// -------------------------
const groupCoverStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'StageScout/group_covers',
    allowed_formats: ['jpeg', 'png', 'jpg'],
    resource_type: 'image',
    public_id: (req, file) => `group-cover-${req.params.id}`,
    overwrite: true,
  },
});

// -------------------------
// User Cover Photo Storage
// -------------------------
const coverPhotoStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'StageScout/covers',
    allowed_formats: ['jpg', 'png', 'jpeg'],
    resource_type: 'image',
    public_id: (req, file) => `cover-${req.user._id}`,
    overwrite: true,
  },
});

export {
  cloudinary,
  postStorage,
  avatarStorage,
  resumeStorage,
  groupCoverStorage,
  coverPhotoStorage,
};