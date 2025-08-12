import mongoose from 'mongoose';

const castingCallSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User', // The user who posted the call (Director, Production House)
    },
    projectTitle: {
      type: String,
      required: [true, 'Project title is required'],
    },
    projectType: {
      type: String,
      required: true,
      enum: ['Feature Film', 'Short Film', 'Web Series', 'Advertisement', 'Theatre'],
    },
    roleDescription: {
      type: String,
      required: [true, 'Role description is required'],
    },
    roleType: {
      type: String,
      required: true,
      enum: ['Lead', 'Supporting', 'Cameo', 'Background'],
    },
    location: {
      type: String,
      required: [true, 'Location is required'],
    },
    applicationDeadline: {
      type: Date,
      required: true,
    },
    contactEmail: {
      type: String,
      required: [true, 'A contact email is required'],
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  }
);

const CastingCall = mongoose.model('CastingCall', castingCallSchema);

export default CastingCall;
