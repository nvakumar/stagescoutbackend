import mongoose from 'mongoose';

const notificationSchema = new mongoose.Schema(
  {
    // The user who is applying for the role
    applicant: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    // The user who posted the casting call (the recipient of the notification)
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    // The specific casting call the user is applying to
    castingCall: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'CastingCall',
    },
    // The type of notification
    type: {
      type: String,
      required: true,
      enum: ['application'],
      default: 'application',
    },
    // The status of the notification/application
    status: {
      type: String,
      enum: ['unread', 'read'],
      default: 'unread',
    },
  },
  {
    timestamps: true,
  }
);

const Notification = mongoose.model('Notification', notificationSchema);

export default Notification;
