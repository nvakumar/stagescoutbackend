import User from '../models/userModel.js';
import Post from '../models/postModel.js';

// @desc    Get the top users for the leaderboard
// @route   GET /api/leaderboard
// @access  Public (or Private if desired)
const getLeaderboard = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10; // Default to top 10
    const roleFilter = req.query.role; // Get the optional role filter from query params

    let pipeline = [];

    // If a role filter is provided, add a $match stage based on the user's role
    if (roleFilter) {
      // First, lookup the user details to match by role
      pipeline.push({
        $lookup: {
          from: 'users',
          localField: 'user', // 'user' field in the Post model
          foreignField: '_id',
          as: 'postAuthorDetails'
        }
      },
      {
        $unwind: '$postAuthorDetails' // Deconstruct the array
      },
      {
        $match: {
          'postAuthorDetails.role': roleFilter // Match by the role
        }
      },
      {
        $project: { // Project back only necessary fields for the next stage
          _id: 1,
          user: '$user',
          likes: '$likes',
          createdAt: '$createdAt'
        }
      });
    }

    // Continue with the original aggregation pipeline
    pipeline.push(
      {
        $group: {
          _id: "$user", // Group by user ID
          totalLikes: { $sum: { $size: "$likes" } }, // Sum the number of likes on their posts
          totalPosts: { $sum: 1 } // Count total posts
        }
      },
      {
        $lookup: {
          from: 'users', // The collection to join with
          localField: '_id', // Field from the input documents (_id from group, which is user ID)
          foreignField: '_id', // Field from the "users" collection
          as: 'userDetails' // Output array field
        }
      },
      {
        $unwind: '$userDetails' // Deconstruct the userDetails array
      },
      {
        $project: {
          _id: 0, // Exclude the default _id
          userId: '$userDetails._id',
          fullName: '$userDetails.fullName',
          role: '$userDetails.role',
          avatar: '$userDetails.profilePictureUrl',
          totalLikes: 1,
          totalPosts: 1,
          // Calculate an engagement score (e.g., total likes + (total posts * 5))
          engagementScore: { $add: ["$totalLikes", { $multiply: ["$totalPosts", 5] }] }
        }
      },
      {
        $sort: { engagementScore: -1 } // Sort by engagement score descending
      },
      {
        $limit: limit // Limit to the top N users
      }
    );

    const userEngagement = await Post.aggregate(pipeline);

    res.status(200).json(userEngagement);

  } catch (error) {
    console.error("Error fetching leaderboard:", error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
};

export { getLeaderboard };
