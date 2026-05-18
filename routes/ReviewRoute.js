import express from 'express';
import { CommunityReview } from '../schema/Schemas.js';

const router = express.Router();

router.post('/api/review/new', async (req, res) => {
    const { message, userId, url, verdict } = req.body;
    
    try {
        if (!message) return res.status(400).json({ message: 'Message Field is Required' });
        if (!userId) return res.status(400).json({ message: 'User ID is required for authenticated dashboard comments' });

        const reviewItem = await CommunityReview.create({
            user_id: userId,
            url: url || "",
            verdict: verdict || "",
            comment: message
        });
        
        const processedReview = await reviewItem.populate('user_id', 'fullname email');

        return res.status(201).json({ 
            message: 'Review Sent', 
            review: processedReview 
        });
        
    } catch (err) {
        console.error("New Review Error:", err.message);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

router.get('/api/reviews', async (req, res) => {
    try {
        const reviews = await CommunityReview.find({})
            .populate('user_id', 'fullname email')
            .sort({ submitted_at: -1 })
            .limit(20);

        if (!reviews || reviews.length === 0) {
            return res.status(200).json([]);
        }
        
        return res.status(200).json(reviews);

    } catch (err) {
        console.error("Fetch Reviews Feed Error:", err.message);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

export default router;