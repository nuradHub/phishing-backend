import express from 'express';
import { GeneralReview } from '../schema/Schemas.js';

const router = express.Router();

router.post('/api/general-review/new', async (req, res) => {
    const { name, message } = req.body;
    
    try {
        if (!message) {
            return res.status(400).json({ message: 'Message content is required.' });
        }

        const newFeedback = await GeneralReview.create({
            reviewer_name: name?.trim() || "Anonymous Guest",
            comment: message
        });

        return res.status(201).json({ 
            message: 'Feedback posted successfully!', 
            review: newFeedback 
        });
        
    } catch (err) {
        console.error("❌ Public Feedback Error:", err.message);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

router.get('/api/general-reviews', async (req, res) => {
    try {
        const publicLogs = await GeneralReview.find({})
            .sort({ submitted_at: -1 })
            .limit(15);
        
        return res.status(200).json(publicLogs);
    } catch (err) {
        console.error("❌ Public Feed Fetch Error:", err.message);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

export default router;