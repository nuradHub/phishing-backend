import express from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../schema/UserSchema.js';
import {UrlSubmission, CommunityReview, GeneralReview } from '../schema/Schemas.js';
import AdminProtected from '../middleware/AdminMIddleWare.js';
import UserProtected from '../middleware/UserMIddleWare.js';
import brain from 'brain.js';
import { NeuralModel, MissedPattern } from '../schema/Schemas.js';
import { runAutoTrain } from '../services/retrain.js';

const router = express.Router();

router.get('/api/admin/metrics-stream', UserProtected, AdminProtected, async (req, res) => {
    try {
        const [users, scans, privateReviews, publicReviews] = await Promise.all([
            User.find({}, 'fullname email role createdAt').sort({ createdAt: -1 }),
            UrlSubmission.find({}).sort({ timestamp: -1 }).limit(100),
            CommunityReview.find({}).populate('user_id', 'fullname email').sort({ submitted_at: -1 }),
            GeneralReview.find({}).sort({ submitted_at: -1 })
        ]);

        return res.status(200).json({
            users,
            scans,
            privateReviews,
            publicReviews
        });
    } catch (err) {
        console.error("❌ Admin metrics stream collection failure:", err.message);
        return res.status(500).json({ error: "Internal cluster query error." });
    }
});

router.post('/api/retrain', UserProtected, AdminProtected, async (req, res) => {
    try {
        const sampleCount = await runAutoTrain();
        return res.status(200).json({ success: true, samplesProcessed: sampleCount });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.delete('/api/admin/scan/:id', UserProtected, AdminProtected, async (req, res) => {
    try {
        await UrlSubmission.findByIdAndDelete(req.params.id);
        return res.status(200).json({ success: true, message: "Telemetry entry purged from cluster." });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.delete('/api/admin/user/:id', UserProtected, AdminProtected, async (req, res) => {
    try {
        // Safety guard: Prevent the admin from accidentally deleting themselves
        if (req.user.userId === req.params.id) {
            return res.status(400).json({ error: "Operation rejected: Cannot delete active root session profile." });
        }
        await User.findByIdAndDelete(req.params.id);
        return res.status(200).json({ success: true, message: "User identity node dropped cleanly." });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

export default router;
