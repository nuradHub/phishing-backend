import express from 'express';
import Scanner from '../services/scanners.js';
import UserProtected from '../middleware/UserMIddleWare.js';

const router = express.Router();

// MOUNT REFACTOR: Accessible via POST -> /api/scan
router.post('/api/scan', async (req, res) => {
    const { url, userId } = req.body;
    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }

    // 2. Validate URL Format
    const urlObj = Scanner.prepareUrl(url);
    if (!urlObj) {
        return res.status(400).json({ 
            error: "Invalid URL format",
            message: "Please provide a valid URL" 
        });
    }

    try {

        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        const fullReport = await Scanner.getFullAnalysis(url, userId || null, clientIp);

        // 4. Send the Professional Report
        return res.status(200).json(fullReport);

    } catch (err) {
        console.error("Route Error:", err);
        res.status(500).json({ error: "System Analysis Failed" });
    }
});

router.get('/api/dashboard/history/:userId', UserProtected, async (req, res) => {
    try {
        const { UrlSubmission } = await import('../schema/Schemas.js');
        
        // Query database for submissions explicitly linked to this User ID node
        const historyLogs = await UrlSubmission.find({ user_id: req.userId })
            .sort({ timestamp: -1 })
            .limit(50);
            
        return res.status(200).json(historyLogs);
    } catch (err) {
        console.error("Dashboard History Error:", err);
        return res.status(500).json({ error: "Failed to load scan history" });
    }
});

export default router;