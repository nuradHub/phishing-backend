import express from 'express';
import Scanner from '../services/scanners.js';
import UserProtected from '../middleware/UserMIddleWare.js';
import { runAutoTrain, captureMissedPattern } from '../services/retrain.js';

const router = express.Router();

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

        // Execute scan pipeline to get data details
        const fullReport = await Scanner.getFullAnalysis(url, userId || null, clientIp);

        // 🛠️ 2. CONTINUOUS DISCREPANCY DETECTOR LOOP:
        const features = fullReport.analysis?.features || fullReport.features;
        const aiScore = parseFloat(fullReport.analysis?.ai_confidence || fullReport.analysis?.aiConfidence || 0);
        const vtFlags = parseInt(fullReport.analysis?.global_reports || fullReport.analysis?.globalReports || 0);

        const aiMissedThreat = aiScore < 0.50; // AI thought it was safe
        const vtConfirmedThreat = vtFlags > 5;  // VirusTotal flagged it as malicious

        if (aiMissedThreat && vtConfirmedThreat && features) {
            console.log(`🧠 [DISCREPANCY CAUGHT] AI score was low (${aiScore}) but VT flags were high (${vtFlags}). Isolating vector pattern...`);

            // 1. Capture and save the missed pattern signature in MongoDB if it doesn't exist
            await captureMissedPattern(features, url, vtFlags);

            // 2. Fire the neural retrain loop ASYNCHRONOUSLY in the background.

            runAutoTrain()
                .then(totalSamples => console.log(`⚡ [AUTO-LEARN SUCCESS] Optimization run complete. Total weights in network: ${totalSamples}`))
                .catch(err => console.error("⚡ [AUTO-LEARN EXCEPTION] Background training process dropped:", err.message));
        }

        // 4. Send the Professional Report immediately to the user 
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
