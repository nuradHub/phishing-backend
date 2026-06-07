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

        // 🛠️ DEBUG SNIPMAP: Prints exactly what properties are returning from your scanner helper
        console.log("🔍 [DEBUG METRICS] Raw report payload keys found:", Object.keys(fullReport));
        if (fullReport.analysis) {
            console.log("🔍 [DEBUG METRICS] Inner analysis payload keys found:", Object.keys(fullReport.analysis));
        }

        // 🛠️ UPGRADED FALLBACK PROPERTY EXTRACTORS:
        const features = fullReport.analysis?.features || fullReport.features;

        // Extract raw intelligence score representation safely
        let rawAiScore = fullReport.analysis?.aiConfidence ?? fullReport.analysis?.ai_confidence ?? fullReport.ai_confidence ?? 0;
        
        // Strip out any percentage symbol string notation if present before converting to float
        if (typeof rawAiScore === 'string') {
            rawAiScore = rawAiScore.replace('%', '');
        }
        
        let aiScore = parseFloat(rawAiScore);
        
        // Scale normalization threshold correction layer:
        if (aiScore > 1) {
            aiScore = aiScore / 100;
        }

        // Extract VirusTotal malicious tracking metrics across possible naming conventions
        const vtFlags = parseInt(fullReport.analysis?.globalReports ?? fullReport.analysis?.global_reports ?? fullReport.global_reports ?? fullReport.virustotal_flags ?? 0);

        console.log(`📊 Normalized Metrics for Evaluation -> AI Score: ${aiScore} (${(aiScore * 100).toFixed(2)}%), VT Flags: ${vtFlags}, Features Exist: ${!!features}`);

        // Logical evaluation boundaries mapped safely to decimal parameters
        const aiMissedThreat = aiScore < 0.50;  // 0.1714 < 0.50 evaluates to TRUE ✅
        const vtConfirmedThreat = vtFlags >= 1; // 12 >= 1 evaluates to TRUE ✅

        if (aiMissedThreat && vtConfirmedThreat && features) {
            console.log(`🧠 [DISCREPANCY CAUGHT] Running background continuous learning loop...`);

            // 1. Capture and save the missed pattern signature in MongoDB if it doesn't exist
            await captureMissedPattern(features, url, vtFlags);

            // 2. Fire the neural retrain loop ASYNCHRONOUSLY in the background (No 'await' keyword)
            runAutoTrain()
                .then(totalSamples => console.log(`⚡ [AUTO-LEARN SUCCESS] Optimization run complete. Total weights in network: ${totalSamples}`))
                .catch(err => console.error("⚡ [AUTO-LEARN EXCEPTION] Background training process dropped:", err.message));
        } else {
            console.log("ℹ️ [SCAN GATEWAY LOG] Conditions mismatch or missing features array. Skipping training loop invocation.");
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
