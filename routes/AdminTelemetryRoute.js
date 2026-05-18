import express from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../schema/UserSchema.js';
import {UrlSubmission, CommunityReview, GeneralReview } from '../schema/Schemas.js';
import AdminProtected from '../middleware/AdminMIddleWare.js';
import UserProtected from '../middleware/UserMIddleWare.js';
import brain from 'brain.js';
import { NeuralModel, MissedPattern } from '../schema/Schemas.js';

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
      // 1. Gather all recently logged missed patterns from your collection cluster
      const accumulatedMissedPatterns = await MissedPattern.find({}).lean();
      console.log(`📊 Found ${accumulatedMissedPatterns.length} newly isolated threat patterns for core processing.`);

      // 2. Instantiate a fresh brain.js network structure matching your main engine layout
      const net = new brain.NeuralNetwork({ hiddenLayers: [12, 8, 4] });

      // 3. Define your core baseline foundational vectors (so it doesn't forget general rules)
      const trainingDataset = [
          { input: [0, 0, 0, 0, 0, 0, 0], output: [0] }, // Pure Safe Vector
          { input: [1, 1, 1, 1, 1, 1, 1], output: [1] }, // High Threat Critical Vector
          { input: [0, 0, 1, 0, 0, 0, 1], output: [0.85] },
          { input: [0, 1, 0, 0, 0, 0, 0], output: [0.45] },
          { input: [0, 0, 0, 0, 1, 1, 0], output: [0.75] },
          { input: [1, 0, 0, 1, 0, 0, 1], output: [0.95] },
          { input: [0, 1, 1, 0, 1, 0, 0], output: [0.80] },
          { input: [0, 0, 0, 0, 1, 0, 0], output: [1] }
      ];

      // 4. Inject the missed pattern attributes dynamically with strict sizing filters
      let sanitizedCount = 0;
      accumulatedMissedPatterns.forEach((pattern, index) => {
          if (pattern && pattern.features && Array.isArray(pattern.features)) {
              
              // 🛡️ CRITICAL MATRIX GUARD: Ensure vector size matches exactly 7 features
              // This protects brain.js from a matrix multiplication crash inside hidden layers
              if (pattern.features.length === 7) {
                  // Fallback safely whether your document tracks virustotal_flags or global_reports
                  const flags = pattern.virustotal_flags ?? pattern.global_reports ?? 0;
                  const targetOutput = flags > 5 ? [1] : [0.85];
                  
                  trainingDataset.push({
                      input: pattern.features,
                      output: targetOutput
                  });
                  sanitizedCount++;
              } else {
                  console.warn(`⚠️ [DATA GUARD] Skipping pattern index ${index}: Malformed features array dimension (${pattern.features.length}/7).`);
              }
          }
      });

      console.log(`⚙️ Dataset verification complete. Passing ${sanitizedCount} valid vectors to the neural core.`);

      // 5. Execute optimization backpropagation training cycles
      console.log(`⚙️ Executing mathematical layer corrections across ${trainingDataset.length} vectors...`);
      net.train(trainingDataset, {
          iterations: 2000,     // Balanced iteration count limit to prevent live server processing timeout hangs
          errorThresh: 0.01,    // Safe threshold limit for brain execution environments
          log: true,
          logPeriod: 1000
      });

      // 6. Serialize compiled network layers down to plain JSON
      const optimizedModelJson = net.toJSON();
      const totalSampleCount = trainingDataset.length;

      // 7. Update or create the singular weights document in your NeuralModel cluster
      await NeuralModel.findOneAndUpdate(
          {}, 
          { 
              model_json: optimizedModelJson,
              trained_at: new Date(),
              sample_count: totalSampleCount
          }, 
          { upsert: true, new: true }
      );

      console.log("✅ [ADMIN SERVER] Neural network model weight matrix synchronized successfully.");
      
      return res.status(200).json({ 
          success: true, 
          message: "Neural Network model rebuilt with newly captured vectors successfully!",
          samplesProcessed: totalSampleCount 
      });

  } catch (err) {
      console.error("❌ Admin Retrain Routine Failure:", err);
      return res.status(500).json({ error: `Retraining sequence compilation collapsed: ${err.message}` });
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
