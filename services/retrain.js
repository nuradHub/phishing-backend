import brain from 'brain.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { MissedPattern, NeuralModel } from '../schema/Schemas.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const trainingSetPath = path.join(__dirname, '../data/training-set.json'); 

export const captureMissedPattern = async (inputVector, url, vtFlags) => {
    try {
        // Only enforce safety checks on vectors matching your network shape
        if (!inputVector || inputVector.length !== 7) return;

        const exists = await MissedPattern.findOne({ features: inputVector });
        if (!exists) {
            await MissedPattern.create({ 
                url: url,
                features: inputVector, 
                virustotal_flags: vtFlags
            });
            console.log("🚀 Pattern saved to MongoDB Missed_Pattern repository.");
        }
    } catch (err) {
        console.error("❌ DB Capture Error:", err);
    }
};

// Pulls from training-set.json AND MissedPattern collection to update your model weights
export const runAutoTrain = async () => {
    try {
        // 1. Load your core baseline rules so your AI NEVER forgets foundational safety parameters
        let consolidatedDataset = [];
        if (fs.existsSync(trainingSetPath)) {
            const rawBaselineData = fs.readFileSync(trainingSetPath, 'utf8');
            consolidatedDataset = JSON.parse(rawBaselineData);
            console.log(`📦 Loaded ${consolidatedDataset.length} baseline vectors from training-set.json.`);
        } else {
            console.warn("⚠️ Core baseline training-set.json path mismatch. Using internal fallback rules.");
            // Hardcoded fallback rules array to ensure server doesn't crash if file path skips a node
            consolidatedDataset = [
                { input: [0, 0, 0, 0, 0, 0, 0], output: [0] },
                { input: [1, 1, 1, 1, 1, 1, 1], output: [1] }
            ];
        }

        // 2. Fetch your newly captured continuous error patterns from MongoDB
        const dynamicPatterns = await MissedPattern.find({}).lean();
        console.log(`📊 Found ${dynamicPatterns.length} dynamic mistake signatures in MongoDB.`);

        // 3. Inject dynamic patterns into your active dataset WITH strict input vector layer safety checks
        let freshInjectionsCount = 0;
        dynamicPatterns.forEach((pattern) => {
            if (pattern && pattern.features && Array.isArray(pattern.features) && pattern.features.length === 7) {
                // If VirusTotal metrics flag it heavily, anchor target to 1. Else tag as a high risk threshold
                const targetOutput = pattern.virustotal_flags > 5 ? [1] : [0.85];
                
                consolidatedDataset.push({
                    input: pattern.features,
                    output: targetOutput
                });
                freshInjectionsCount++;
            }
        });

        console.log(`⚙️ Dataset built. Added ${freshInjectionsCount} dynamic nodes. Training over ${consolidatedDataset.length} total entries.`);

        // 4. Initialize your Hidden Layers matrix perceptron
        const net = new brain.NeuralNetwork({ hiddenLayers: [12, 8, 4] });
        
        // 5. Fire your optimization backpropagation learning calculations over the combined data array
        net.train(consolidatedDataset, {
            iterations: 4000,
            errorThresh: 0.005,
            log: true,
            logPeriod: 1000
        });

        // 6. Serialize weights matrix parameters directly into MongoDB
        const modelJSON = net.toJSON();
        await NeuralModel.findOneAndUpdate(
            {}, 
            { 
                model_json: modelJSON, 
                trained_at: new Date(), 
                sample_count: consolidatedDataset.length 
            }, 
            { upsert: true, new: true }
        );
        
        console.log("✅ Neural_Model brain mapping successfully updated in cloud.");
        return consolidatedDataset.length;

    } catch (err) {
        console.error("❌ Model Training Failure:", err);
        throw err;
    }
};
