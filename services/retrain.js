import brain from 'brain.js';
import { MissedPattern, NeuralModel } from '../schema/Schemas.js';

export const captureMissedPattern = async (inputVector, url, vtFlags) => {
    try {
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

// Pulls from MissedPattern collection, updates NeuralModel document
export const runAutoTrain = async () => {
    try {
        const allPatterns = await MissedPattern.find({}).lean();
        if (allPatterns.length === 0) return console.log("No dynamic patterns to train on.");

        const net = new brain.NeuralNetwork({ hiddenLayers: [12, 8, 4] });
        
        console.log(`🧠 Re-training AI on ${allPatterns.length} persistent vectors...`);
        net.train(allPatterns.map(p => ({ input: p.features, output: [1] })), {
            iterations: 5000,
            log: true
        });

        const modelJSON = net.toJSON();
        await NeuralModel.findOneAndUpdate(
            {}, 
            { model_json: modelJSON, trained_at: Date.now(), sample_count: allPatterns.length },
            { upsert: true }
        );
        console.log("✅ Neural_Model brain mapping successfully updated in cloud.");
    } catch (err) {
        console.error("❌ Model Training Failure:", err);
    }
};