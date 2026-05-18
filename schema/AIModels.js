import mongoose from 'mongoose';

const TrainingPatternSchema = new mongoose.Schema({
    input: [Number],
    output: [Number],

}, {timestamps: true});

const TrainedModelSchema = new mongoose.Schema({
    modelData: Object,
    lastUpdated: { type: Date, default: Date.now }
}, {timestamps: true});

export const TrainingPattern = mongoose.model('TrainingPattern', TrainingPatternSchema);
export const TrainedModel = mongoose.model('TrainedModel', TrainedModelSchema);