import mongoose from 'mongoose';

const UrlSubmissionSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    url: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    risk_score: { type: String, required: true },
    verdict: { type: String, required: true },
    source_ip: { type: String },
    
    awareness_feedback: { type: [String], default: [] }, 
    analysis: {
        ai_confidence: { type: String },
        heuristic_score: { type: Number },
        content_risk: { type: String }, 
        content_detail: { type: String },
        global_reports: { type: Number },
        malicious_engines: { type: [String], default: [] },
        categories: { type: [String], default: [] }
    }
});

const DetectionResultSchema = new mongoose.Schema({
    submission_id: { type: mongoose.Schema.Types.ObjectId, ref: 'UrlSubmission', required: true },
    layer: { type: String, required: true }, // e.g., 'ML', 'HEURISTIC', 'CONTENT', 'VIRUSTOTAL'
    score: { type: Number, required: true },
    evidence: { type: [String], default: [] }
});

const MissedPatternSchema = new mongoose.Schema({
    url: { type: String, required: true },
    features: { type: [Number], required: true }, // The 7-feature Array
    virustotal_flags: { type: Number, required: true },
    captured_at: { type: Date, default: Date.now }
});

const NeuralModelSchema = new mongoose.Schema({
    model_json: { type: Object, required: true }, // Mapped to TrainedModel's object data
    trained_at: { type: Date, default: Date.now },
    sample_count: { type: Number, required: true }
}, { timestamps: true });

const CommunityReviewSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    url: { type: String },
    verdict: { type: String },
    comment: { type: String, required: true },
    submitted_at: { type: Date, default: Date.now }
});

const GeneralReviewSchema = new mongoose.Schema({
    reviewer_name: { type: String, default: "Anonymous Guest" },
    comment: { type: String, required: true },
    submitted_at: { type: Date, default: Date.now }
});

export const UrlSubmission = mongoose.models.UrlSubmission || mongoose.model('UrlSubmission', UrlSubmissionSchema);
export const DetectionResult = mongoose.models.DetectionResult || mongoose.model('DetectionResult', DetectionResultSchema);
export const MissedPattern = mongoose.models.MissedPattern || mongoose.model('MissedPattern', MissedPatternSchema);
export const NeuralModel = mongoose.models.NeuralModel || mongoose.model('NeuralModel', NeuralModelSchema);
export const CommunityReview = mongoose.models.CommunityReview || mongoose.model('CommunityReview', CommunityReviewSchema);
export const GeneralReview = mongoose.models.GeneralReview || mongoose.model('GeneralReview', GeneralReviewSchema);