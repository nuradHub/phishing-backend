import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import analyzeRoute from './routes/analyzeRoute.js';
import ReviewRoute from './routes/ReviewRoute.js';
import UserRoute from './routes/UserRoute.js';
import GeneralReviewRoute from './routes/GeneralReviewRoute.js';
import AdminTelemetryRoute from './routes/AdminTelemetryRoute.js';
import connectDB from './db.js';

// --- DATABASE CONNECTION ---
connectDB()

const app = express();

app.use(cors({
    origin: process.env.FRONTEND_URL,
    methods: ['POST', 'GET', 'DELETE', 'PUT'],
    credentials: true
}));

app.use(express.json());

app.options('/{*slack}', cors())


app.get('/', (req, res) => res.status(200).send('✅✅ Server is Running'));
app.post('/', (req, res) => res.status(200).send('✅✅ Server is Running'));

app.use('/', analyzeRoute);
app.use('/', ReviewRoute);
app.use('/', UserRoute);
app.use('/', GeneralReviewRoute);
app.use('/', AdminTelemetryRoute);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Phishing Detection System Active on Port ${PORT}`);
});