import brain from 'brain.js';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { captureMissedPattern } from './retrain.js';
import { NeuralModel, UrlSubmission, DetectionResult } from '../schema/Schemas.js';

let cachedNet = null;

const getAiBrain = async () => {
    if (cachedNet) return cachedNet;
    const net = new brain.NeuralNetwork({ hiddenLayers: [12, 8, 4] });
    try {
        const savedModel = await NeuralModel.findOne({}).lean();
        if (savedModel && savedModel.model_json) {
            net.fromJSON(savedModel.model_json);
            console.log("✅ AI Engine running on optimized Neural_Model dataset.");
        } else {
            console.log("⚠️ Neural_Model empty. Bootstrapping with baseline vectors...");
            net.train([
                { input: [0, 0, 0, 0, 0, 0, 0], output: [0] },
                { input: [1, 1, 1, 1, 1, 1, 1], output: [1] },
                { input: [0, 0, 1, 0, 0, 0, 1], output: [0.85] },
                { input: [0, 1, 0, 0, 0, 0, 0], output: [0.45] },
                { input: [0, 0, 0, 0, 1, 1, 0], output: [0.75] },
                { input: [1, 0, 0, 1, 0, 0, 1], output: [0.95] },
                { input: [0, 1, 1, 0, 1, 0, 0], output: [0.80] },
                { input: [0, 0, 0, 0, 1, 0, 0], output: [1] }
            ], { iterations: 5000 });
        }
    } catch (e) {
        console.error("Core Engine boot crash, executing hardcoded safety array:", e);
        net.train([{ input: [0, 0, 0, 0, 0, 0, 0], output: [0] }, { input: [1, 1, 1, 1, 1, 1, 1], output: [1] }]);
    }
    cachedNet = net;
    return cachedNet;
};

const calculateFinalScore = (ml, heurScore, globalReports, contentRisk) => {
    let score = 0;
    if (globalReports > 0) score += (globalReports >= 5 ? 100 : globalReports * 20);
    if (contentRisk === "CRITICAL") score += 50;
    if (contentRisk === "HIGH") score += 30;
    if (contentRisk === "MEDIUM") score += 15;
    score += heurScore;
    score += (ml * 20);
    return Math.min(Math.round(score), 100).toFixed(2);
};

const Scanner = {
    generateInputVector: (url) => {
        const urlObj = Scanner.prepareUrl(url);
        if (!urlObj) return [0, 0, 0, 0, 0, 0, 0];
        const suspiciousTLDs = ['.xyz', '.top', '.gq', '.tk', '.ml', '.vip', '.cfd', '.click', '.monster', '.rest', '.cf', '.shop', '.site'];
        const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(urlObj.hostname);
        const entropy = Scanner.getEntropy(urlObj.hostname);
        const pathDepth = urlObj.pathname.split('/').filter(Boolean).length;

        return [
            urlObj.protocol === 'https:' ? 0 : 1,
            url.length > 60 ? 1 : 0,
            urlObj.hostname.split('.').length > 3 ? 1 : 0,
            isIP ? 1 : 0,
            suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld)) ? 1 : 0,
            entropy > 3.7 ? 1 : 0,
            pathDepth > 2 ? 1 : 0
        ];
    },

    getEntropy: (str) => {
        const len = str.length;
        const frequencies = Array.from(str).reduce((acc, char) => {
            acc[char] = (acc[char] || 0) + 1;
            return acc;
        }, {});
        return Object.values(frequencies).reduce((sum, f) => {
            const p = f / len;
            return sum - p * Math.log2(p);
        }, 0);
    },

    prepareUrl: (url) => {
        let normalized = url.trim();
        if (!/^https?:\/\//i.test(normalized)) normalized = 'http://' + normalized;
        try { return new URL(normalized); } catch (e) { return null; }
    },

    analyzeHeuristics: (url) => {
        const urlObj = Scanner.prepareUrl(url);
        if (!urlObj) return { score: 100, flags: ["Fatal Error: Invalid URL"] };
        const flags = [];
        let score = 0;
        if (/[а-я|α-ω|ɩ|\|]/.test(urlObj.hostname)) {
            score += 60;
            flags.push("Homograph Attack (Look-alike characters) detected.");
        }
        const keywords = ['login', 'verify', 'update', 'secure', 'bank', 'office', 'wallet', 'crypto', 'support', 'signin', 'account', 'temu', 'gift'];
        keywords.forEach(word => {
            if (url.toLowerCase().includes(word)) {
                score += 25;
                flags.push(`Deceptive keyword detected: ${word}.`);
            }
        });
        const brands = ['microsoft', 'google', 'facebook', 'amazon', 'apple', 'paypal', 'netflix', 'binance', 'metamask', 'temu'];
        brands.forEach(brand => {
            if (urlObj.hostname.includes(brand) && !urlObj.hostname.endsWith(`${brand}.com`) && !urlObj.hostname.endsWith(`.${brand}.com`)) {
                score += 50;
                flags.push(`High-Risk Brand Impersonation: ${brand}.`);
            }
        });
        return { score: Math.min(score, 100), flags };
    },

    analyzeContent: async (url) => {
        const urlObj = Scanner.prepareUrl(url);
        try {
            const { data } = await axios.get(urlObj.href, {
                timeout: 6000,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0' }
            });
            const $ = cheerio.load(data);
            const hasPassword = $('input[type="password"]').length > 0;
            const text = $('body').text().toLowerCase();
            const urgency = /action required|suspended|log in immediately|confirm identity|unauthorized|account locked/i.test(text);
            const formAction = $('form').attr('action');
            if (formAction && !formAction.startsWith('/') && !formAction.includes(urlObj.hostname)) {
                return { risk: "CRITICAL", detail: "Suspicious Form Action: Data sent to external domain." };
            }
            if (hasPassword && urlObj.protocol !== 'https:') return { risk: "CRITICAL", detail: "Unencrypted Password Form (No HTTPS)." };
            if (urgency) return { risk: "HIGH", detail: "Social Engineering detected." };
            return { risk: "LOW", detail: "No obvious malicious content found." };
        } catch (e) {
            return { risk: "MEDIUM", detail: "Site Unreachable or Scanner Blocked (Potential Cloaking)." };
        }
    },

    checkAPI: async (url) => {
        try {
            const urlId = Buffer.from(url).toString('base64').replace(/=/g, "");
            const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                headers: { 'x-apikey': process.env.VT_API_KEY }
            });
            return res.data.data.attributes;
        } catch (err) { return null; }
    },

    getFullAnalysis: async (url, activeUserId = null, clientIp = "127.0.0.1") => {
        const net = await getAiBrain();

        const [heur, cont, vtAttributes] = await Promise.all([
            Scanner.analyzeHeuristics(url),
            Scanner.analyzeContent(url),
            Scanner.checkAPI(url)
        ]);

        const inputDNA = Scanner.generateInputVector(url);
        const ml = net.run(inputDNA)[0];

        const stats = vtAttributes?.last_analysis_stats;
        const results = vtAttributes?.last_analysis_results || {};
        const globalReports = stats ? (stats.malicious || 0) + (stats.suspicious || 0) : 0;
        const calculatedRisk = calculateFinalScore(ml, heur.score, globalReports, cont.risk);

        if (globalReports > 5 && ml < 0.4) {
            captureMissedPattern(inputDNA, url, globalReports);
        }

        const maliciousEngines = Object.keys(results)
            .filter(engine => results[engine].category === 'malicious');
        const categories = vtAttributes?.categories ? Object.values(vtAttributes.categories) : [];
        const uniqueCategories = [...new Set(categories)];

        let finalFeedback = [...heur.flags];
        if (globalReports > 0) finalFeedback.unshift(`Threat verified by ${globalReports} global sources.`);
        if (cont.risk === "CRITICAL" || cont.risk === "HIGH") finalFeedback.push(`Malicious Content detected: ${cont.detail}`);
        if (cont.detail.includes("Cloaking")) finalFeedback.push("Evasive behavior detected: Site is attempting to hide from scanners.");
        if (finalFeedback.length === 0 && ml < 0.4) finalFeedback.push("URL structure and behavior appear consistent with safe patterns.");

        const finalVerdict = (calculatedRisk >= 50 || globalReports > 0) ? 'MALICIOUS' : 'SAFE';

        try {
            const submission = await UrlSubmission.create({
                user_id: activeUserId || null,
                url: url,
                risk_score: calculatedRisk,
                verdict: finalVerdict,
                source_ip: clientIp,
                awareness_feedback: finalFeedback,
                analysis: {
                    ai_confidence: `${(ml * 100).toFixed(2)}%`,
                    heuristic_score: heur.score,
                    content_risk: cont.risk,
                    content_detail: cont.detail,
                    global_reports: globalReports,
                    malicious_engines: maliciousEngines, 
                    categories: uniqueCategories
                }
            });

            // Write matching tracking documents for DetectionResult table entries
            await DetectionResult.insertMany([
                { submission_id: submission._id, layer: 'ML', score: Math.round(ml * 100), evidence: [`Vector: [${inputDNA.join(',')}]`] },
                { submission_id: submission._id, layer: 'HEURISTIC', score: heur.score, evidence: heur.flags },
                { submission_id: submission._id, layer: 'CONTENT', score: cont.risk === 'CRITICAL' ? 100 : cont.risk === 'HIGH' ? 70 : 30, evidence: [cont.detail] },
                { submission_id: submission._id, layer: 'VIRUSTOTAL', score: globalReports, evidence: maliciousEngines }
            ]);
        } catch (dbErr) {
            console.error("⚠️ Failed executing pipeline writes for ERD log schemas:", dbErr);
        }

        return {
            verdict: finalVerdict,
            riskScore: calculatedRisk,
            url: url,
            awarenessFeedback: finalFeedback,
            analysis: {
                aiConfidence: `${(ml * 100).toFixed(2)}%`,
                heuristicScore: heur.score,
                contentRisk: cont.risk,
                contentDetail: cont.detail,
                globalReports: globalReports,
                maliciousEngines: maliciousEngines.length,
                categories: uniqueCategories
            }
        };
    }
};

export default Scanner;