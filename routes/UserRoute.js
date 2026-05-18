import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { User } from '../schema/UserSchema.js';
import UserProtected from '../middleware/UserMIddleWare.js';

const router = express.Router();

router.post('/api/auth/register', async (req, res) => {
    const { fullname, email, password } = req.body;

    try {
        // Validation checks
        if (!fullname || !email || !password) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        // Check if user already exists
        const userExists = await User.findOne({ email: email.toLowerCase() });
        if (userExists) {
            return res.status(400).json({ message: 'An account with this email already exists.' });
        }

        // Create and save user to MongoDB
        const newUser = await User.create({
            fullname,
            email: email.toLowerCase(),
            password: password
        });

        return res.status(201).json({ 
            message: 'User registered successfully!',
            userId: newUser._id 
        });

    } catch (err) {
        console.error("Registration Error:", err);
        return res.status(500).json({ message: 'Server configuration error during signup.' });
    }
});

router.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Validation checks
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password credentials.' });
        }

        // 3. Compare passwords using your schema hook methods
        const verifyPassword = await user.comparePassword(password);
        if (!verifyPassword) {
            return res.status(400).json({ message: 'Invalid email or password credentials.' });
        }

        // 4. Generate JSON Web Token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        return res.status(200).json({
            message: 'Login successful!',
            token,
            user: {
                id: user._id,
                fullname: user.fullname,
                email: user.email,
                role: user.role
            }
        });

    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ message: 'Server configuration error during login.' });
    }
});

router.get('/api/current-user', UserProtected, async (req, res)=> {
    try{
     const user = await User.findById(req.userId).select('-password')

     if(!user) return res.status(404).json({message: 'No Current User'})
    
    return res.status(200).json(user)

    }catch(err){
        console.error("Login Error:", err);
        return res.status(500).json({ message: 'Server configuration error.' }); 
    }
})

export default router;