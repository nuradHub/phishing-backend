import mongoose from 'mongoose';
import bcrypt from 'bcryptjs'

const UserSchema = new mongoose.Schema({
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: 'user'
    }
}, { timestamps: true });

UserSchema.pre('save', async function () {
    if (!this.isModified('password')) return;

    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    } catch (err) {
        return next(err);
    }
})

UserSchema.methods.comparePassword = async function (currentPassword) {
    return await bcrypt.compare(currentPassword, this.password)
}

export const User = mongoose.model('User', UserSchema);