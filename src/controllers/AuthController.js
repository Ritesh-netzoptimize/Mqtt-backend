import User from "../models/users.js";
import generateToken, { createSecretToken } from "../utils/jwtToken.js";
import jwt from 'jsonwebtoken';
import bcrypt from "bcryptjs";
import randToken from "rand-token";
import Token from "../models/token.js";

const createRefreshToken = () => randToken.uid(256)

const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(12);
    return await bcrypt.hash(password, salt);
}

export const signup = async (req, res) => {

    const { email, password, firstName, lastName } = req.body

    const hashedPassword = await hashPassword(password)
    const userData = {
        email: email,
        firstName: firstName,
        lastName: lastName,
        password: hashedPassword,
    }

    const existingUser = await User.findOne({ email: email }).lean()

    if (existingUser) {
        return res.status(400).json({
            success: "false",
            message: 'Email already exists'
        })
    }

    const user = new User(userData)
    const savedUser = await user.save()

    if (savedUser) {
        const accessToken = generateToken(savedUser);
        const refreshToken = createRefreshToken();

        // Store refresh token
        const tokenDoc = new Token({
            refreshToken,
            user: savedUser._id
        });
        await tokenDoc.save();

        // Get expiry from access token
        const decodedToken = jwt.decode(accessToken);
        const expiresAt = decodedToken.exp;

        return res.status(200).json({
            success: true,
            user,
            message: 'User created successfully',
            accessToken,
            // refreshToken,
            expiresAt
        });
    }
}

export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }
        const accessToken = createSecretToken(user._id);
        const refreshToken = createRefreshToken();

        // Store refresh token
        const tokenDoc = new Token({
            refreshToken,
            user: user._id
        });
        await tokenDoc.save();

        res.status(200).json({
            success: true,
            message: "User logged in successfully",
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName
            },
            accessToken,
            // refreshToken
        });
        // response sent; do not call next() to avoid "Headers already sent" issues
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
};

export const getRefreshToken = async (req, res) => {
    const { refreshToken } = req.body
    try {
        const tokenDoc = await Token.findOne({ refreshToken }).select('user');

        if (!tokenDoc) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        const existingUser = await User.findOne({ _id: tokenDoc.user });

        if (!existingUser) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        const token = generateToken(existingUser);
        return res.json({ accessToken: token });
    } catch (err) {
        return res.status(500).json({ message: 'Could not refresh token' })
    }
}

export const attachUser = (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    if (!authHeader) {
        return res.status(401).json({ message: 'Authentication invalid' });
    }

    // Accept both "Bearer <token>" and raw token in Authorization header
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    const SECRET = process.env.SECRET_KEY || 'change_this_secret_in_production';

    try {
        const decodedToken = jwt.verify(token, SECRET);
        if (!decodedToken) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decodedToken;
        return next();
    } catch (err) {
        console.error('Token verification failed:', err.message);
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};
