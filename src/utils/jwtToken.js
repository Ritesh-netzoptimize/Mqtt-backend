
import jwt from 'jsonwebtoken';

// Create a token for a user id (used for simple session tokens)
export const createSecretToken = (userId) => {
    const SECRET = process.env.SECRET_KEY || 'change_this_secret_in_production';
    return jwt.sign({ sub: userId }, SECRET, {
        expiresIn: '1h',
        algorithm: 'HS256',
    });
}

const generateToken = (user) => {
    const SECRET = process.env.SECRET_KEY || 'change_this_secret_in_production';

    const token = jwt.sign({
        sub: user._id,
        email: user.email,
        aud: 'api.example.com',
        iss: 'api.example.com',
    }, SECRET, {
        expiresIn: '1h',
        algorithm: 'HS256'
    });

    return token;
}

export default generateToken;