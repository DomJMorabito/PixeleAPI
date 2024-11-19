import express from 'express';
import serverless from 'serverless-http';
import { Amplify } from 'aws-amplify';
import { resendSignUpCode } from 'aws-amplify/auth';

Amplify.configure({
    Auth: {
        Cognito: {
            userPoolClientId: process.env.AWS_USER_POOL_CLIENT_ID,
            userPoolId: process.env.AWS_USER_POOL_ID,
        }
    }
});

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    console.log(`${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

app.post('/users/resend-verification-code', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({
            message: 'Username is required',
            code: 'MISSING_FIELDS',
            details: {
                missingFields: ['username']
            }
        });
    }

    try {
        await resendSignUpCode({ username: username.trim() });
        res.status(200).json({
            message: 'Successfully resent verification code.',
            code: 'RESEND_SUCCESS',
            details: {
                username
            }
        });
    } catch (error) {
        console.error('Error resending verification code:', error);
        if (error.name === 'UserNotFoundException') {
            return res.status(404).json({
                message: 'User not found.',
                code: 'USER_NOT_FOUND',
                details: { username }
            });
        }
        if (error.name === 'LimitExceededException') {
            return res.status(429).json({
                message: 'Too many attempts. Please try again later.',
                code: 'RATE_LIMIT_EXCEEDED',
                details: {
                    username,
                    retryAfter: '30s'
                }
            });
        }

        res.status(500).json({
            message: 'Failed to resend verification code.',
            code: 'SERVER_ERROR',
            details: {
                error: error.message
            }
        });

    }
})

export const handler = serverless(app);