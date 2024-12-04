import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

const secretsManager = new AWS.SecretsManager();

async function getSecrets() {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.SECRET_ID
        }).promise();
        try {
            return JSON.parse(data.SecretString);
        } catch (parseError) {
            console.error('Error parsing secrets:', parseError);
            throw new Error('Invalid secret format');
        }
    } catch (error) {
        console.error('Error retrieving secrets:', error);
        throw error;
    }
}

async function initialize() {
    try {
        const secrets = await getSecrets();
        if (!secrets.USER_POOL_CLIENT_ID) {
            throw new Error('Required Cognito credentials not found in secrets');
        }
        return express();
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}

let app;
const appPromise = initialize().then(initializedApp => {
    app = initializedApp;
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

    app.post('/users/verify', async (req, res) => {
        const secrets = await getSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        const { username, verificationCode } = req.body;

        if (!username || !verificationCode) {
            return res.status(400).json({
                message: 'All fields are required.',
                code: 'MISSING_FIELDS',
                details: {
                    missingFields: [
                        !username && 'username',
                        !verificationCode && 'verificationCode',
                    ].filter(Boolean)
                }
            });
        }

        const params = {
            ClientId: secrets.USER_POOL_CLIENT_ID,
            Username: username,
            ConfirmationCode: verificationCode,
        }

        try {
            await cognito.confirmSignUp(params).promise();
            res.status(200).json({
                message: 'Verification Successful!',
                code: 'VERIFICATION_SUCCESS',
                details: { username }
            });
        } catch (error) {
            console.error('Verification error:', error);

            switch (error.code) {
                case 'CodeMismatchException':
                    return res.status(400).json({
                        message: 'Verification code is incorrect.',
                        code: 'INVALID_CODE',
                        details: { username }
                    });
                case 'UserNotFoundException':
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: { username }
                    });
                case 'NotAuthorizedException':
                    return res.status(409).json({
                        message: 'This account is already verified.',
                        code: 'ALREADY_VERIFIED',
                        details: { username }
                    });
                case 'ExpiredCodeException':
                    return res.status(410).json({
                        message: 'Verification code has expired. Please request a new one.',
                        code: 'EXPIRED_CODE',
                        details: { username }
                    });
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED',
                        details: {
                            username,
                            retryAfter: '30s'
                        }
                    });
                default:
                    res.status(500).json({
                        message: 'Unable to complete verification. Please try again later.',
                        code: 'SERVER_ERROR',
                        details: {
                            error: error.message
                        }
                    });
            }
        }
    });
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};