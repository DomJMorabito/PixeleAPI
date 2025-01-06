import express from 'express';
import serverless from 'serverless-http';
import { Amplify } from 'aws-amplify';
import { resendSignUpCode } from 'aws-amplify/auth';
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
        if (!secrets.USER_POOL_CLIENT_ID || !secrets.USER_POOL_ID) {
            throw new Error('Required Cognito credentials not found in secrets');
        }
        Amplify.configure({
            Auth: {
                Cognito: {
                    userPoolClientId: secrets.USER_POOL_CLIENT_ID,
                    userPoolId: secrets.USER_POOL_ID,
                }
            }
        });
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
        res.setHeader('Access-Control-Allow-Origin', 'https://pixele.gg');
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

        const normalizedUsername = username.trim().toLowerCase();

        try {
            const cognito = new AWS.CognitoIdentityServiceProvider();
            const secrets = await getSecrets();

            const params = {
                UserPoolId: secrets.USER_POOL_ID,
                Username: normalizedUsername
            };

            try {
                const userResponse = await cognito.adminGetUser(params).promise();
                const isConfirmed = userResponse.UserStatus === 'CONFIRMED';

                if (isConfirmed) {
                    return res.status(409).json({
                        message: 'This account is already verified.',
                        code: 'ALREADY_VERIFIED',
                        details: {
                            username
                        }
                    });
                }
            } catch (error) {
                if (error.code === 'UserNotFoundException') {
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: { username }
                    });
                }
            }

            await resendSignUpCode({ username: normalizedUsername });

            res.status(200).json({
                message: 'Successfully resent verification code.',
                code: 'RESEND_SUCCESS',
                details: {
                    username
                }
            });
        } catch (error) {
            console.error('Error resending verification code:', error);
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
    });
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};