import express from 'express';
import serverless from 'serverless-http';
import { Amplify } from 'aws-amplify';
import { confirmResetPassword } from 'aws-amplify/auth';
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

    app.post('/users/reset-password/confirm-new-password', async (req, res) => {
        const { username, confirmationCode, newPassword } = req.body;

        if (!username || !confirmationCode || !newPassword) {
            return res.status(400).json({
                message: 'All fields are required.',
                code: 'MISSING_FIELDS',
                details: {
                    missingFields: [
                        !username && 'username',
                        !confirmationCode && 'confirmationCode',
                        !newPassword && 'newPassword'
                    ].filter(Boolean)
                }
            });
        }

        if (!validatePassword(newPassword)) {
            return res.status(400).json({
                message: 'Password requirements not met.',
                code: 'INVALID_PASSWORD',
                details: {
                    minLength: 8,
                    requiresNumber: true,
                    requiresSpecialChar: true
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
            }

            try {
                await cognito.adminGetUser(params).promise();
            } catch (error) {
                if (error.code === 'UserNotFoundException') {
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: { username }
                    });
                }
            }

            await confirmResetPassword({
                username: normalizedUsername,
                confirmationCode: confirmationCode,
                newPassword
            });

            res.status(200).json({
                message: 'Successfully reset password.',
                code: 'PASSWORD_RESET_SUCCESS',
                details: {
                    username
                }
            });
        } catch (error) {
            console.error('Error confirming password reset:', error);

            if (error.name === 'CodeMismatchException') {
                return res.status(400).json({
                    message: 'Invalid confirmation code.',
                    code: 'INVALID_CODE',
                    details: {
                        username,
                        confirmationCode
                    }
                });
            }

            if (error.name === 'ExpiredCodeException') {
                return res.status(400).json({
                    message: 'Confirmation code has expired.',
                    code: 'EXPIRED_CODE',
                    details: {
                        username,
                        confirmationCode
                    }
                });
            }

            if (error.name === 'LimitExceededException') {
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED',
                    details: {
                        retryAfter: '30s'
                    }
                });
            }
            return res.status(500).json({
                message: 'Internal Server Error',
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

// Helper function to validate password structure
const validatePassword = (password) => {
    const lengthValid = password.length >= 8;
    const containsNumber = /\d/.test(password);
    const containsSpecial = /[^A-Za-z0-9]/.test(password);

    return lengthValid && containsNumber && containsSpecial;
};