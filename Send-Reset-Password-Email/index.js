import express from 'express';
import serverless from 'serverless-http';
import { resetPassword } from 'aws-amplify/auth';
import { Amplify } from 'aws-amplify';
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

    app.post('/users/reset-password/send-email', async (req, res) => {
        const secrets = await getSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        let { identifier } = req.body;

        if (!identifier) {
            return res.status(400).json({
                message: 'Username or Email is required.',
                code: 'MISSING_FIELDS',
                details: {
                    missingFields: [
                        !identifier && 'identifier'
                    ].filter(Boolean)
                }
            });
        }

        identifier = identifier.toLowerCase();

        try {
            let params = {
                UserPoolId: secrets.USER_POOL_ID,
                Filter: `username = "${identifier}"`,
                Limit: 1
            };

            let userData = await cognito.listUsers(params).promise();

            if (!userData.Users || userData.Users.length === 0) {
                params.Filter = `email = "${identifier}"`;
                userData = await cognito.listUsers(params).promise();
            }

            if (!userData.Users || userData.Users.length === 0) {
                return res.status(404).json({
                    message: 'No account found with this identifier.',
                    code: 'USER_NOT_FOUND',
                    details: {
                        identifier: identifier,
                    }
                });
            }

            const user = userData.Users[0];
            const username = user.Username;
            const email = user.Attributes.find(attribute => attribute.Name === 'email')?.Value;

            await resetPassword({ username });

            return res.status(200).json({
                message: 'Password reset email sent successfully.',
                code: 'EMAIL_SEND_SUCCESS',
                details: {
                    email,
                    username
                }
            });
        } catch (error) {
            switch (error.code) {
                case 'UserNotFoundException':
                    return res.status(404).json({
                        message: 'No account found with this email address.',
                        code: 'USER_NOT_FOUND',
                        details: {
                            identifier: identifier,
                            error: error
                        }
                    });
                case 'InvalidParameterException':
                    return res.status(400).json({
                        message: 'Invalid email format.',
                        code: 'INVALID_EMAIL',
                        details: {
                            identifier: identifier,
                            error: error
                        }
                    });
                case 'TooManyRequestsException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED',
                        details: {
                            error: error
                        }
                    });
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Request limit exceeded. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED',
                        details: {
                            error: error
                        }
                    });
                default:
                    console.error('Error sending email:', error);
                    return res.status(500).json({
                        message: 'Internal server error.',
                        code: 'SERVER_ERROR',
                        details: {
                            error: error
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