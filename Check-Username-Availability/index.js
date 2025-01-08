import AWS from 'aws-sdk';
import express from "express";
import serverless from 'serverless-http';

const secretsManager = new AWS.SecretsManager();

async function getCognitoSecrets() {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.AUTH_SECRET_ID
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
        const secrets = await getCognitoSecrets();
        if (!secrets.USER_POOL_ID) {
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
        res.setHeader('Access-Control-Allow-Origin', 'https://pixele.gg');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (req.method === 'OPTIONS') {
            return res.status(200).end();
        }
        console.log(`${req.method} ${req.path} - IP: ${req.ip}`);
        next();
    });

    app.get('/users/check-username-availability', async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        const username = req.query.username?.toLowerCase();

        if (!username) {
            return res.status(400).json({
                message: 'Username is required.',
                code: 'MISSING_FIELDS',
                details: {
                    providedUsername: username
                }
            });
        }

        try {
            const params = {
                UserPoolId: cognitoSecrets.USER_POOL_ID,
                Filter: `username = "${username.replace(/"/g, '\\"')}"`,
                Limit: 1
            };
            const result = await cognito.listUsers(params).promise();
            return res.status(200).json({
                taken: result.Users && result.Users.length > 0
            });
        } catch (error) {
            console.error('Error checking duplicate username:', error);
            if (error.code === 'LimitExceededException') {
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED',
                    details: {
                        error: error
                    }
                });
            }
            return res.status(500).json({
                message: 'Internal Server Error',
                code: 'SERVER_ERROR',
                details: {
                    error: error
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