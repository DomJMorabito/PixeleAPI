import express from 'express';
import serverless from 'serverless-http';
import cookieParser from 'cookie-parser';
import { signOut, fetchAuthSession } from 'aws-amplify/auth';
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
    app.use(cookieParser());
    app.use((req, res, next) => {
        res.setHeader('Access-Control-Allow-Origin', 'https://pixele.gg');
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (req.method === 'OPTIONS') {
            return res.status(200).end();
        }
        console.log(`${req.method} ${req.path} - IP: ${req.ip}`);
        next();
    });

    app.post ('/users/logout', async (req, res) => {
        const sessionToken = req.cookies.pixele_session;

        if (!sessionToken) {
            return res.status(401).json({
                message: 'No active session found.',
                code: 'NO_SESSION',
                details: {
                    error: 'User is not logged in.'
                }
            });
        }

        try {
            try {
                const session = await fetchAuthSession();

                if (!session.tokens?.accessToken) {
                    console.error('Invalid session.');
                }
            } catch (error) {
                console.error('Error validating session', error);
            }

            await signOut();

            res.clearCookie('pixele_session', {
                httpOnly: true,
                secure: true,
                sameSite: 'lax',
                path: '/',
                domain: 'pixele.gg'
            });

            res.clearCookie('pixele_user', {
                httpOnly: false,
                secure: true,
                sameSite: 'lax',
                path: '/',
                domain: 'pixele.gg'
            });

            return res.status(200).json({
                message: 'Successfully logged out. See ya later!'
            });
        } catch (error) {
            console.error('Logout error:', error);

            res.clearCookie('pixele_session', {
                httpOnly: true,
                secure: true,
                sameSite: 'lax',
                path: '/',
                domain: 'pixele.gg'
            });

            res.clearCookie('pixele_user', {
                httpOnly: false,
                secure: true,
                sameSite: 'lax',
                path: '/',
                domain: 'pixele.gg'
            });

            return res.status(500).json({
                message: 'Failed to complete logout.',
                code: 'LOGOUT_FAILED',
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