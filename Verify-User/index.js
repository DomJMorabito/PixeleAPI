import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';
import mysql from 'mysql2/promise';

const secretsManager = new AWS.SecretsManager();

async function getDbSecrets() {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.DB_SECRET_ID
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

let pool;

async function initialize() {
    try {
        const [dbSecrets, cognitoSecrets] = await Promise.all([
            getDbSecrets(),
            getCognitoSecrets()
        ]);
        if (!cognitoSecrets.USER_POOL_CLIENT_ID || !cognitoSecrets.USER_POOL_ID) {
            throw new Error('Required Cognito credentials not found in secrets');
        } else if (!dbSecrets.host || !dbSecrets.username || !dbSecrets.password || !dbSecrets.port) {
            throw new Error('Required RDS credentials not found in secrets');
        }

        pool = mysql.createPool({
            host: dbSecrets.host,
            user: dbSecrets.username,
            password: dbSecrets.password,
            database: 'pixele',
            port: dbSecrets.port,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 5
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

    app.post('/users/verify', async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
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
            ClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
            Username: username,
            ConfirmationCode: verificationCode,
        }

        try {
            await cognito.confirmSignUp(params).promise();

            const connection = await pool.getConnection();
            try {
                await connection.beginTransaction();

                const [result] = await connection.execute(
                    'UPDATE users SET confirmed = TRUE WHERE username = ?',
                    [username]
                );

                if (result.affectedRows === 0) {
                    await connection.rollback();
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: { username }
                    });
                }

                await connection.commit();

                res.status(200).json({
                    message: 'Verification Successful!',
                    code: 'VERIFICATION_SUCCESS',
                    details: { username }
                });
            } catch (dbError) {
                console.error('Database error:', dbError);
                await connection.rollback();
                return res.status(500).json({
                    message: 'Database error occurred. Please try again later.',
                    code: 'DATABASE_ERROR',
                    details: {
                        username
                    }
                });
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error('Verification error:', error);
            switch (error.code) {
                case 'UserNotFoundException':
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: { username }
                    });
                case 'CodeMismatchException':
                    return res.status(400).json({
                        message: 'Verification code is incorrect.',
                        code: 'INVALID_CODE',
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
                            error
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