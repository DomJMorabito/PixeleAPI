// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

// Utils Imports:

import { corsMiddleware } from './utils/middleware/cors.js';
import { initialize } from './utils/init/initialize';
import { getCognitoSecrets } from "./utils/aws/secrets.js";
import { validateInput } from './utils/middleware/validate-input.js';

let app;
let pool;

const appPromise = initialize().then(({ app: initializedApp, pool: initializedPool}) => {
    app = initializedApp;
    pool = initializedPool;

    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/verify', validateInput, async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        const { username, verificationCode } = req.body;

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