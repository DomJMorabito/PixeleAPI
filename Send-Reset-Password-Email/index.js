// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

// Utils Imports:

import { getSecrets } from './utils/aws/secrets.js';
import { initialize } from './utils/init/initialize.js';
import { corsMiddleware } from "./utils/middleware/cors.js";
import { validateInput } from './utils/middleware/validate-input.js';

let app;

const appPromise = initialize().then(initializedApp => {
    app = initializedApp;
    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/reset-password/send-email', validateInput, async (req, res) => {
        const secrets = await getSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        let { identifier } = req.body;

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

            if (user.UserStatus !== 'CONFIRMED') {
                return res.status(400).json({
                    message: 'Account not verified.',
                    code: 'UNCONFIRMED_ACCOUNT',
                    details: {
                        username: username,
                        email: email
                    }
                });
            }

            const forgotPasswordParams = {
                ClientId: secrets.USER_POOL_CLIENT_ID,
                Username: username
            }

            await cognito.forgotPassword(forgotPasswordParams).promise();

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