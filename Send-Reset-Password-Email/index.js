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
            let userData;
            try {
                const userParams = {
                    UserPoolId: secrets.USER_POOL_ID,
                    Filter: identifier.includes('@')
                        ? `email = "${identifier}"`
                        : `username = "${identifier}"`,
                    Limit: 1
                };

                userData = await cognito.listUsers(userParams).promise();

                if ((!userData.Users || userData.Users.length === 0) && !identifier.includes('@')) {
                    userData = await cognito.listUsers({
                        ...userParams,
                        Filter: `email = "${identifier}"`
                    }).promise();
                }

                if (!userData.Users || userData.Users.length === 0) {
                    return res.status(401).json({
                        message: 'Invalid credentials.',
                        code: 'INVALID_CREDENTIALS'
                    });
                }
            } catch (error) {
                console.error('Error looking up user:', error);
            }

            const user = userData.Users[0];
            const username = user.Username;
            const email = user.Attributes.find(attribute => attribute.Name === 'email')?.Value;

            if (user.UserStatus !== 'CONFIRMED') {
                try {
                    await cognito.resendConfirmationCode({
                        ClientId: secrets.USER_POOL_CLIENT_ID,
                        Username: username
                    }).promise();

                    return res.status(403).json({
                        message: 'Email verification required. Confirmation code has been resent.',
                        code: 'CONFIRM_SIGN_UP',
                        params: {
                            username: username,
                            email: email
                        }
                    })
                } catch (resendError) {
                    console.error('Error resending verification code:', resendError);
                    if (resendError.code === 'LimitExceededException' || resendError.code === 'TooManyRequestsException') {
                        return res.status(429).json({
                            message: 'Too many attempts. Please try again later.',
                            code: 'RATE_LIMIT_EXCEEDED'
                        });
                    }

                    res.status(500).json({
                        message: 'Failed to resend verification code.',
                        code: 'SERVER_ERROR'
                    });
                }
            }

            const forgotPasswordParams = {
                ClientId: secrets.USER_POOL_CLIENT_ID,
                Username: username
            }

            await cognito.forgotPassword(forgotPasswordParams).promise();

            return res.status(200).json({
                message: 'Password reset email sent successfully.',
                code: 'EMAIL_SEND_SUCCESS'
            });
        } catch (error) {
            console.error('Error sending email:', error);
            switch (error.code) {
                case 'TooManyRequestsException':
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED',
                    })
                default:
                    return res.status(500).json({
                        message: 'Internal server error.',
                        code: 'SERVER_ERROR'
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