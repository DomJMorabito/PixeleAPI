// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

// Utils Imports:

import { validateInput } from './utils/middleware/validate-input.js';
import { corsMiddleware } from './utils/middleware/cors.js';
import { getSecrets } from './utils/aws/secrets.js';
import { initialize } from './utils/init/initialize.js';

let app;
const appPromise = initialize().then(initializedApp => {
    app = initializedApp;
    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/resend-verification-code', validateInput, async (req, res) => {
        const { username } = req.body;

        try {
            const cognito = new AWS.CognitoIdentityServiceProvider();
            const secrets = await getSecrets();

            let userResponse;
            const userParams = {
                UserPoolId: secrets.USER_POOL_ID,
                Username: username
            };

            try {
                userResponse = await cognito.adminGetUser(userParams).promise();
            } catch (error) {
                if (error.code === 'NotAuthorizedException' || error.code === 'UserNotFoundException') {
                    return res.status(401).json({
                        message: 'Invalid credentials.',
                        code: 'INVALID_CREDENTIALS'
                    });
                }
            }

            if (userResponse.UserStatus === 'CONFIRMED') {
                return res.status(409).json({
                    message: 'This account is already verified.',
                    code: 'ALREADY_VERIFIED'
                });
            }

            const resendSignUpCodeParams = {
                ClientId: secrets.USER_POOL_CLIENT_ID,
                Username: username
            }

            await cognito.resendConfirmationCode(resendSignUpCodeParams).promise();

            res.status(200).json({
                message: 'Successfully resent verification code.',
                code: 'RESEND_SUCCESS'
            });
        } catch (error) {
            console.error('Error resending verification code:', error);
            if (error.code === 'LimitExceededException' || error.code === 'TooManyRequestsException') {
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
    });
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};