import express from 'express';
import serverless from 'serverless-http';
import { resendSignUpCode } from 'aws-amplify/auth';
import AWS from 'aws-sdk';

import { validateInput } from 'utils/middleware/validate-input.js';
import { corsMiddleware } from 'utils/middleware/cors.js';
import { getSecrets } from 'utils/aws/secrets.js';
import { initialize } from 'utils/init/initialize.js';

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

            const params = {
                UserPoolId: secrets.USER_POOL_ID,
                Username: username
            };

            try {
                const userResponse = await cognito.adminGetUser(params).promise();
                const isConfirmed = userResponse.UserStatus === 'CONFIRMED';

                if (isConfirmed) {
                    return res.status(409).json({
                        message: 'This account is already verified.',
                        code: 'ALREADY_VERIFIED',
                        details: {
                            username: username
                        }
                    });
                }
            } catch (error) {
                if (error.code === 'UserNotFoundException') {
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: {
                            username: username
                        }
                    });
                }
            }

            await resendSignUpCode({ username: username });

            res.status(200).json({
                message: 'Successfully resent verification code.',
                code: 'RESEND_SUCCESS',
                details: {
                    username: username
                }
            });
        } catch (error) {
            console.error('Error resending verification code:', error);
            if (error.name === 'LimitExceededException') {
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED',
                    details: {
                        error: error
                    }
                });
            }

            res.status(500).json({
                message: 'Failed to resend verification code.',
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