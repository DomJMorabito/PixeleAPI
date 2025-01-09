import express from 'express';
import serverless from 'serverless-http';
import { confirmResetPassword } from 'aws-amplify/auth';
import AWS from 'aws-sdk';

import { corsMiddleware } from './utils/middleware/cors.js';
import { initialize } from './utils/init/initialize.js';
import { getSecrets } from './utils/aws/secrets.js';
import { validateInputs } from './utils/middleware/validate-inputs.js';

let app;
const appPromise = initialize().then(initializedApp => {
    app = initializedApp;
    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/reset-password/confirm-new-password', validateInputs, async (req, res) => {
        const { username, confirmationCode, newPassword } = req.body;

        try {
            const cognito = new AWS.CognitoIdentityServiceProvider();
            const secrets = await getSecrets();

            const params = {
                UserPoolId: secrets.USER_POOL_ID,
                Username: username
            }

            try {
                await cognito.adminGetUser(params).promise();
            } catch (error) {
                if (error.code === 'UserNotFoundException') {
                    return res.status(404).json({
                        message: 'User not found.',
                        code: 'USER_NOT_FOUND',
                        details: {
                            username: username,
                            error: error
                        }
                    });
                }
            }

            await confirmResetPassword({
                username: username,
                confirmationCode: confirmationCode,
                newPassword
            });

            res.status(200).json({
                message: 'Successfully reset password.',
                code: 'PASSWORD_RESET_SUCCESS',
                details: {
                    username: username
                }
            });
        } catch (error) {
            console.error('Error confirming password reset:', error);
            if (error.name === 'CodeMismatchException') {
                return res.status(400).json({
                    message: 'Invalid confirmation code.',
                    code: 'INVALID_CODE',
                    details: {
                        code: confirmationCode,
                        error: error
                    }
                });
            }
            if (error.name === 'ExpiredCodeException') {
                return res.status(400).json({
                    message: 'Confirmation code has expired.',
                    code: 'EXPIRED_CODE',
                    details: {
                        code: confirmationCode,
                        error: error
                    }
                });
            }
            if (error.name === 'LimitExceededException') {
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