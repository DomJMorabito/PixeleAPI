// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

// Utils Imports:

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

            let userData;
            try {
                userData = await cognito.adminGetUser(params).promise();
            } catch (error) {
                if (error.code === 'UserNotFoundException') {
                    return res.status(401).json({
                        message: 'Invalid credentials.',
                        code: 'INVALID_CREDENTIALS'
                    });
                }
            }

            if (userData.UserStatus !== 'CONFIRMED') {
                const email = userData.UserAttributes.find(attribute => attribute.Name === 'email')?.Value;
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
                    if (resendError.code === 'LimitExceededException') {
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

            const confirmPasswordParams = {
                ClientId: secrets.USER_POOL_CLIENT_ID,
                Username: username,
                ConfirmationCode: confirmationCode,
                Password: newPassword
            }

            await cognito.confirmForgotPassword(confirmPasswordParams).promise();

            res.status(200).json({
                message: 'Successfully reset password.',
                code: 'PASSWORD_RESET_SUCCESS'
            });
        } catch (error) {
            console.error('Error confirming password reset:', error);
            if (error.name === 'CodeMismatchException') {
                return res.status(400).json({
                    message: 'Invalid confirmation code.',
                    code: 'INVALID_CODE'
                });
            }
            if (error.name === 'ExpiredCodeException') {
                return res.status(400).json({
                    message: 'Confirmation code has expired.',
                    code: 'EXPIRED_CODE'
                });
            }
            if (error.name === 'LimitExceededException' || error.name === 'TooManyRequestsException') {
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED'
                });
            }
            return res.status(500).json({
                message: 'Internal Server Error',
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