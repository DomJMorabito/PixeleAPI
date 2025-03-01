// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

// Utils Imports:

import { corsMiddleware } from './utils/middleware/cors.js';
import { initialize } from './utils/init/initialize.js';
import { getSecrets } from "./utils/aws/secrets.js";
import { validateInput } from './utils/middleware/validate-input.js';

let app;

const appPromise = initialize().then((initializedApp) => {
    app = initializedApp;

    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/verify', validateInput, async (req, res) => {
        const cognitoSecrets = await getSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        const { username, verificationCode } = req.body;

        const userParams = {
            UserPoolId: cognitoSecrets.USER_POOL_ID,
            Username: username
        };

        try {
            await cognito.adminGetUser(userParams).promise();
        } catch (error) {
            if (error.code === 'NotAuthorizedException' || error.code === 'UserNotFoundException') {
                return res.status(401).json({
                    message: 'Invalid credentials.',
                    code: 'INVALID_CREDENTIALS'
                });
            }
        }

        const confirmSignUpParams = {
            ClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
            Username: username,
            ConfirmationCode: verificationCode,
        }

        try {
            await cognito.confirmSignUp(confirmSignUpParams).promise();
            res.status(200).json({
                message: 'Verification Successful!',
                code: 'VERIFICATION_SUCCESS'
            });
        } catch (error) {
            console.error('Verification error:', error);
            switch (error.code) {
                case 'CodeMismatchException':
                    return res.status(400).json({
                        message: 'Verification code is incorrect.',
                        code: 'INVALID_CODE'
                    })
                case 'NotAuthorizedException':
                    return res.status(409).json({
                        message: 'This account is already verified.',
                        code: 'ALREADY_VERIFIED'
                    })
                case 'ExpiredCodeException':
                    return res.status(410).json({
                        message: 'Verification code has expired. Please request a new one.',
                        code: 'EXPIRED_CODE'
                    })
                case 'TooManyRequestsException':
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED'
                    })
                default:
                    res.status(500).json({
                        message: 'Unable to complete verification. Please try again later.',
                        code: 'SERVER_ERROR'
                    })
            }
        }
    });
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};