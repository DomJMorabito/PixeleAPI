// Package Imports:

import express from "express";
import serverless from "serverless-http";
import { fetchAuthSession } from "aws-amplify/auth";
import AWS from "aws-sdk";

// Utils Imports:

import { initialize } from './utils/init/initialize.js';
import { corsMiddleware } from './utils/middleware/cors.js';

let app;

const appPromise = initialize().then(({ app: initializedApp}) => {
    app = initializedApp;

    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.get('/users/check-auth', async (req, res) => {
        try {
            const session = await fetchAuthSession();

            if (!session.tokens?.accessToken) {
                return res.status(401).json({
                    isAuthenticated: false,
                    message: 'No session found.',
                    code: 'NO_SESSION'
                });
            }

            const decodedToken = session.tokens.accessToken.payload;
            if (decodedToken.exp * 1000 < Date.now()) {
                return res.status(401).json({
                    isAuthenticated: false,
                    message: 'Session expired.',
                    code: 'SESSION_EXPIRED'
                });
            }

            const cognito = new AWS.CognitoIdentityServiceProvider();
            const params = {
                AccessToken: session.tokens.accessToken.toString()
            }

            const userData = await cognito.getUser(params).promise();

            const userInfo = {
                username: userData.Username
            };

            return res.status(200).json({
                isAuthenticated: true,
                userInfo
            })
        } catch (error) {
            console.error('Error checking Auth:', error);
            switch (error.code) {
                case 'NotAuthorizedException':
                    return res.status(401).json({
                        isAuthenticated: false,
                        message: 'Invalid/Expired session.',
                        code: 'INVALID_SESSION'
                    })
                case 'LimitExceededException':
                    return res.status(429).json({
                        isAuthenticated: false,
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED'
                    })
                case 'UserNotFoundException':
                    return res.status(404).json({
                        isAuthenticated: false,
                        message: 'User Not Found',
                        code: 'USER_NOT_FOUND'
                    })
                default:
                    return res.status(500).json({
                        isAuthenticated: false,
                        message: 'Internal Server Error',
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