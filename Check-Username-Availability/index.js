// Package Imports:

import AWS from 'aws-sdk';
import express from "express";
import serverless from 'serverless-http';

// Utils Imports:

import { getSecrets } from './utils/aws/secrets.js';
import { corsMiddleware } from './utils/middleware/cors.js';
import { initialize } from './utils/init/initialize.js';
import { validateInput } from './utils/middleware/validate-input.js';

let app;

const appPromise = initialize().then(initializedApp => {
    app = initializedApp;
    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.get('/users/check-username-availability', validateInput, async (req, res) => {
        const cognitoSecrets = await getSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        const username = req.query.username?.toLowerCase();

        try {
            const params = {
                UserPoolId: cognitoSecrets.USER_POOL_ID,
                Filter: `username = "${username.replace(/"/g, '\\"')}"`,
                Limit: 1
            };
            const result = await cognito.listUsers(params).promise();
            return res.status(200).json({
                taken: result.Users && result.Users.length > 0
            });
        } catch (error) {
            console.error('Error checking duplicate username:', error);
            if (error.code === 'LimitExceededException') {
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