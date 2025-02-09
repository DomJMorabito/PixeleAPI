// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import cookieParser from 'cookie-parser';
import AWS from 'aws-sdk';

// Utils Imports:

import { initialize } from './utils/init/initialize.js';
import { corsMiddleware } from "./utils/middleware/cors.js";

let app;

const appPromise = initialize().then(initializedApp => {
    app = initializedApp;

    app.use(express.json({ limit: '10kb' }));
    app.use(cookieParser());
    app.use(corsMiddleware);

    app.post ('/users/logout', async (req, res) => {
        const sessionToken = req.cookies.pixele_session;

        if (!sessionToken) {
            return res.status(401).json({
                message: 'No active session found.',
                code: 'NO_SESSION'
            });
        }

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            path: '/',
            domain: 'pixele.gg'
        }

        try {
            const cognito = new AWS.CognitoIdentityServiceProvider();

            try {
                await cognito.globalSignOut({
                    AccessToken: sessionToken
                }).promise();
            } catch (signOutError) {
                console.log('Sign out error (non-critical):', signOutError);
            }

            res.clearCookie('pixele_session', {
                ...cookieOptions
            });

            res.clearCookie('pixele_id', {
                ...cookieOptions
            });

            res.clearCookie('pixele_refresh', {
                ...cookieOptions
            });

            return res.status(200).json({
                message: 'Successfully logged out. See ya later!'
            });
        } catch (error) {
            console.error('Logout error:', error);

            res.clearCookie('pixele_session', {
                ...cookieOptions
            });

            res.clearCookie('pixele_id', {
                ...cookieOptions
            });

            res.clearCookie('pixele_refresh', {
                ...cookieOptions
            });

            return res.status(500).json({
                message: 'Failed to complete logout.',
                code: 'LOGOUT_FAILED'
            });
        }
    });

    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};