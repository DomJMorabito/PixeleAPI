// Package Imports:

import express from "express";
import serverless from "serverless-http";
import cookieParser from 'cookie-parser';
import { jwtDecode } from "jwt-decode";
import AWS from "aws-sdk";

// Utils Imports:

import { initialize } from './utils/init/initialize.js';
import { corsMiddleware } from './utils/middleware/cors.js';
import { getSecrets } from "./utils/aws/secrets.js";

let app;

const appPromise = initialize().then(({ app: initializedApp}) => {
    app = initializedApp;

    app.use(express.json({ limit: '10kb' }));
    app.use(cookieParser());
    app.use(corsMiddleware);

    app.get('/users/check-auth', async (req, res) => {
        try {
            const secrets  = await getSecrets();
            const cognito = new AWS.CognitoIdentityServiceProvider();
            const sessionToken = req.cookies.pixele_session;
            const idToken = req.cookies.pixele_id;
            const refreshToken = req.cookies.pixele_refresh;

            if (!sessionToken || !idToken) {
                return res.status(401).json({
                    isAuthenticated: false,
                    message: 'No session found.',
                    code: 'NO_SESSION'
                });
            }

            let decodedSessionToken = jwtDecode(sessionToken);
            let decodedIdToken = jwtDecode(idToken);

            const fiveMinutes = 5 * 60 * 1000;
            const sessionExpiration = decodedSessionToken.exp * 1000;
            const idExpiration = decodedIdToken.exp * 1000;
            const now = Date.now();

            if (sessionExpiration < now + fiveMinutes || idExpiration < now + fiveMinutes) {
                if (refreshToken) {
                    try {
                        const refreshParams = {
                            AuthFlow: 'REFRESH_TOKEN_AUTH',
                            ClientId: secrets.USER_POOL_CLIENT_ID,
                            AuthParameters: {
                                REFRESH_TOKEN: refreshToken
                            }
                        };

                        const authResult = await cognito.initiateAuth(refreshParams).promise();
                        const { AccessToken: newAccessToken, IdToken: newIdToken } = authResult.AuthenticationResult;

                        const newAccessTokenPayload = jwtDecode(newAccessToken);
                        const newIdTokenPayload = jwtDecode(newIdToken);

                        res.cookie('pixele_session', newAccessToken, {
                            httpOnly: true,
                            secure: true,
                            sameSite: 'strict',
                            maxAge: newAccessTokenPayload.exp * 1000 - now,
                            path: '/',
                            domain: 'pixele.gg'
                        });

                        res.cookie('pixele_id', newIdToken, {
                            httpOnly: true,
                            secure: true,
                            sameSite: 'strict',
                            maxAge: newIdTokenPayload.exp * 1000 - now,
                            path: '/',
                            domain: 'pixele.gg'
                        });
                    } catch (refreshError) {
                        console.error('Token refresh error:', refreshError);
                        if (refreshError.code === 'NotAuthorizedException') {
                            const cookieOptions = {
                                httpOnly: true,
                                secure: true,
                                sameSite: 'strict',
                                path: '/',
                                domain: 'pixele.gg'
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
                        }
                        return res.status(401).json({
                            isAuthenticated: false,
                            message: 'Session expired.',
                            code: 'SESSION_EXPIRED'
                        });
                    }
                } else {
                    return res.status(401).json({
                        isAuthenticated: false,
                        message: 'Session expired.',
                        code: 'SESSION_EXPIRED'
                    });
                }
            }

            try {
                const userResult = await cognito.getUser({
                    AccessToken: sessionToken
                }).promise();

                const userDetails = {
                    UserPoolId: secrets.USER_POOL_ID,
                    Username: userResult.Username
                }.promise();

                const userInfo = {
                    username: userDetails.Username,
                    email: userDetails.UserAttributes.find(attribute => attribute.name === 'email').Value
                }

                return res.status(200).json({
                    isAuthenticated: true,
                    userInfo
                });
            } catch (error) {
                console.error('Token verification error:', error);
                return res.status(401).json({
                    isAuthenticated: false,
                    message: 'Invalid session.',
                    code: 'INVALID_SESSION'
                });
            }

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