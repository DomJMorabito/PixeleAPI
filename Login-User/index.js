// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import { jwtDecode } from 'jwt-decode';
import AWS from 'aws-sdk';

// Utils Imports:

import { initialize } from './utils/init/initialize.js';
import { validateInput } from './utils/middleware/validate-input.js';
import { getCognitoSecrets } from './utils/aws/secrets.js';
import { corsMiddleware } from './utils/middleware/cors.js';

let app;
let pool;

const appPromise = initialize().then(({ app: initializedApp, pool: initializedPool }) => {
    app = initializedApp;
    pool = initializedPool;

    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/login', validateInput, async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        let { identifier, password } = req.body;

        try {
            let username = identifier;
            let email = identifier;
            if (identifier.includes('@')) {
                try {
                    const params = {
                        UserPoolId: cognitoSecrets.USER_POOL_ID,
                        Filter: `email = "${identifier}"`,
                        Limit: 1
                    };

                    const userData = await cognito.listUsers(params).promise();
                    username = userData.Users[0]?.Username;
                } catch (error) {
                    console.error('Error looking up username:', error);
                }
            } else {
                try {
                    const params = {
                        UserPoolId: cognitoSecrets.USER_POOL_ID,
                        Username: identifier
                    };

                    const userData = await cognito.adminGetUser(params).promise();
                    email = userData.UserAttributes.find(attribute => attribute.Name === 'email')?.Value || identifier;
                } catch (error) {
                    console.error('Error looking up email:', error);
                }
            }

            const authParams = {
                AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
                ClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
                UserPoolId: cognitoSecrets.USER_POOL_ID,
                AuthParameters: {
                    USERNAME: username,
                    PASSWORD: password
                }
            };

            try {
                const userConfirmationStatus = await cognito.adminGetUser({
                    UserPoolId: cognitoSecrets.USER_POOL_ID,
                    Username: username
                }).promise();

                if (userConfirmationStatus.UserStatus === 'UNCONFIRMED') {
                    try {
                        await cognito.resendConfirmationCode({
                            ClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
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
            } catch (statusCheckError) {
                console.error('Error checking confirmation status:', statusCheckError);
            }

            const authResult = await cognito.adminInitiateAuth(authParams).promise();

            if (!authResult.AuthenticationResult) {
                return res.status(500).json({
                    message: 'Authentication failed, no tokens received.',
                    code: 'AUTH_FAILED'
                });
            }

            const { AccessToken, IdToken, RefreshToken } = authResult.AuthenticationResult;

            const connection = await pool.getConnection();

            try {
                await connection.beginTransaction();

                await connection.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?',
                    [username]
                );
                await connection.commit();
            } catch (dbError) {
                await connection.rollback();
                console.error('Error updating last_login:', dbError);
                return res.status(500).json({
                    message: 'Database error occurred. Please try again later.',
                    code: 'DATABASE_ERROR'
                });
            } finally {
                connection.release();
            }

            const accessTokenPayload = jwtDecode(AccessToken);
            const idTokenPayload = jwtDecode(IdToken);

            res.cookie('pixele_session', AccessToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: accessTokenPayload.exp * 1000 - Date.now(),
                path: '/',
                domain: 'pixele.gg'
            });

            res.cookie('pixele_id', IdToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: idTokenPayload.exp * 1000 - Date.now(),
                path: '/',
                domain: 'pixele.gg'
            });

            res.cookie('pixele_refresh', RefreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 90 * 24 * 60 * 60 * 1000,
                path: '/',
                domain: 'pixele.gg'
            });

            return res.status(200).json({
                message: 'Successfully logged in!'
            });
        } catch (error) {
            console.error('Login error:', error);
            switch (error.name) {
                case 'NotAuthorizedException':
                    return res.status(401).json({
                        message: 'Invalid Username/Email or Password.',
                        code: 'INVALID_CREDENTIALS'
                    })
                case 'UserNotFoundException':
                    return res.status(404).json({
                        message: 'No account associated with this Email/Username.',
                        code: 'USER_NOT_FOUND'
                    })
                case 'TooManyRequestsException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED'
                    })
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Request limit exceeded. Please try again later.',
                        code: 'LIMIT_EXCEEDED'
                    })
                default:
                    return res.status(500).json({
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