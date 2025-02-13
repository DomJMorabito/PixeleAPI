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
import { getLockoutResponse } from "./utils/helper/get-lockout-response.js";

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

        let username = null;
        let userData = null;
        let connection;

        try {
            const userParams = {
                UserPoolId: cognitoSecrets.USER_POOL_ID,
                Filter: identifier.includes('@')
                    ? `email = "${identifier}"`
                    : `username = "${identifier}"`,
                Limit: 1
            };

            userData = await cognito.listUsers(userParams).promise();

            if ((!userData.Users || userData.Users.length === 0) && !identifier.includes('@')) {
                userData = await cognito.listUsers({
                    UserPoolId: cognitoSecrets.USER_POOL_ID,
                    Filter: `email = "${identifier}"`,
                    Limit: 1
                }).promise();
            }

            if (!userData.Users || userData.Users.length === 0) {
                return res.status(401).json({
                    message: 'Invalid credentials.',
                    code: 'INVALID_CREDENTIALS'
                });
            }

            username = userData.Users[0].Username;

            const userDetails = await cognito.adminGetUser({
                UserPoolId: cognitoSecrets.USER_POOL_ID,
                Username: username
            }).promise();

            if (userDetails.UserStatus === 'UNCONFIRMED') {
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
                            email: userDetails.UserAttributes.find(attr => attr.Name === 'email')?.Value
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

                     return res.status(500).json({
                        message: 'Failed to resend verification code.',
                        code: 'SERVER_ERROR'
                    });
                }
            }

            connection = await pool.getConnection();

            const [lockStatus] = await connection.execute(
                'SELECT failed_login_attempts, last_failed_login_attempt FROM users where username = ?',
                [username]
            );

            if (lockStatus[0]) {
                const lastFailedLoginAttempt = new Date(lockStatus[0].last_failed_login_attempt);
                const lockoutDuration = 15 * 60 * 1000;
                const unlockTime = new Date(lastFailedLoginAttempt.getTime() + lockoutDuration);

                if (lockStatus[0].failed_login_attempts >= 5 && unlockTime > new Date()) {
                    const response = getLockoutResponse(lockStatus[0].last_failed_login_attempt);
                    return res.status(response.status).json(response.body);
                }

                if (unlockTime <= new Date()) {
                    await connection.execute(
                        'UPDATE users SET failed_login_attempts = 0, last_failed_login_attempt = NULL WHERE username = ?',
                        [username]
                    );
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

            const authResult = await cognito.adminInitiateAuth(authParams).promise();
            const {AccessToken, IdToken, RefreshToken} = authResult.AuthenticationResult;

            await connection.beginTransaction();
            await connection.execute(
                'UPDATE users SET failed_login_attempts = 0, last_failed_login_attempt = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?',
                [username]
            );
            await connection.commit();

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
            if (connection) {
                try {
                    await connection.rollback();
                    console.log(error.errorMessage);
                    console.log(error.message);
                    if (error.name === 'NotAuthorizedException' && username) {
                        await connection.beginTransaction();
                        await connection.execute(
                            'UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login_attempt = CURRENT_TIMESTAMP WHERE username = ?',
                            [username]
                        );

                        const [attempts] = await connection.execute(
                            'SELECT failed_login_attempts FROM users WHERE username = ?',
                            [username]
                        );

                        await connection.commit();

                        if (attempts[0]?.failed_login_attempts >= 5) {
                            const response = getLockoutResponse(new Date());
                            return res.status(response.status).json(response.body);
                        }
                    }
                } catch (dbError) {
                    console.error('Error updating database:', dbError);
                    return res.status(500).json({
                        message: 'Database error occurred. Please try again later.',
                        code: 'DATABASE_ERROR'
                    });
                }
            }
            switch (error.name) {
                case 'NotAuthorizedException':
                    return res.status(401).json({
                        message: 'Invalid credentials.',
                        code: 'INVALID_CREDENTIALS'
                    });
                case 'TooManyRequestsException':
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED'
                    })
                case 'UserNotFoundException':
                    return res.status(401).json({
                        message: 'Invalid credentials.',
                        code: 'INVALID_CREDENTIALS'
                    })
                default:
                    return res.status(500).json({
                        message: 'Internal Server Error',
                        code: 'SERVER_ERROR'
                    });
            }
        } finally {
            if (connection) {
                connection.release();
            }
        }
    });

    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};