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

        let username;
        let userData;
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

            try {
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

                        res.status(500).json({
                            message: 'Failed to resend verification code.',
                            code: 'SERVER_ERROR'
                        });
                    }
                }
            } catch (statusCheckError) {
                console.error('Error checking confirmation status:', statusCheckError);
            }

            const connection = await pool.getConnection();
            try {
                await connection.beginTransaction();
                const [lockStatus] = await connection.execute(
                    'SELECT failed_login_attempts, last_failed_login_attempt FROM users where username = ?',
                    [username]
                );
                await connection.commit();

                if (lockStatus[0]) {
                    const lastFailedLoginAttempt = new Date(lockStatus[0].last_failed_login_attempt);
                    const lockoutDuration = 15 * 60 * 1000;
                    const unlockTime = new Date(lastFailedLoginAttempt.getTime() + lockoutDuration);

                    if (lockStatus[0].failed_login_attempts >= 5 && unlockTime > new Date()) {
                        return res.status(403).json({
                            message: 'Account temporarily locked.',
                            code: 'ACCOUNT_LOCKED'
                        });
                    }

                    if (unlockTime <= new Date()) {
                        try {
                            await connection.beginTransaction();
                            await connection.execute(
                                'UPDATE users SET failed_login_attempts = 0, last_failed_login_attempt = NULL WHERE username = ?',
                                [username]
                            );
                            await connection.commit();
                        } catch (dbError) {
                            await connection.rollback();
                            console.error('Error resetting failed_login_attempts:', dbError);
                            return res.status(500).json({
                                message: 'Database error occurred. Please try again later.',
                                code: 'DATABASE_ERROR'
                            });
                        } finally {
                            await connection.release()
                        }
                    }
                }
            } catch (dbError) {
                await connection.rollback();
                console.error('Error updating failed_login_attempts:', dbError);
                return res.status(500).json({
                    message: 'Database error occurred. Please try again later.',
                    code: 'DATABASE_ERROR'
                });
            }
            finally {
                await connection.release();
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
                const authResult = await cognito.adminInitiateAuth(authParams).promise();
                const { AccessToken, IdToken, RefreshToken } = authResult.AuthenticationResult;

                const connection = await pool.getConnection();
                try {
                    await connection.beginTransaction();
                    await connection.execute(
                        'UPDATE users SET failed_login_attempts = 0, last_failed_login_attempt = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?',
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
                    await connection.release();
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
            } catch (authError) {
                const connection = await pool.getConnection();
                try {
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
                        return res.status(403).json({
                            message: 'Account temporarily locked.',
                            code: 'ACCOUNT_LOCKED'
                        });
                    }
                } catch (dbError) {
                    await connection.rollback();
                    console.error('Error updating failed_login_attempts:', dbError);
                    return res.status(500).json({
                        message: 'Database error occurred. Please try again later.',
                        code: 'DATABASE_ERROR'
                    });
                } finally {
                    await connection.release();
                }
            }
        } catch (error) {
            console.error('Login error:', error);
            switch (error.name) {
                case 'NotAuthorizedException':
                    return res.status(403).json({
                        message: 'Account temporarily locked. Password attempt limit exceeded.',
                        code: 'ACCOUNT_LOCKED'
                    })
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
        }
    });
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};