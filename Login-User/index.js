// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import cookieParser from 'cookie-parser';
import { signIn, signOut, fetchAuthSession } from 'aws-amplify/auth';
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
    app.use(cookieParser());
    app.use(corsMiddleware);

    app.post('/users/login', validateInput, async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        let { identifier, password } = req.body;

        try {
            try {
                await signOut();
            } catch (error) {
                console.log('SignOut error (non-critical):', error);
            }

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

            const { isSignedIn, nextStep } = await signIn({
                username: username,
                password
            });

            if (nextStep?.signInStep === 'CONFIRM_SIGN_UP') {
                try {
                    await cognito.resendConfirmationCode({
                        ClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
                        Username: username
                    }).promise();
                } catch (error) {
                    console.error('Error resending confirmation code:', error);
                }
            }

            if (!isSignedIn && (!nextStep || nextStep.signInStep !== 'DONE')) {
                return res.status(403).json({
                    message: 'Further authentication required.',
                    code: 'AUTH_INCOMPLETE',
                    details: {
                        username: username,
                        email: email,
                        nextStep: nextStep
                    }
                });
            }

            try {
                const session = await fetchAuthSession();
                console.log(session);

                if (!session.tokens?.accessToken) {
                    return res.status(500).json({
                        message: 'No access token available after authentication.',
                        code: 'TOKEN_UNAVAILABLE',
                        details: {
                            username: username,
                            email: email
                        }
                    });
                }

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
                        code: 'DATABASE_ERROR',
                        details: {
                            error: dbError,
                            email: email,
                            username: username
                        }
                    });
                } finally {
                    connection.release();
                }

                res.cookie('pixele_session', session.tokens.accessToken.toString(), {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'strict',
                    maxAge: session.tokens.accessToken.payload.exp * 1000 - Date.now(),
                    path: '/',
                    domain: 'pixele.gg'
                });

                return res.status(200).json({
                    token: session.tokens.accessToken.toString(),
                    user: {
                        username: username,
                        email: email
                    },
                    session: {
                        isValid: true,
                        expiresAt: new Date(session.tokens.accessToken.payload.exp * 1000)
                    }
                });
            } catch (error) {
                console.error('Error getting current user:', error);
                try {
                    await signOut();
                } catch (error) {
                    console.log('Cleanup signOut error (non-critical):', error);
                }
                return res.status(500).json({
                    message: 'Failed to complete authentication.',
                    code: 'AUTH_COMPLETION_FAILED',
                    details: {
                        error: error
                    }
                });
            }
        } catch (error) {
            try {
                await signOut();
            } catch (error) {
                console.log('Cleanup signOut error (non-critical):', error);
            }
            switch (error.name) {
                case 'NotAuthorizedException':
                    return res.status(401).json({
                        message: 'Invalid Username/Email or Password.',
                        code: 'INVALID_CREDENTIALS',
                        details: {
                            error: error
                        }
                    })
                case 'UserNotFoundException':
                    return res.status(404).json({
                        message: 'No account associated with this Email/Username.',
                        code: 'USER_NOT_FOUND',
                        details: {
                            identifier: identifier,
                            error: error
                        }
                    })
                case 'TooManyRequestsException':
                    return res.status(429).json({
                        message: 'Too many attempts. Please try again later.',
                        code: 'RATE_LIMIT_EXCEEDED',
                        details: {
                            error: error
                        }
                    })
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Request limit exceeded. Please try again later.',
                        code: 'LIMIT_EXCEEDED',
                        details: {
                            error: error
                        }
                    })
                default:
                    console.error('Login error:', error);
                    return res.status(500).json({
                        message: 'Internal Server Error',
                        code: 'SERVER_ERROR',
                        details: {
                            error: error
                        }
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