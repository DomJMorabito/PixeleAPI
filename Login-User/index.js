import express from 'express';
import serverless from 'serverless-http';
import cookieParser from 'cookie-parser';
import { signIn, signOut, getCurrentUser, fetchAuthSession } from 'aws-amplify/auth';
import { Amplify } from 'aws-amplify';

Amplify.configure({
    Auth: {
        Cognito: {
            userPoolClientId: process.env.AWS_USER_POOL_CLIENT_ID,
            userPoolId: process.env.AWS_USER_POOL_ID,
        }
    }
});

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    console.log(`${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

app.post('/users/login', async (req, res) => {
    let { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            details: {
                missingFields: [
                    !identifier && 'usernameEmailInput',
                    !password && 'passwordInput',
                ].filter(Boolean)
            }
        });
    }

    identifier = identifier.toLowerCase();

    try {
        try {
            await signOut();
        } catch (error) {
            console.log('SignOut error (non-critical):', error);
        }

        const { isSignedIn, nextStep } = await signIn({
            username: identifier,
            password
        });

        if (!isSignedIn && (!nextStep || nextStep.signInStep !== 'DONE')) {
            return res.status(400).json({
                message: 'Further authorization required.',
                code: 'AUTHENTICATION_INCOMPLETE',
                details: {
                    nextStep
                }
            });
        }

        try {
            const [currentUser, session] = await Promise.all([
                getCurrentUser(),
                fetchAuthSession()
            ]);

            if (!session.tokens?.accessToken) {
                return res.status(500).json({
                    message: 'No access token available after authentication.',
                    code: 'TOKEN_UNAVAILABLE',
                    details: {
                        error: 'Access token missing from authenticated session'
                    }
                });
            }

            const tokenExpiration = session.tokens.accessToken.payload.exp * 1000;
            const cookieOptions = {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: tokenExpiration - Date.now()
            };

            res.cookie('pixele_session', session.tokens.accessToken.toString(), {
                ...cookieOptions,
                httpOnly: true
            });

            res.cookie('pixele_user', JSON.stringify({
                username: currentUser.username,
                email: currentUser.signInDetails.loginId
            }), {
                ...cookieOptions,
                httpOnly: false
            });

            return res.status(200).json({
                token: session.tokens.accessToken.toString(),
                user: {
                    username: currentUser.username,
                    email: currentUser.signInDetails.loginId
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
                message: 'Failed to complete authentication',
                code: 'AUTH_COMPLETION_FAILED',
                details: {
                    error: error.message
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
                })
            case 'UserNotFoundException':
                return res.status(404).json({
                    message: 'No account associated with this Email/Username.',
                    code: 'USER_NOT_FOUND',
                    details: {
                        identifier
                    }
                })
            case 'TooManyRequestsException':
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED'
                })
            case 'UserNotConfirmedException':
                return res.status(403).json({
                    message: 'Please verify your email before logging in.',
                    code: 'USER_NOT_CONFIRMED',
                    details: {
                        identifier
                    }
                })
            default:
                console.error('Login error:', error);
                return res.status(500).json({
                    message: 'Internal Server Error',
                    code: 'SERVER_ERROR',
                    details: {
                        error: error.message
                    }
                });
        }
    }
});

export const handler = serverless(app);