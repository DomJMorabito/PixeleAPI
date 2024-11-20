import express from 'express';
import serverless from 'serverless-http';
import { signIn, signOut, getCurrentUser } from 'aws-amplify/auth';
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

        await new Promise(resolve => setTimeout(resolve, 100));

        try {
            const currentUser = await getCurrentUser();
            if (!currentUser.tokens?.accessToken) {
                return res.status(500).json({
                    message: 'No access token available after authentication.',
                    code: 'TOKEN_UNAVAILABLE',
                    details: {
                        error: 'Access token missing from authenticated session'
                    }
                });
            }
            return res.status(200).json({
                token: currentUser.tokens.accessToken.toString(),
                user: {
                    username: identifier
                },
                session: {
                    isValid: true,
                    expiresAt: new Date(currentUser.tokens.accessToken.payload.exp * 1000)
                }
            });
        } catch (getUserError) {
            console.error('Error getting current user:', getUserError);
            try {
                await signOut();
            } catch (error) {
                console.log('Cleanup signOut error (non-critical):', error);
            }
            return res.status(500).json({
                message: 'Failed to complete authentication',
                code: 'AUTH_COMPLETION_FAILED',
                details: {
                    error: getUserError.message
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