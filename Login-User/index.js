import express from 'express';
import serverless from 'serverless-http';
import { signIn } from 'aws-amplify/auth';
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
        const signInResult = await signIn({
            username: identifier,
            password
        });

        return res.status(200).json({
            token: signInResult.signInUserSession.accessToken.jwtToken,
            user: {
                username: signInResult.username,
                email: signInResult.attributes.email,
                userId: signInResult.attributes.id
            },
            session: {
                isValid: signInResult.signInUserSession.isValid(),
                expiresAt: new Date(signInResult.signInUserSession.accessToken.payload.exp * 1000)
            }
        });
    } catch (error) {
        switch (error.name) {
            case 'UserNotFoundException':
                return res.status(404).json({
                    message: 'No account associated with this Email/Username.',
                    code: 'USER_NOT_FOUND',
                    details: {
                        identifier
                    }
                })
            case 'NotAuthorizedException':
                return res.status(401).json({
                    message: 'Password is incorrect.',
                    code: 'INVALID_PASSWORD',
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