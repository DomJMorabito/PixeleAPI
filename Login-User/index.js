import express from 'express';
import serverless from 'serverless-http';
import cookieParser from 'cookie-parser';
import { signIn, signOut, fetchAuthSession } from 'aws-amplify/auth';
import { Amplify } from 'aws-amplify';
import AWS from 'aws-sdk';

const secretsManager = new AWS.SecretsManager();

async function getSecrets() {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.SECRET_ID
        }).promise();
        try {
            return JSON.parse(data.SecretString);
        } catch (parseError) {
            console.error('Error parsing secrets:', parseError);
            throw new Error('Invalid secret format');
        }
    } catch (error) {
        console.error('Error retrieving secrets:', error);
        throw error;
    }
}

async function initialize() {
    try {
        const secrets = await getSecrets();
        if (!secrets.USER_POOL_CLIENT_ID || !secrets.USER_POOL_ID) {
            throw new Error('Required Cognito credentials not found in secrets');
        }
        Amplify.configure({
            Auth: {
                Cognito: {
                    userPoolClientId: secrets.USER_POOL_CLIENT_ID,
                    userPoolId: secrets.USER_POOL_ID,
                }
            }
        });
        return express();
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}

let app;
const appPromise = initialize().then(initializedApp => {
    app = initializedApp;
    app.use(express.json({ limit: '10kb' }));
    app.use(cookieParser());
    app.use((req, res, next) => {
        res.setHeader('Access-Control-Allow-Origin', 'https://pixele.gg');
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (req.method === 'OPTIONS') {
            return res.status(200).end();
        }
        console.log(`${req.method} ${req.path} - IP: ${req.ip}`);
        next();
    });

    app.post('/users/login', async (req, res) => {
        const secrets = await getSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
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

            let username = identifier;
            let email = identifier;
            if (identifier.includes('@')) {
                try {
                    const params = {
                        UserPoolId: secrets.USER_POOL_ID,
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
                        UserPoolId: secrets.USER_POOL_ID,
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
                        ClientId: secrets.USER_POOL_CLIENT_ID,
                        Username: username
                    }).promise();
                } catch (error) {
                    console.error('Error resending confirmation code:', error);
                }
            }

            if (!isSignedIn && (!nextStep || nextStep.signInStep !== 'DONE')) {
                return res.status(403).json({
                    message: 'Further authentication required',
                    code: 'AUTH_INCOMPLETE',
                    details: {
                        nextStep,
                        username,
                        email
                    }
                });
            }

            try {
                const session = await fetchAuthSession();

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
                    maxAge: tokenExpiration - Date.now(),
                    domain: 'pixele.gg'
                };

                res.cookie('pixele_session', session.tokens.accessToken.toString(), {
                    ...cookieOptions,
                    httpOnly: true
                });

                res.cookie('pixele_user', JSON.stringify({
                    username: username,
                    email: email
                }), {
                    ...cookieOptions,
                    httpOnly: false
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
                case 'LimitExceededException':
                    return res.status(429).json({
                        message: 'Request limit exceeded. Please try again later.',
                        code: 'LIMIT_EXCEEDED'
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
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};