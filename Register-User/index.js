import express from 'express';
import serverless from 'serverless-http';
import { Filter } from 'bad-words';
import AWS from 'aws-sdk';
import { signUp } from 'aws-amplify/auth';
import { Amplify } from 'aws-amplify';
import mysql from 'mysql2/promise';

const secretsManager = new AWS.SecretsManager();

async function getDbSecrets() {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.DB_SECRET_ID
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

async function getCognitoSecrets() {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.AUTH_SECRET_ID
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

let pool;

async function initialize() {
    try {
        const [dbSecrets, cognitoSecrets] = await Promise.all([
            getDbSecrets(),
            getCognitoSecrets()
        ]);
        if (!cognitoSecrets.USER_POOL_CLIENT_ID || !cognitoSecrets.USER_POOL_ID) {
            throw new Error('Required Cognito credentials not found in secrets');
        } else if (!dbSecrets.host || !dbSecrets.username || !dbSecrets.password || !dbSecrets.port) {
            throw new Error('Required RDS credentials not found in secrets');
        }

        pool = mysql.createPool({
            host: dbSecrets.host,
            user: dbSecrets.username,
            password: dbSecrets.password,
            database: 'pixele',
            port: dbSecrets.port,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 5
        });

        Amplify.configure({
            Auth: {
                Cognito: {
                    userPoolClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
                    userPoolId: cognitoSecrets.USER_POOL_ID,
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

    app.post('/users/register', async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        let { username, email, password } = req.body;
        const filter = new Filter();

        if (!username || !email || !password) {
            return res.status(400).json({
                message: 'All fields are required.',
                code: 'MISSING_FIELDS',
                details: {
                    missingFields: [
                        !username && 'usernameInput',
                        !email && 'emailInput',
                        !password && 'passwordInput'
                    ].filter(Boolean)
                }
            });
        }

        username = username.toLowerCase();

        if (!validateEmail(email)) {
            return res.status(400).json({
                message: 'Enter a valid email.',
                code: 'INVALID_EMAIL',
                details: {
                    providedEmail: email
                }
            });
        }

        if (!validateUsernameLength(username)) {
            return res.status(400).json({
                message: 'Username must be 5-18 characters.',
                code: 'INVALID_USERNAME',
                details: {
                    requirements: {
                        minLength: 5,
                        maxLength: 18
                    }
                }
            });
        }

        if (!validateUsernameSpecialCharacters(username)) {
            return res.status(400).json({
                message: 'Username cannot contain any special characters.',
                code: 'INVALID_USERNAME',
                details: {
                    requirements: {
                        allowedCharacters: 'alphanumeric'
                    }
                }
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                message: 'Password requirements not met.',
                code: 'INVALID_PASSWORD',
                details: {
                    requirements: {
                        minLength: 8,
                        requiresNumber: true,
                        requiresSpecialChar: true
                    }
                }
            });
        }

        if (filter.isProfane(username)) {
            return res.status(400).json({
                message: 'Seriously?',
                code: 'INAPPROPRIATE_CONTENT',
                details: {
                    username
                }
            });
        }


        try {
            const [emailExists, usernameExists] = await Promise.all([
                checkForDuplicateEmail(email, cognitoSecrets.USER_POOL_ID, cognito),
                checkForDuplicateUsername(username, cognitoSecrets.USER_POOL_ID, cognito)
            ]);

            if (emailExists && usernameExists) {
                return res.status(409).json({
                    message: 'Both Email and Username are already in use.',
                    code: 'DUPLICATE_CREDENTIALS',
                    details: {
                        email,
                        username
                    }
                });
            }

            if (emailExists) {
                return res.status(409).json({
                    message: 'Email already in use.',
                    code: 'EMAIL_EXISTS',
                    details: {
                        email
                    }
                });
            }

            if (usernameExists) {
                return res.status(409).json({
                    message: 'Username already in use.',
                    code: 'USERNAME_EXISTS',
                    details: {
                        username
                    }
                });
            }

            try {
                await signUp({
                    username: username,
                    password: password,
                    options: {
                        userAttributes: {
                            email: email,
                        }
                    }
                });
            } catch (cognitoError) {
                console.error('Cognito signup failed:', cognitoError);
                throw cognitoError;
            }

            const connection = await pool.getConnection();

            try {
                await connection.beginTransaction();

                const [userResult] = await connection.execute(
                    'INSERT INTO users (username) VALUES (?)',
                    [username]
                );

                const userId = userResult.insertId;
                const [games] = await connection.execute('SELECT id FROM games');

                await Promise.all(games.map(game =>
                    connection.execute(
                        'INSERT INTO game_stats (user_id, game_id) VALUES (?, ?)',
                        [userId, game.id]
                    )
                ));

                await connection.commit();

                return res.status(201).json({
                    message: 'Registration Successful! Please check your email for verification.',
                    code: 'REGISTRATION_SUCCESS',
                    details: {
                        email,
                        username
                    }
                });
            } catch (dbError) {
                await connection.rollback();
                try {
                    const params = {
                        UserPoolId: cognitoSecrets.USER_POOL_ID,
                        Username: username
                    };
                    await cognito.adminDeleteUser(params).promise();
                } catch (cleanupError) {
                    console.error('Cognito cleanup error:', cleanupError);
                }
                throw dbError;
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error('Cognito sign up error:', error);
            if (error.code === 'LimitExceededException') {
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED',
                    details: {
                        retryAfter: '30s'
                    }
                });
            }
            return res.status(500).json({
                message: 'Internal Server Error',
                code: 'SERVER_ERROR',
                details: {
                    error: error.message
                }
            });
        }
    });
    return app;
});

// Check for Duplicate Email:

const checkForDuplicateEmail = async (email, userPoolId, cognito) => {
    try {
        const params = {
            UserPoolId: userPoolId,
            Filter: `email = "${email.replace(/"/g, '\\"')}"`,
            Limit: 1,
        };
        const result = await cognito.listUsers(params).promise();
        return result.Users && result.Users.length > 0;
    } catch (error) {
        console.error('Error checking duplicate email:', error);
        return false;
    }
}

// Check for Duplicate Username:

const checkForDuplicateUsername = async (username, userPoolId, cognito) => {
    try {
        const params = {
            UserPoolId: userPoolId,
            Filter: `username = "${username.replace(/"/g, '\\"')}"`,
            Limit: 1,
        };
        const result = await cognito.listUsers(params).promise();
        return result.Users && result.Users.length > 0;
    } catch (error) {
        console.error('Error checking duplicate username:', error);
        return false;
    }
}

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};

// Helper function to validate email format
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Helper function to validate username length
const validateUsernameLength = (username) => {
    return username.length >= 5 && username.length <= 18;
};

// Helper function to validate username characters
const validateUsernameSpecialCharacters = (username) => {
    const specialCharRegex = /^[a-zA-Z0-9]+$/;
    return specialCharRegex.test(username);
};

// Helper function to validate password structure
const validatePassword = (password) => {
    const lengthValid = password.length >= 8;
    const containsNumber = /\d/.test(password);
    const containsSpecial = /[^A-Za-z0-9]/.test(password);

    return lengthValid && containsNumber && containsSpecial;
};