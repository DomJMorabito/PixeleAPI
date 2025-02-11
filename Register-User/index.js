// Package Imports:

import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

// Utils Imports:

import { initialize } from './utils/init/initialize.js';
import { corsMiddleware } from './utils/middleware/cors.js';
import { checkForDuplicateEmail, checkForDuplicateUsername } from './utils/auth/checks.js';
import { getCognitoSecrets } from './utils/aws/secrets.js';
import { validateInput } from "./utils/middleware/validate-input.js";

let app;
let pool;

const appPromise = initialize().then(({ app: initializedApp, pool: initializedPool }) => {
    app = initializedApp;
    pool = initializedPool;

    app.use(express.json({ limit: '10kb' }));
    app.use(corsMiddleware);

    app.post('/users/register', validateInput, async (req, res) => {
        const cognitoSecrets = await getCognitoSecrets();
        const cognito = new AWS.CognitoIdentityServiceProvider();
        let { username, email, password } = req.body;

        try {
            const [emailExists, usernameExists] = await Promise.all([
                checkForDuplicateEmail(email, cognitoSecrets.USER_POOL_ID, cognito),
                checkForDuplicateUsername(username, cognitoSecrets.USER_POOL_ID, cognito)
            ]);

            if (emailExists && usernameExists) {
                return res.status(409).json({
                    message: 'Both Email and Username are already in use.',
                    code: 'DUPLICATE_CREDENTIALS'
                });
            }

            if (emailExists) {
                return res.status(409).json({
                    message: 'Email already in use.',
                    code: 'EMAIL_EXISTS'
                });
            }

            if (usernameExists) {
                return res.status(409).json({
                    message: 'Username already in use.',
                    code: 'USERNAME_EXISTS'
                });
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

                try {
                    const signUpParams = {
                        ClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
                        Username: username,
                        Password: password,
                        UserAttributes: [
                            {
                                Name: 'email',
                                Value: email
                            }
                        ]
                    };

                    await cognito.signUp(signUpParams).promise();

                    await connection.commit();

                    return res.status(201).json({
                        message: 'Registration Successful!',
                        code: 'REGISTRATION_SUCCESS'
                    });
                } catch (cognitoError) {
                    await connection.rollback();
                    console.error('Cognito SignUp failed:', cognitoError);
                }
            } catch (dbError) {
                await connection.rollback();
                console.error('Database Insertion failed:', dbError);
                return res.status(500).json({
                    message: 'Database error occurred. Please try again later.',
                    code: 'DATABASE_ERROR'
                });
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error('Registration error:', error);
            if (error.code === 'LimitExceededException') {
                return res.status(429).json({
                    message: 'Too many attempts. Please try again later.',
                    code: 'RATE_LIMIT_EXCEEDED'
                });
            }
            return res.status(500).json({
                message: 'Internal Server Error',
                code: 'SERVER_ERROR'
            });
        }
    });
    return app;
});

export const handler = async (event, context) => {
    await appPromise;
    return serverless(app)(event, context);
};