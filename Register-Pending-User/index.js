import express from 'express';
import mysql from 'mysql2/promise';
import serverless from 'serverless-http';
import crypto from 'crypto';
import bcryptjs from 'bcryptjs';
import { Filter } from 'bad-words';

const app = express();

// Middleware to parse JSON body:

app.use(express.json());

// Enable CORS for all routes:

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// POST Endpoint to put a user into the "pending_users" table:

app.post('/users/pending', async (req, res) => {
    const { username, email, password } = req.body;
    const filter = new Filter();

    if (!username || !email || !password || !password) {
        return res.status(400).json({ message: "All fields are required." });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({ message: "Enter a valid email." });
    }

    if (!validateUsernameLength(username)) {
        return res.status(400).json({ message: "Username must be 5-18 characters." });
    }

    if (!validateUsernameSpecialCharacters(username)) {
        return res.status(400).json({ message: "Username cannot contain any special characters."});
    }

    if (!validatePassword(password)) {
        return res.status(400).json({ message: "Password requirements not met." });
    }

    if (filter.isProfane(username)) {
        return res.status(400).json({ message: "Seriously?" });
    }

    try {
        const connection = await mysql.createConnection(dbConfig);

        const checkQueryUsername = `
            SELECT username FROM pending_users WHERE username = ?
            UNION
            SELECT username FROM users WHERE username = ?
        `;

        const checkQueryEmail = `
            SELECT email FROM pending_users WHERE email = ?
            UNION
            SELECT email FROM users WHERE email = ?
        `;

        const [usernameRows] = await connection.query(checkQueryUsername, [username, username]);
        const [emailRows] = await connection.query(checkQueryEmail, [email, email]);

        if (usernameRows.length > 0 && emailRows.length > 0) {
            return res.status(409).json({ message: "Both Email and Username are already in use." });
        }

        if (emailRows.length > 0) {
            return res.status(409).json({ message: "Email already in use." });
        }

        if (usernameRows.length > 0) {
            return res.status(409).json({ message: "Username already in use." });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        const insertQuery = `
            INSERT INTO pending_users (username, email, password, verification_token) 
            VALUES (?, ?, ?, ?)
        `;
        const verification_token = generateToken();
        await connection.query(insertQuery, [username, email, hashedPassword, verification_token]);
        await connection.end();

        return res.status(201).json({
            message: "Added to pending_users!",
            verification_token: verification_token,
        });
    } catch (error) {
        console.error('Error inserting into database:', error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
});

export const handler = serverless(app);

// Environment Variables for MySQL Connection:

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
};

// Generates a random verification token:

const generateToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Validate email format:

const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Validate username length:

const validateUsernameLength = (username) => {
    return username.length >= 5 && username.length <= 18;
};

// Validate username characters:

const validateUsernameSpecialCharacters = (username) => {
    const specialCharRegex = /^[a-zA-Z0-9]+$/;
    return specialCharRegex.test(username);
};

// Validate password structure:

const validatePassword = (password) => {
    const lengthValid = password.length >= 8;
    const containsNumber = /\d/.test(password);
    const containsSpecial = /[^A-Za-z0-9]/.test(password);

    return lengthValid && containsNumber && containsSpecial;
};

/**
 * import mysql from 'mysql2/promise';
 * import crypto from 'crypto';
 * import bcryptjs from 'bcryptjs';
 * import { Filter } from 'bad-words';
 *
 * export const handler = async (event) => {
 *     try {
 *         // Ensure it's a POST request
 *         if (event.httpMethod !== 'POST') {
 *             return {
 *                 statusCode: 405,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: 'Method Not Allowed' }),
 *             };
 *         }
 *
 *         const body = JSON.parse(event.body);
 *         const { username, email, password } = body;
 *         const filter = new Filter();
 *
 *         // Input validation
 *         if (!username || !email || !password) {
 *             return {
 *                 statusCode: 400,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "All fields are required." }),
 *             };
 *         }
 *
 *         if (!validateEmail(email)) {
 *             return {
 *                 statusCode: 400,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Enter a valid email." }),
 *             };
 *         }
 *
 *         if (!validateUsername(username)) {
 *             return {
 *                 statusCode: 400,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Username must be 5-18 characters." }),
 *             };
 *         }
 *
 *         if (!validatePassword(password)) {
 *             return {
 *                 statusCode: 400,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Password requirements not met." }),
 *             };
 *         }
 *
 *         if (filter.isProfane(username)) {
 *             return {
 *                 statusCode: 400,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Seriously?" }),
 *             };
 *         }
 *
 *         // Database connection and query
 *         const connection = await mysql.createConnection(dbConfig);
 *
 *         const checkQueryUsername = `
 *             SELECT username FROM pending_users WHERE username = ?
 *             UNION
 *             SELECT username FROM users WHERE username = ?
 *         `;
 *
 *         const checkQueryEmail = `
 *             SELECT email FROM pending_users WHERE email = ?
 *             UNION
 *             SELECT email FROM users WHERE email = ?
 *         `;
 *
 *         const [usernameRows] = await connection.query(checkQueryUsername, [username, username]);
 *         const [emailRows] = await connection.query(checkQueryEmail, [email, email]);
 *
 *         if (usernameRows.length > 0 && emailRows.length > 0) {
 *             return {
 *                 statusCode: 409,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Both Email and Username are already in use" }),
 *             };
 *         }
 *
 *         if (emailRows.length > 0) {
 *             return {
 *                 statusCode: 409,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Email already in use" }),
 *             };
 *         }
 *
 *         if (usernameRows.length > 0) {
 *             return {
 *                 statusCode: 409,
 *                 headers: {
 *                     'Content-Type': 'application/json',
 *                     'Access-Control-Allow-Origin': '*',  // CORS
 *                 },
 *                 body: JSON.stringify({ message: "Username already in use" }),
 *             };
 *         }
 *
 *         const hashedPassword = await bcryptjs.hash(password, 10);
 *
 *         const insertQuery = `
 *             INSERT INTO pending_users (username, email, password, verification_token)
 *             VALUES (?, ?, ?, ?)
 *         `;
 *
 *         const verification_token = generateToken();
 *         await connection.query(insertQuery, [username, email, hashedPassword, verification_token]);
 *         await connection.end();
 *
 *         return {
 *             statusCode: 201,
 *             headers: {
 *                 'Content-Type': 'application/json',
 *                 'Access-Control-Allow-Origin': '*',  // CORS
 *             },
 *             body: JSON.stringify({
 *                 message: "Registration Successful!",
 *                 verification_token: verification_token,
 *             }),
 *         };
 *     } catch (error) {
 *         console.error('Error inserting into database:', error);
 *         return {
 *             statusCode: 500,
 *             headers: {
 *                 'Content-Type': 'application/json',
 *                 'Access-Control-Allow-Origin': '*',  // CORS
 *             },
 *             body: JSON.stringify({ message: "Internal Server Error" }),
 *         };
 *     }
 * };
 *
 * // Environment Variables for MySQL Connection:
 * const dbConfig = {
 *     host: process.env.DB_HOST,
 *     user: process.env.DB_USER,
 *     password: process.env.DB_PASSWORD,
 *     database: process.env.DB_NAME,
 * };
 *
 * // Generates a random verification token:
 * const generateToken = () => {
 *     return crypto.randomBytes(32).toString('hex');
 * };
 *
 * // Validate email format:
 * const validateEmail = (email) => {
 *     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
 *     return emailRegex.test(email);
 * }
 *
 * // Validate username length:
 * const validateUsername = (username) => {
 *     return username.length >= 5 && username.length <= 18;
 * }
 *
 * // Validate password structure:
 * const validatePassword = (password) => {
 *     const lengthValid = password.length >= 8;
 *     const containsNumber = /\d/.test(password);
 *     const containsSpecial = /[^A-Za-z0-9]/.test(password);
 *
 *     return lengthValid && containsNumber && containsSpecial;
 * }
 */