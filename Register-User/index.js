import express from 'express';
import serverless from 'serverless-http';
import { Filter } from 'bad-words';
import AWS from 'aws-sdk';
import { signUp } from 'aws-amplify/auth';
import { Amplify } from 'aws-amplify';

Amplify.configure({
    Auth: {
        Cognito: {
            userPoolClientId: process.env.AWS_USER_POOL_CLIENT_ID,
            userPoolId: process.env.AWS_USER_POOL_ID,
        }
    }
});

const cognito = new AWS.CognitoIdentityServiceProvider();

const app = express();
app.use(express.json());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

app.post('/users/register', async (req, res) => {
    let { username, email, password } = req.body;
    const filter = new Filter();
    username = username.toLowerCase();

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({ message: "Enter a valid email." });
    }

    if (!validateUsernameLength(username)) {
        return res.status(400).json({ message: "Username must be 5-18 characters." });
    }

    if (!validateUsernameSpecialCharacters(username)) {
        return res.status(400).json({ message: "Username cannot contain any special characters." });
    }

    if (!validatePassword(password)) {
        return res.status(400).json({ message: "Password requirements not met." });
    }

    if (filter.isProfane(username)) {
        return res.status(400).json({ message: "Seriously?" });
    }

    try {
        const emailExists = await checkForDuplicateEmail(email);
        const usernameExists = await checkForDuplicateUsername(username);

        if (emailExists && usernameExists) {
            return res.status(409).json({ message: "Both Email and Username are already in use." });
        }

        if (emailExists) {
            return res.status(409).json({ message: "Email already in use." });
        }

        if (usernameExists) {
            return res.status(409).json({ message: "Username already in use." });
        }

        await signUp({
            username: username,
            password: password,
            options: {
                userAttributes: {
                    email: email,
                }
            }
        });
        return res.status(201).json({
            message: 'Registration Successful! Please check your email for verification.',
        });
    } catch (error) {
        console.error('Cognito sign up error:', error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
});

export const handler = serverless(app);

// Check for Duplicate Email:

const checkForDuplicateEmail = async (email) => {
    try {
        const params = {
            UserPoolId: process.env.AWS_USER_POOL_ID,
            Filter: `email = "${email}"`,
            Limit: 1,
        };
        const result = await cognito.listUsers(params).promise();
        return result.Users && result.Users.length > 0;
    } catch (error) {
        console.error('Error checking duplicate email:', error);
    }
}

// Check for Duplicate Username:

const checkForDuplicateUsername = async (username) => {
    try {
        const params = {
            UserPoolId: process.env.AWS_USER_POOL_ID,
            Filter: `username = "${username}"`,
            Limit: 1,
        };
        const result = await cognito.listUsers(params).promise();
        return result.Users && result.Users.length > 0;
    } catch (error) {
        console.error('Error checking duplicate username:', error);
    }
}

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