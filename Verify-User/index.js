import express from 'express';
import serverless from 'serverless-http';
import AWS from 'aws-sdk';

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

app.post('/users/verify', async (req, res) => {
    const { username, verificationCode } = req.body;

    if (!username || !verificationCode) {
        return res.status(400).json({ message: "All fields are required." });
    }

    const params = {
        ClientId: process.env.AWS_USER_POOL_CLIENT_ID,
        Username: username,
        ConfirmationCode: verificationCode,
    }

    try {
        const result = await cognito.confirmSignUp(params).promise();
        res.status(200).json({ message: 'Verification Successful!', result });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Verification Code is Incorrect." });
    }
});

export const handler = serverless(app);
