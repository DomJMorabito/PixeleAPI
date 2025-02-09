// Package Imports:

import { Amplify } from "aws-amplify";
import express from "express";

// Utils Imports:

import { getSecrets } from '../aws/secrets.js';

export const initialize = async () => {
    try {
        const secrets = await getSecrets();

        Amplify.configure({
            Auth: {
                Cognito: {
                    userPoolClientId: secrets.USER_POOL_CLIENT_ID,
                    userPoolId: secrets.USER_POOL_ID,
                }
            }
        });

        const app = express();
        return { app };
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}