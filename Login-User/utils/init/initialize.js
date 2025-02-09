// Package Imports:

import { Amplify } from "aws-amplify";
import express from "express";

// Utils Imports:

import { getCognitoSecrets, getDbSecrets } from '../aws/secrets.js'
import { createPool } from '../db/pool.js';

export const initialize = async () => {
    try {
        const [dbSecrets, cognitoSecrets] = await Promise.all([
            getDbSecrets(),
            getCognitoSecrets()
        ]);

        Amplify.configure({
            Auth: {
                Cognito: {
                    userPoolClientId: cognitoSecrets.USER_POOL_CLIENT_ID,
                    userPoolId: cognitoSecrets.USER_POOL_ID,
                }
            }
        });

        const app = express();
        const pool = createPool(dbSecrets);

        return { app, pool };
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}