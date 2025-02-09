// Package Imports:

import { Amplify } from "aws-amplify";
import { CookieStorage } from 'aws-amplify/utils';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
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

        const cookieStorage = new CookieStorage({
            path: '/',
            domain: 'pixele.gg',
            expires: 365,
            sameSite: 'strict',
            secure: true
        });

        cognitoUserPoolsTokenProvider.setKeyValueStorage(cookieStorage);

        const app = express();
        const pool = createPool(dbSecrets);

        return { app, pool };
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}