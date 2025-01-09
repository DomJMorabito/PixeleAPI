import express from 'express';
import { Amplify } from 'aws-amplify';

import { getDbSecrets, getCognitoSecrets } from '../aws/secrets';
import { createPool } from '../db/pool';

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
};