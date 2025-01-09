import express from "express";

import { createPool } from '../db/pool.js';
import { getDbSecrets } from "../aws/secrets.js";

export const initialize = async () => {
    try {
        const dbSecrets = await getDbSecrets().promise();

        const app = express();
        const pool = createPool(dbSecrets);

        return { app, pool }
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}