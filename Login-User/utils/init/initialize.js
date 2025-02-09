// Package Imports:

import express from "express";

// Utils Imports:

import { getDbSecrets } from '../aws/secrets.js'
import { createPool } from '../db/pool.js';

export const initialize = async () => {
    try {
        const dbSecrets = await getDbSecrets();

        const app = express();
        const pool = createPool(dbSecrets);

        return { app, pool };
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}