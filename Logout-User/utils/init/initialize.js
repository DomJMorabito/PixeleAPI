// Package Imports:

import express from 'express';

export const initialize = async () => {
    try {
        const app = express();
        return { app };
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}