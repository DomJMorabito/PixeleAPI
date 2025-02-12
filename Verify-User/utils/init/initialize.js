// Package Imports:

import express from "express";

// Utils Imports:

import { getSecrets } from "../aws/secrets.js";

export const initialize = async () => {
    try {
        await getSecrets();
        return express();
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}