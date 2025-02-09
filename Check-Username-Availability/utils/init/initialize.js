// Package Imports:

import express from 'express';

export const initialize = async () => {
    try {
        return express();
    } catch (error) {
        console.error('Initialization failed:', error);
        throw error;
    }
}