// Package Imports:

import { Filter } from 'bad-words';

// Utils Imports:

import {
    validateEmail,
    validatePassword,
    validateUsernameLength,
    validateUsernameSpecialCharacters
} from "../auth/validation.js";

export const validateInput = (req, res, next) => {
    const filter = new Filter();
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            details: {
                missingFields: [
                    !username && 'username',
                    !email && 'email',
                    !password && 'password',
                    !password && 'confirmPassword'
                ].filter(Boolean)
            }
        });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({
            message: 'Enter a valid email.',
            code: 'INVALID_EMAIL',
            details: {
                providedEmail: email
            }
        });
    }

    if (!validateUsernameLength(username)) {
        return res.status(400).json({
            message: 'Username must be 5-18 characters.',
            code: 'INVALID_USERNAME',
            details: {
                requirements: {
                    minLength: 5,
                    maxLength: 18
                }
            }
        });
    }

    if (!validateUsernameSpecialCharacters(username)) {
        return res.status(400).json({
            message: 'Username cannot contain any special characters.',
            code: 'INVALID_USERNAME',
            details: {
                requirements: {
                    allowedCharacters: 'alphanumeric'
                }
            }
        });
    }

    if (!validatePassword(password)) {
        return res.status(400).json({
            message: 'Password requirements not met.',
            code: 'INVALID_PASSWORD',
            details: {
                requirements: {
                    minLength: 8,
                    requiresNumber: true,
                    requiresSpecialChar: true
                }
            }
        });
    }

    if (filter.isProfane(username)) {
        return res.status(400).json({
            message: 'Seriously?',
            code: 'INAPPROPRIATE_CONTENT',
            details: {
                username: username
            }
        });
    }

    if (typeof username !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            details: {
                invalidFields: [
                    typeof username !== 'string' && 'username',
                    typeof email !== 'string' && 'email',
                    typeof password !== 'string' && 'password',
                    typeof password !== 'string' && 'confirmPassword'
                ].filter(Boolean)
            }
        });
    }

    req.body.username = username.trim().toLowerCase();
    req.body.email = email.trim().toLowerCase();
    req.body.password = password;
    next();
}