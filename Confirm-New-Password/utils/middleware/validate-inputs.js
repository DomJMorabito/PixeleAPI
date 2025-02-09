// Utils Imports:

import { validatePassword } from '../auth/validation.js';

export const validateInputs = (req, res, next) => {
    const { username, confirmationCode, newPassword } = req.body;

    if (!username || !confirmationCode || !newPassword) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            details: {
                missingFields: [
                    !username && 'username',
                    !confirmationCode && 'code',
                    !newPassword && 'password',
                    !newPassword && 'confirmPassword'
                ].filter(Boolean)
            }
        });
    }

    if (!validatePassword(newPassword)) {
        return res.status(400).json({
            message: 'Password requirements not met.',
            code: 'INVALID_PASSWORD',
            details: {
                minLength: 8,
                requiresNumber: true,
                requiresSpecialChar: true
            }
        });
    }

    if (typeof username !== 'string' || typeof confirmationCode !== 'string' || typeof newPassword !== 'string') {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            details: {
                invalidFields: [
                    typeof username !== 'string' && 'username',
                    typeof confirmationCode !== 'string' && 'code',
                    typeof newPassword !== 'string' && 'password',
                    typeof newPassword !== 'string' && 'confirmPassword'
                ].filter(Boolean)
            }
        });
    }

    req.body.username = username.trim().toLowerCase();
    req.body.confirmationCode = confirmationCode.trim();
    req.body.newPassword = newPassword;
    next();
}