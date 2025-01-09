export const validateInput = (req, res, next) => {
    const { username, verificationCode } = req.body;

    if (!username || !verificationCode) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            details: {
                missingFields: [
                    !username && 'username',
                    !verificationCode && 'verificationCode',
                ].filter(Boolean)
            }
        });
    }

    if (typeof username !== 'string' || typeof verificationCode !== 'string') {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            details: {
                invalidFields: [
                    typeof username !== 'string' && 'username',
                    typeof verificationCode !== 'string' && 'verificationCode'
                ].filter(Boolean)
            }
        });
    }

    req.body.username = username.trim().toLowerCase();
    req.body.verificationCode = verificationCode.trim();
    next();
}