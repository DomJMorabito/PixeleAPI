export const validateInput = (req, res, next) => {
    const { username, verificationCode } = req.body;

    if (!username || !verificationCode) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            requirements: [
                !username && 'username',
                !verificationCode && 'code'
            ].filter(Boolean)
        });
    }

    if (typeof username !== 'string'
        || typeof verificationCode !== 'string'
        || !username.trim()
        || !verificationCode.trim()
    ) {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            requirements: [
                typeof username !== 'string' && 'username',
                typeof verificationCode !== 'string' && 'code'
            ].filter(Boolean)
        });
    }

    req.body.username = username.trim().toLowerCase();
    req.body.verificationCode = verificationCode.trim();
    next();
}