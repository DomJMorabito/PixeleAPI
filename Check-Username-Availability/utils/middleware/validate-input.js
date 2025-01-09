export const validateInput = (req, res, next) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).json({
            message: 'Username is required.',
            code: 'MISSING_FIELDS',
            details: {
                username: username
            }
        });
    }

    if (typeof username !== 'string') {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            details: {
                username: username
            }
        });
    }

    req.query.username = req.query.username.trim().toLowerCase();
    next();
}