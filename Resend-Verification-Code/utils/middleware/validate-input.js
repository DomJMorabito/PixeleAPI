export const validateInput = (req, res, next) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            requirements: [
                !username || 'username'
            ].filter(Boolean)
        });
    }

    if (typeof username !== 'string' || !username.trim()) {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            requirements: [
                typeof username !== 'string' && 'username'
            ].filter(Boolean)
        });
    }

    req.body.username = username.trim().toLowerCase();
    next();
}