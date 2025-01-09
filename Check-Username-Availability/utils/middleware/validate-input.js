export const validateInput = (req, res, next) => {
    const { username } = req.query.username;

    if (!username) {
        if (!username) {
            return res.status(400).json({
                message: 'Username is required.',
                code: 'MISSING_FIELDS',
                details: {
                    username: username
                }
            });
        }
    }

    if (typeof username !== 'string') {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            details: {
                invalidFields: [
                    typeof username !== 'string' && 'username'
                ].filter(Boolean)
            }
        });
    }

    req.query.username = req.query.username.trim().toLowerCase();
    next();
}