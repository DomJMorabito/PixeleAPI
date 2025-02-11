export const validateInput = (req, res, next) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({
            message: 'All fields are required.',
            code: 'MISSING_FIELDS',
            requirements: [
                !identifier && 'identifier',
                !password && 'password'
            ].filter(Boolean)
        });
    }

    if (typeof identifier !== 'string'
        || typeof password !== 'string'
        || !identifier.trim()
        || !password.trim()
    ) {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            requirements: [
                typeof identifier !== 'string' && 'identifier',
                typeof password !== 'string' && 'password'
            ].filter(Boolean)
        });
    }

    req.body.identifier = identifier.trim().toLowerCase();
    req.body.password = password;
    next();
}