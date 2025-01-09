export const validateInput = (req, res, next) => {
    const { identifier } = req.body;

    if (!identifier) {
        return res.status(400).json({
            message: 'Username or Email is required.',
            code: 'MISSING_FIELDS',
            details: {
                missingFields: [
                    !identifier && 'identifier'
                ].filter(Boolean)
            }
        });
    }

    if (typeof identifier !== 'string') {
        return res.status(400).json({
            message: 'All fields must be valid.',
            code: 'INVALID_INPUT',
            details: {
                invalidFields: [
                    typeof identifier !== 'string' && 'identifier'
                ].filter(Boolean)
            }
        });
    }

    req.body.identifier = identifier.trim().toLowerCase();
    next();
}