 export const getLockoutResponse = (lastFailedLoginAttempt) => {
    const lockoutDuration = 15 * 60 * 1000;
    const unlockTime = new Date(new Date(lastFailedLoginAttempt).getTime() + lockoutDuration);
    const remainingTime = Math.max(1, Math.ceil((unlockTime - new Date()) / 1000 / 60));

    return {
        status: 403,
        body: {
            message: 'Account temporarily locked.',
            code: 'ACCOUNT_LOCKED',
            required: {
                remainingTime: remainingTime
            }
        }
    };
};