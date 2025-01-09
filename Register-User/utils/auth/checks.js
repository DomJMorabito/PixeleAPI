export const checkForDuplicateEmail = async (email, userPoolId, cognito) => {
    try {
        const params = {
            UserPoolId: userPoolId,
            Filter: `email = "${email.replace(/"/g, '\\"')}"`,
            Limit: 1,
        };
        const result = await cognito.listUsers(params).promise();
        return result.Users && result.Users.length > 0;
    } catch (error) {
        console.error('Error checking duplicate email:', error);
        return false;
    }
};

export const checkForDuplicateUsername = async (username, userPoolId, cognito) => {
    try {
        const params = {
            UserPoolId: userPoolId,
            Filter: `username = "${username.replace(/"/g, '\\"')}"`,
            Limit: 1,
        };
        const result = await cognito.listUsers(params).promise();
        return result.Users && result.Users.length > 0;
    } catch (error) {
        console.error('Error checking duplicate username:', error);
        return false;
    }
};