import AWS from 'aws-sdk';

const secretsManager = new AWS.SecretsManager();

export const getCognitoSecrets = async () => {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.AUTH_SECRET_ID
        }).promise();
        try {
            return JSON.parse(data.SecretString);
        } catch (parseError) {
            console.error('Error parsing secrets:', parseError);
        }
    } catch (error) {
        console.error('Error retrieving secrets:', error);
        throw error;
    }
}

export const getDbSecrets = async () => {
    try {
        const data = await secretsManager.getSecretValue({
            SecretId: process.env.DB_SECRET_ID
        }).promise();
        try {
            return JSON.parse(data.SecretString);
        } catch (parseError) {
            console.error('Error parsing secrets:', parseError);
        }
    } catch (error) {
        console.error('Error retrieving secrets:', error);
        throw error;
    }
}