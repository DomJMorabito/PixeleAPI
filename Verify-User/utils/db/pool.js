import mysql from 'mysql2/promise';

export const createPool = (dbSecrets) => {
    if (!dbSecrets.host || !dbSecrets.username || !dbSecrets.password || !dbSecrets.port) {
        throw new Error('Required RDS credentials not found in secrets');
    }

    return mysql.createPool({
        host: dbSecrets.host,
        user: dbSecrets.username,
        password: dbSecrets.password,
        database: 'pixele',
        port: dbSecrets.port,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 5
    });
};