import mysql from 'mysql2/promise';

export const createPool = (dbSecrets) => {
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