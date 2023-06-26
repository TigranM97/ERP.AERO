const {createPool} = require('mysql')
require('dotenv').config()

const pool = createPool({
    port: process.env.DB_PORT,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10 
})

pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to the database:', err);
      return;
    }
    console.log('Connected to the database.');
  
    // Release the connection
    connection.release();
  });

module.exports = pool