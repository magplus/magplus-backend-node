const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'my_publish',
    password: 'postgres',
    port: 5432,
    ssl: false
});

// Test the database connection when the app starts
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Error connecting to the database:', err.stack);
    } else {
        console.log('Database connected:', res.rows);
    }
});


module.exports = pool;
