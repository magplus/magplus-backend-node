const express = require('express');
const pool = require('./db');  // Import the pool from db.js
const routes = require('./routes/routes');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const accountRoutes = require('./routes/accountRoutes');
const app = express();

// Middleware configurations
app.use(cors({
    credentials: true,
    origin: ['http://localhost:4200']
}));
app.use(cookieParser());
app.use(express.json());

// API routes
app.use("/api", routes);

// Check if the database connection is successful
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to the database:', err.stack);
    } else {
        console.log('Database connected successfully!');
        release(); // Release the client back to the pool
    }
});

app.use('/accounts', accountRoutes);

// Start the server
app.listen(5000, () => {
    console.log('App is listening on port 5000');
});
