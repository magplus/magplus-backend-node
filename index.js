const express = require('express');
const pool = require('./config/db');  
const routes = require('./routes/routes');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const accountRoutes = require('./routes/accountRoutes'); 
const app = express();


app.use(cors({
    credentials: true,
    origin: ['http://localhost:4200'] 
}));
app.use(cookieParser());
app.use(express.json()); 
app.use("/api", routes); 


pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to the database:', err.stack);
    } else {
        console.log('Database connected successfully!');
        release(); 
    }
});


app.use('/accounts', accountRoutes);

app.listen(5000, () => {
    console.log('App is listening on port 5000');
});
