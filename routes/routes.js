const { Router } = require('express');
const jwt = require('jsonwebtoken');
const pool = require('../db'); 
const bcrypt = require('bcrypt');
const JWT_SECRET = 'your_secret_key';

const router = Router();

router.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ message: "User already exists" });
        }


        const saltRounds = 10; 
        const cryptedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Hashed password during signup:', cryptedPassword); 

        const newUser = await pool.query(
            'INSERT INTO users (name, email, crypted_password) VALUES ($1, $2, $3) RETURNING *',
            [username, email, cryptedPassword]
        );

        console.log("New user registered: ", newUser.rows[0]);

        res.status(201).json({ message: "User registered successfully!" });
    } catch (error) {
        console.error("Error during registration: ", error.message);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];

        if (!user) {
            console.error('User not found for email:', email);
            return res.status(400).json({ message: "Invalid credentials" });
        }

        console.log('User found:', user);  

        const passwordMatch = await bcrypt.compare(password, user.crypted_password);
        if (!passwordMatch) {
            console.error('Password mismatch');
            return res.status(400).json({ message: "Invalid credentials" });
        }

        await pool.query('UPDATE users SET last_login = $1 WHERE id = $2', [new Date(), user.id]);

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            message: "Login successfully!",
            token,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error("Error during login: ", error);
        res.status(500).json({ message: "Internal server error", error });
    }
});

module.exports = router;
