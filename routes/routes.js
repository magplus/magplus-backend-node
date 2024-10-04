const { Router } = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');  
const JWT_SECRET = 'your_secret_key';   

const router = Router();
router.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        user = new User({
            name: username,
            email: email,
            password: hashedPassword
        });

        await user.save();
        console.log("New user registered: ", user);

        res.status(201).json({ message: "User registered successfully!" });
    } catch (error) {
        console.error("Error during registration: ", error);
        res.status(500).json({ message: "Internal server error", error });
    }
});

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        let user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        user.lastLogin = new Date();  
        await user.save();            
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            message: "Login successfully!",
            token,
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error("Error during login: ", error);
        res.status(500).json({ message: "Internal server error", error });
    }
});
module.exports = router;
