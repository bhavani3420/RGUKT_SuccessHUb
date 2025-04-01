const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
    session({
        secret: "my_secret_key",
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false, httpOnly: true }, // Ensure cookies are used properly
    })
);

// MySQL Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Bhavani@3420",
    database: "rgukt_achievements",
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed: " + err.stack);
        return;
    }
    console.log("Connected to MySQL database.");
});

// Serve index.html
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});


// Signup Route
app.post("/signup", (req, res) => {
    const { username, email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.json({ success: false, message: "Database error." });
        }
        if (results.length > 0) {
            return res.json({ success: false, message: "Email already registered." });
        }

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error(err);
                return res.json({ success: false, message: "Error hashing password." });
            }

            db.query(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                [username, email, hash],
                (err) => {
                    if (err) {
                        console.error(err);
                        return res.json({ success: false, message: "Signup failed." });
                    }
                    res.json({ success: true, message: "Signup successful!" });
                }
            );
        });
    });
});

// Login Route
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.json({ success: false, message: "Database error." });
        }
        if (results.length === 0) {
            return res.json({ success: false, message: "User not found." });
        }

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error(err);
                return res.json({ success: false, message: "Error verifying password." });
            }
            if (!isMatch) {
                return res.json({ success: false, message: "Invalid credentials." });
            }

            req.session.user = { id: user.id, username: user.username }; // Store minimal user data
            res.json({ success: true, message: "Login successful!" });
        });
    });
});

// Check Authentication Status
app.post("/submit-achievement", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "You need to log in to submit the form." });
    }

    // Just return success without saving to the database
    res.json({ success: true, message: "Achievement submitted successfully!" });
});

app.get("/check-auth", (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, username: req.session.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});


// Logout Route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Logout failed." });
        }
        res.clearCookie("connect.sid"); // Clears session cookie
        res.redirect("/"); // Redirect to home page after logout
    });
});


 //form submission
 app.post("/submit-achievement", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: "You need to log in to submit the form." });
    }

    // Process form data here (store in database, etc.)
    res.json({ message: "Achievement submitted successfully!" });
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
