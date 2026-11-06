
const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const app = express();

// Read data submitted through HTML forms
app.use(express.urlencoded({ extended: true }));

// Serve HTML files from the public folder
app.use(express.static("public"));

// Parse cookies sent by the browser
app.use(cookieParser());

// Configure session management
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60000 * 60, // 1 hour
        httpOnly: true,
        secure: false       // Local HTTP development
    }
}));

// Read MySQL password from environment variable
const pass = process.env.ROOTPASS;

// Connect to the MySQL database
const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: pass,
    database: "login_registration",
    port: 3306
});

conn.connect(function(err) {
    if (err) {
        console.log("Could not connect to MySQL", err);
    } else {
        console.log("Database connection established");
    }
});

// Escape special HTML characters to prevent HTML injection
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

/*
 * Registration Route
 * Registers a new user and stores their hashed password.
 */
app.post("/register", function(req, res) {

    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    // Check whether all required fields are provided
    if (!username || !email || !password) {
        return res.status(400).send(
            "All fields are required"
        );
    }

    // Generate a unique random salt for each user
    const salt = crypto.randomBytes(16).toString("hex");

    // Hash the password using PBKDF2
    const hashedPassword = crypto.pbkdf2Sync(
        password,
        salt,
        100000,
        64,
        "sha512"
    ).toString("hex");

    // Insert user information into MySQL
    const sql = `
        INSERT INTO users (username, email, password, salt)
        VALUES (?, ?, ?, ?)
    `;

    conn.query(
        sql,
        [username, email, hashedPassword, salt],
        function(err, result) {

            if (err) {
                console.log("Registration error:", err);

                return res.status(400).send(
                    "Registration failed. Username or email may already exist."
                );
            }

            res.send(`
                <h2>You have successfully registered</h2>
                <a href="/login.html">Go to Login</a>
            `);
        }
    );
});

/*
 * Login Route
 * Verifies the username and password.
 * Stores the username in a session after successful login.
 */
app.post("/login", function(req, res) {

    const username = req.body.username;
    const password = req.body.password;

    // Check whether login fields are provided
    if (!username || !password) {
        return res.status(400).send(`
            <p>The login credentials were incorrect</p>
            <a href="/login.html">Back to Login</a>
        `);
    }

    // Retrieve the user from MySQL
    const sql = "SELECT * FROM users WHERE username = ?";

    conn.query(sql, [username], function(err, result) {

        if (err) {
            console.log("Login database error:", err);
            return res.status(500).send("Database error");
        }

        // Username does not exist
        if (result.length === 0) {
            return res.status(401).send(`
                <p>The login credentials were incorrect</p>
                <a href="/login.html">Back to Login</a>
            `);
        }

        const user = result[0];

        // Hash the entered password using the stored salt
        const hashedPassword = crypto.pbkdf2Sync(
            password,
            user.salt,
            100000,
            64,
            "sha512"
        ).toString("hex");

        // Compare the hashed password with the stored password
        if (hashedPassword === user.password) {

            // Regenerate the session after authentication
            req.session.regenerate(function(err) {

                if (err) {
                    console.log("Session regeneration error:", err);
                    return res.status(500).send(
                        "Unable to create login session"
                    );
                }

                // Store the authenticated username in the session
                req.session.user = {
                    username: user.username
                };

                // Save the session before responding
                req.session.save(function(err) {

                    if (err) {
                        console.log("Session error:", err);
                        return res.status(500).send(
                            "Unable to save login session"
                        );
                    }

                    res.send(`
                        <h2>You have logged in successfully</h2>
                        <p>Welcome, ${escapeHtml(user.username)}!</p>
                        <a href="/profile">View Profile</a>
                        <br><br>
                        <a href="/logout">Logout</a>
                    `);
                });
            });

        } else {
            // Password is incorrect
            res.status(401).send(`
                <p>The login credentials were incorrect</p>
                <a href="/login.html">Back to Login</a>
            `);
        }
    });
});

/*
 * Profile Route
 * Displays the username stored in the session.
 * Only logged-in users can access this page.
 */
app.get("/profile", function(req, res) {

    // Check whether the user has an active session
    if (!req.session.user) {
        return res.status(401).send(`
            <h2>You are not logged in</h2>
            <a href="/login.html">Login here</a>
        `);
    }

    // Retrieve the username from the session
    const username = req.session.user.username;

    // Display the logged-in user's username
    res.send(`
        <h2>My Profile</h2>
        <p>Welcome, ${escapeHtml(username)}!</p>
        <p>You are currently logged in.</p>
        <a href="/logout">Logout</a>
    `);
});

/*
 * Logout Route
 * Destroys the user's session when they click Logout.
 */
app.get("/logout", function(req, res) {

    // Destroy the current session
    req.session.destroy(function(err) {

        if (err) {
            console.log("Logout error:", err);
            return res.status(500).send(
                "Error logging out"
            );
        }

        // Remove the session cookie from the browser
        res.clearCookie("connect.sid");

        res.send(`
            <h2>Logged out successfully!</h2>
            <a href="/login.html">Login again</a>
        `);
    });
});

// Start the Express server
app.listen(3000, function() {
    console.log("Server running at http://localhost:3000");
});
