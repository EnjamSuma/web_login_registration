const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2"); 

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const pass = process.env.ROOTPASS;
 
const conn = mysql.createConnection({host:"localhost",user:"root",password:pass,database:"login_registration",port:3306});

conn.connect(function(err)
{
	if(err)
		console.log("Could not connect to MySQL",err);
	else
		console.log("Database connection established");
	
});

//

app.post("/register", function(req, res) {

    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    if (!username || !email || !password) {
        return res.status(400).send(
            "All fields are required"
        );
    }

    const salt = crypto.randomBytes(16).toString("hex");

    const hashedPassword = crypto.pbkdf2Sync(
        password,
        salt,
        100000,
        64,
        "sha512"
    ).toString("hex");

    const sql = `
        INSERT INTO users (username, email, password, salt)
        VALUES (?, ?, ?, ?)
    `;

    conn.query(
        sql,
        [username, email, hashedPassword, salt],
        function(err, result) {

            if (err) {
                console.log(err);

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



app.post("/login", function(req, res) {

    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        return res.status(400).send(`
            <p>The login credentials were incorrect</p>
            <a href="/login.html">Back to Login</a>
        `);
    }

    const sql = "SELECT * FROM users WHERE username = ?";

    conn.query(sql, [username], function(err, result) {

        if (err) {
            console.log(err);
            return res.status(500).send("Database error");
        }

        if (result.length === 0) {
            return res.status(401).send(`
                <p>The login credentials were incorrect</p>
                <a href="/login.html">Back to Login</a>
            `);
        }

        const user = result[0];

        const hashedPassword = crypto.pbkdf2Sync(
            password,
            user.salt,
            100000,
            64,
            "sha512"
        ).toString("hex");

        if (hashedPassword === user.password) {
            res.send(`
                <h2>You have logged in successfully</h2>
                <a href="/login.html">Back to Login</a>
            `);
        } else {
            res.status(401).send(`
                <p>The login credentials were incorrect</p>
                <a href="/login.html">Back to Login</a>
            `);
        }
    });
});




app.listen(3000,function(){
	console.log("Server running at http://localhost:3000");
});