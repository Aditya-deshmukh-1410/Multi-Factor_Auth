const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const dotenv = require("dotenv");
const session = require("express-session");
const MySQLStore = require('express-mysql-session')(session);
const nodemailer = require("nodemailer");
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

dotenv.config();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static("public"));

// 1. Setup Database Connection Options
const dbOptions = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// 2. Create the MySQL Pool
const db = mysql.createPool(dbOptions);

// 3. Initialize the MySQL Session Store
// We pass it the options and tell it to use our existing db pool
const sessionStore = new MySQLStore(dbOptions, db);

app.use(
    session({
        key: 'mfa_session_cookie',
        secret: process.env.SESSION_SECRET,
        store: sessionStore,
        resave: false,
        saveUninitialized: false,
        cookie: {
             maxAge: 1000 * 60 * 60 * 24 // Sets session to expire in 1 day
        }
    })
);

// 5. Test the pool connection
db.getConnection((err, connection) => {
    if (err) {
        console.error("MySQL pool connection failed:", err.message);
        return;
    }
    console.log("MySQL pool connected successfully!");
    connection.release();
});

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.get("/", (req, res) => {
    res.redirect("/register.html");
});

app.post("/register", async (req, res) => {
    const {
        username,
        email,
        password,
        security_question,
        security_answer
    } = req.body;

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate TOTP secret
        const secret = speakeasy.generateSecret({
            name: `MFA Demo (${username})`
        });

        // Insert user into database
        const sql = `
            INSERT INTO users
            (
                username,
                email,
                password,
                security_question,
                security_answer,
                totp_secret
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        db.query(
            sql,
            [
                username,
                email,
                hashedPassword,
                security_question,
                security_answer,
                secret.base32
            ],
            async (err) => {

                if (err) {
                    console.log("Registration error:", err.message);
                    return res.send("Registration failed.");
                }

                // Generate QR code
                const qrCode = await QRCode.toDataURL(
                    secret.otpauth_url
                );

                res.send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Authenticator Setup</title>
                <link rel="stylesheet" href="/style.css">
                </head>

                <body>

                <div class="container">

                <div class="card">

                <div class="security-icon">📱</div>

                <h1>Authenticator Setup</h1>

                <p class="subtitle">
                    Your account has been created successfully.
                    Scan the QR code below with Google Authenticator.
                </p>

                <div class="steps">
                    <div class="step done">✓</div>
                    <div class="step active">2</div>
                    <div class="step">3</div>
                    <div class="step">4</div>
                    <div class="step">5</div>
                </div>

                <div style="
                    background: white;
                    padding: 15px;
                    border-radius: 14px;
                    width: fit-content;
                    margin: 25px auto;
                ">
                    <img
                        src="${qrCode}"
                        width="220"
                        alt="Google Authenticator QR Code"
                    >
                </div>

                <p class="subtitle">
                    Open <strong>Google Authenticator</strong>,
                    scan this QR code, and then continue to login.
                </p>

                <a href="/login.html" style="
                    display: block;
                    width: 100%;
                    padding: 13px;
                    border-radius: 10px;
                    background: #2563eb;
                    color: white;
                    text-decoration: none;
                    font-weight: bold;
                ">
                    Continue to Login
                </a>

                </div>

                </div>

                </body>
                </html>
                `);
            }
        );

    } catch (error) {
        console.log("Registration error:", error);
        res.send("Error during registration.");
    }
});


app.post("/login", (req, res) => {

    const { username, password } = req.body;

    const sql = `
        SELECT *
        FROM users
        WHERE username = ?
    `;

    db.query(sql, [username], async (err, results) => {

        if (err) {
            console.log("Database error:", err.message);
            return res.send("Database error.");
        }

        if (results.length === 0) {
            return res.send("Invalid username or password.");
        }

        const user = results[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.send("Invalid username or password.");
        }

        // Store user information in session
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.email = user.email;

        // Generate 6-digit OTP
        const otp = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        // Store OTP in session
        req.session.emailOTP = otp;

        // Send OTP to registered email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Your Login OTP",
            text: `Your login OTP is ${otp}`
        });

        // MFA step
        req.session.mfaStep = 1;

        res.redirect("/otp.html");
    });
});

app.post("/verify-otp", (req, res) => {

    const { otp } = req.body;

    if (
        !req.session.emailOTP ||
        otp !== req.session.emailOTP
    ) {
        return res.send("Invalid OTP.");
    }

    // OTP is correct
    delete req.session.emailOTP;

   req.session.mfaStep = 2;

    res.redirect("/security.html");
});


app.post("/verify-security", (req, res) => {

    const { answer } = req.body;

    const sql = `
        SELECT security_answer
        FROM users
        WHERE id = ?
    `;

    db.query(
        sql,
        [req.session.userId],
        (err, results) => {

            if (err || results.length === 0) {
                return res.send("Error.");
            }

            if (
                answer.trim().toLowerCase() !==
                results[0].security_answer.trim().toLowerCase()
            ) {
                return res.send("Incorrect security answer.");
            }

            req.session.mfaStep = 3;

            res.redirect("/captcha.html");
        }
    );
});

app.get("/security-question", (req, res) => {

    if (!req.session.userId) {
        return res.status(401).send("Unauthorized.");
    }

    const sql = `
        SELECT security_question
        FROM users
        WHERE id = ?
    `;

    db.query(
        sql,
        [req.session.userId],
        (err, results) => {

            if (err || results.length === 0) {
                return res.status(500).send("Error.");
            }

            res.json({
                question: results[0].security_question
            });
        }
    );
});

app.get("/captcha-value", (req, res) => {

    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let captcha = "";

    for (let i = 0; i < 6; i++) {
        captcha += characters.charAt(
            Math.floor(Math.random() * characters.length)
        );
    }

    req.session.captcha = captcha;

    res.json({
        captcha: captcha
    });
});


app.post("/verify-captcha", (req, res) => {

    const { captcha } = req.body;

    if (
        !req.session.captcha ||
        captcha !== req.session.captcha
    ) {
        return res.send("Invalid CAPTCHA.");
    }

    delete req.session.captcha;

    req.session.mfaStep = 4;

    res.redirect("/totp.html");
});

app.post("/verify-totp", (req, res) => {

    const { token } = req.body;

    const sql = `
        SELECT totp_secret
        FROM users
        WHERE id = ?
    `;

    db.query(
        sql,
        [req.session.userId],
        (err, results) => {

            if (err || results.length === 0) {
                return res.send("Error verifying TOTP.");
            }

            const secret = results[0].totp_secret;

            const verified = speakeasy.totp.verify({
                secret: secret,
                encoding: "base32",
                token: token,
                window: 1
            });

            if (!verified) {
                return res.send("Invalid Authenticator code.");
            }

            req.session.mfaStep = 5;
            req.session.authenticated = true;

            res.redirect("/dashboard.html");
        }
    );
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});

