
require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
app.use(express.json());

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
    throw new Error("Configure DATABASE_URL and JWT_SECRET in .env");
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Swagger configuration
const swaggerSpec = swaggerJsdoc({
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Global Coding Academy API",
            version: "1.0.0",
            description: "Signup and login API"
        },
        servers: [{ url: "http://localhost:5000" }]
    },
    apis: ["./server.js"]
});

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - first_name
 *               - last_name
 *               - username
 *               - gender
 *               - country_code
 *               - password
 *               - email
 *             properties:
 *               first_name:
 *                 type: string
 *                 example: Peter
 *               last_name:
 *                 type: string
 *                 example: Mugisha
 *               username:
 *                 type: string
 *                 example: peter123
 *               gender:
 *                 type: string
 *                 enum: [Male, Female, Other]
 *                 example: Male
 *               country_code:
 *                 type: string
 *                 example: +250
 *               password:
 *                 type: string
 *                 format: password
 *                 example: StrongPass123!
 *               email:
 *                 type: string
 *                 format: email
 *                 example: peter@example.com
 *     responses:
 *       201:
 *         description: Account created successfully
 *       400:
 *         description: Invalid input
 *       409:
 *         description: Email or username already exists
 */
app.post("/api/auth/signup", async (req, res) => {
    try {
        const {
            first_name,
            last_name,
            username,
            gender,
            country_code,
            password,
            email
        } = req.body;

        if (
            typeof first_name !== "string" ||
            !first_name.trim() ||
            typeof last_name !== "string" ||
            !last_name.trim() ||
            typeof username !== "string" ||
            !/^[a-zA-Z0-9_]{3,50}$/.test(username) ||
            !["Male", "Female", "Other"].includes(gender) ||
            typeof country_code !== "string" ||
            !/^\+[1-9]\d{0,3}$/.test(country_code) ||
            typeof password !== "string" ||
            password.length < 8 ||
            password.length > 72 ||
            typeof email !== "string" ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
        ) {
            return res.status(400).json({
                message: "Please provide valid registration details."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const normalizedUsername = username.trim().toLowerCase();

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO users
                (first_name, last_name, username, gender,
                 country_code, password, email)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, first_name, last_name, username,
                       gender, country_code, email, created_at`,
            [
                first_name.trim(),
                last_name.trim(),
                normalizedUsername,
                gender,
                country_code,
                passwordHash,
                normalizedEmail
            ]
        );

        return res.status(201).json({
            message: "Account created successfully.",
            user: result.rows[0]
        });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({
                message: "Email or username already exists."
            });
        }

        console.error("Signup error:", error.message);
        return res.status(500).json({
            message: "Internal server error."
        });
    }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Log in with email or username
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [login, password]
 *             properties:
 *               login:
 *                 type: string
 *                 example: peter@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: StrongPass123!
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
app.post("/api/auth/login", async (req, res) => {
    try {
        const { login, password } = req.body;

        if (
            typeof login !== "string" ||
            !login.trim() ||
            typeof password !== "string" ||
            password.length > 72
        ) {
            return res.status(400).json({
                message: "Login and password are required."
            });
        }

        const identifier = login.trim().toLowerCase();

        const result = await pool.query(
            `SELECT id, first_name, last_name, username,
                    gender, country_code, email, password
             FROM users
             WHERE email = $1 OR username = $1
             LIMIT 1`,
            [identifier]
        );

        const user = result.rows[0];

        if (
            !user ||
            !(await bcrypt.compare(password, user.password))
        ) {
            return res.status(401).json({
                message: "Invalid username/email or password."
            });
        }

        const token = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || "1h" }
        );

        return res.json({
            message: "Login successful.",
            token,
            user: {
                id: user.id,
                first_name: user.first_name,
                last_name: user.last_name,
                username: user.username,
                gender: user.gender,
                country_code: user.country_code,
                email: user.email
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);
        return res.status(500).json({
            message: "Internal server error."
        });
    }
});

app.get("/", (req, res) => {
    res.json({
        message: "Global Coding Academy API is running!"
    });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Swagger UI: http://localhost:${PORT}/api-docs`);
});
