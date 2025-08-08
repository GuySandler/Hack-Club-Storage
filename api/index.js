// imports
const express = require('express');
const app = express();
const { hotReloadMiddleware } = require("@devmade/express-hot-reload");
app.use(
	hotReloadMiddleware({
		watchFolders: ["./"],
		ignoreFiles: ["todo.txt"],
		ignorePatterns: ["**/node_modules/**", "**/database.db"],
		verbose: true,
	})
);

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require('body-parser');
const cors = require('cors');
require("dotenv").config();

const JWT_SECRET = process.env.jwt

app.use(cors());
app.use(bodyParser.json());

const db = require("better-sqlite3")("database.db");

const rateLimit = require("express-rate-limit");
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 500,
});
app.use(limiter);

const swaggerUI = require("swagger-ui-express");
const swaggerJsDocs = require("swagger-jsdoc");
const swagger = swaggerJsDocs({
	definition: {
		openapi: "3.0.0",
		info: {
			title: "Hack Club YSWS manager",
			version: "1.0.0",
			description: "An API to manage, find, and run Hack Club YSWSs",
		},
		servers: [
			{
				url: `http://localhost:1234`,
			},
		],
		components: {
			securitySchemes: {
				bearerAuth: {
					type: "http",
					scheme: "bearer",
					bearerFormat: "JWT"
				}
			}
		}
	},
	apis: ["index.js"],
});
app.use("/docs", swaggerUI.serve, swaggerUI.setup(swagger));


// auth
/**
 * @swagger
 * /api/login:
 *   get:
 *     summary: User login
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *       401:
 *         description: Invalid username or password
 *       400:
 *         description: No body
 */
app.get('/api/login', (req, res) => {
	const { username, password } = req.body;
	if (!username || !password) {
		return res.status(400).json({ error: 'Username and password are required' });
	}

	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
	if (!user) {
		return res.status(401).json({ error: 'No user found' });
	}

	// compare user raw password with db hash
	const isValid = bcrypt.compareSync(password, user.passwordHash);
	if (!isValid) {
		return res.status(401).json({ error: 'Invalid username or password' });
	}

	const token = jwt.sign({ id: user.id, username: user.username }, process.env.jwt, { expiresIn: "6h" });
	res.json({ token });
});

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: User sign up
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Account created and token returned
 *       409:
 *         description: Username already taken
 *       400:
 *         description: No body
 */
app.post('/api/register', (req, res) => {
	const { username, password } = req.body;
	if (!username || !password) {
		return res.status(400).json({ error: 'Username and password are required' });
	}
	const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
	if (existingUser) {
		return res.status(409).json({ error: 'Username already taken' });
	}

	const passwordHash = bcrypt.hashSync(password, 10);
	const insertUser = db.prepare("INSERT INTO users (username, passwordHash) VALUES (?, ?)");
	insertUser.run(username, passwordHash);

	// also auto log in
	const token = jwt.sign({ username }, process.env.jwt, { expiresIn: "6h" });
	res.json({ token });
});

function verifyToken(req, res, next) {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

	if (!token) {
		return res.status(401).json({ error: 'Access token required' });
	}

	jwt.verify(token, process.env.jwt, (err, decoded) => {
		if (err) {
			return res.status(403).json({ error: 'Invalid or expired token' });
		}
		req.user = decoded;
		next();
	});
}

function verifyTokenAdmin(req, res, next) {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

	if (!token) {
		return res.status(401).json({ error: 'Access token required' });
	}

	jwt.verify(token, process.env.jwt, (err, decoded) => {
		if (err) {
			return res.status(403).json({ error: 'Invalid or expired token' });
		}

		const user = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.id);
		if (!user) {
			return res.status(404).json({ error: 'User not found' });
		}

		if (user.rank == null || user.rank < 1) {
			return res.status(403).json({ error: 'Access denied' });
		}

		req.user = { ...decoded, rank: user.rank };
		next();
	});
}

// API stuff
/**
 * @swagger
 * /api/ping:
 *   get:
 *     summary: Ping
 *     responses:
 *       200:
 *         description: Pong response with timestamp
 */
app.get('/api/ping', (req, res) => {
	res.json({
		message: 'pong',
		timestamp: new Date().toISOString()
	});
});

/**
 * @swagger
 * /api/newdb:
 *   post:
 *     summary: clears DB, requires admin token (rank 1)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: DB reset successfully
 *       401:
 *         description: Access token required
 *       403:
 *         description: Access denied - insufficient permissions
 */
app.post("/api/newdb", verifyTokenAdmin, (req, res) => {
	db.exec("DROP TABLE IF EXISTS users");
	db.exec("DROP TABLE IF EXISTS ysws");

	db.exec(`
		CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		passwordHash TEXT NOT NULL,
		rank INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
  	`);
	db.exec(`
		CREATE TABLE IF NOT EXISTS ysws (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		startdate TEXT,
		enddate TEXT,
		owner INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
  	`);
	res.sendStatus(200);
});

// ysws
/**
 * @swagger
 * /api/ysws/getall:
 *   get:
 *     summary: Get all ysws
 *     responses:
 *       200:
 *         description: A JSON of all ysws
 */
app.get('/api/ysws/getall', (req, res) => {
	const dbselector = db.prepare("SELECT * FROM ysws");
	const ysws = dbselector.all();
	res.json(ysws);
});
/**
 * @swagger
 * /api/ysws/get/{id}:
 *   get:
 *     summary: Get a specific ysws by ID
 *     responses:
 *       200:
 *         description: A JSON object of the requested ysws
 *       404:
 *         description: YSWS not found
 *       400:
 *         description: No body
 */
app.get('/api/ysws/get/:id', (req, res) => {
	const { id } = req.params;
	if (!id) {
		return res.status(400).json({ error: 'YSWS ID is required' });
	}

	const dbselector = db.prepare("SELECT * FROM ysws WHERE id = ?");
	const ysws = dbselector.get(id);
	if (!ysws) {
		return res.status(404).json({ error: 'YSWS not found' });
	}
	res.json(ysws);
});
/**
 * @swagger
 * /api/ysws/new:
 *   post:
 *     summary: Create a new YSWS
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               startdate:
 *                 type: string
 *               enddate:
 *                 type: string
 *               userid:
 *                 type: integer
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: YSWS created successfully
 *       409:
 *         description: Username already taken
 *       400:
 *         description: No body
 */
// TODO: auto add user ID by token
app.post('/api/ysws/new', verifyToken, (req, res) => {
	const { name, description, startdate, enddate, userid } = req.body;
	if (!name || !description || !startdate || !enddate || !userid) {
		return res.status(400).json({ error: 'Name, description, start date, end date, and user ID are required' });
	}

	const data = db.prepare("INSERT INTO ysws (name, description, startdate, enddate, owner) VALUES (?, ?, ?, ?, ?)");
	data.run(name, description, startdate, enddate, userid);
	res.status(201).json({ message: 'YWS created successfully' });
});
/**
 * @swagger
 * /api/ysws/delete/{id}:
 *   delete:
 *     summary: Delete a YSWS by ID
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: YSWS deleted successfully
 *       404:
 *         description: YSWS not found
 *       400:
 *         description: No body
 *       500:
 *         description: Internal server error
 */
app.delete('/api/ysws/delete/:id', verifyToken, (req, res) => {
	const { id } = req.params;
	if (!id) {
		return res.status(400).json({ error: 'YSWS ID is required' });
	}

	try {
		const deleteRow = db.prepare("DELETE FROM ysws WHERE id = ?");
		const result = deleteRow.run(id);
		
		if (result.changes === 0) {
			return res.status(404).json({ error: 'YSWS not found' });
		}
		
		res.status(200).json({ message: 'YSWS deleted successfully' });
	} catch (error) {
		console.error('Delete error:', error);
		res.status(500).json({ error: 'Internal server error' });
	}
});
/**
 * @swagger
 * /api/ysws/search/{query}:
 *   get:
 *     summary: Search for ysws by name or description
 *     responses:
 *       200:
 *         description: A JSON object of the found ysws
 *       404:
 *         description: None found
 *       400:
 *         description: No body
 */
app.get('/api/ysws/search/:query', (req, res) => {
	const { query } = req.params;
	if (!query) {
		return res.status(400).json({ error: 'Search query is required' });
	}

	const dbselector = db.prepare("SELECT * FROM ysws WHERE name LIKE ? OR description LIKE ?");
	const ysws = dbselector.all(`%${query}%`, `%${query}%`);
	if (!ysws || ysws.length === 0) {
		return res.status(404).json({ error: 'No YSWS found' });
	}
	res.json(ysws);
});
/**
 * @swagger
 * /api/ysws/getactive:
 *   get:
 *     summary: Get all ongoing ysws
 *     responses:
 *       200:
 *         description: A JSON object of the found ysws
 *       404:
 *         description: None found
 */
app.get('/api/ysws/getactive', (req, res) => {
	const currentDate = new Date().toISOString().split('T')[0];
	const dbselector = db.prepare("SELECT * FROM ysws WHERE startdate <= ? AND enddate >= ?");
	const ysws = dbselector.all(currentDate, currentDate);

	if (!ysws || ysws.length === 0) {
		return res.status(404).json({ error: 'No active YSWS found' });
	}
	res.json(ysws);
});

// user stuff
/**
 * @swagger
 * /api/user/changename:
 *   put:
 *     summary: Change user name
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newusername:
 *                 type: string
 *               password:
 *                 type: string
 *               oldusername:
 *                 type: string
 *     responses:
 *       200:
 *         description: Account username updated successfully
 *       409:
 *         description: Username already taken
 *       400:
 *         description: No body
 *       404:
 *         description: User not found
 *       401:
 *         description: Invalid password
 */
app.put('/api/user/changename', (req, res) => {
	const { newusername, password, oldusername } = req.body;
	if (!newusername || !password || !oldusername) {
		return res.status(400).json({ error: 'New username, old password, and old username are required' });
	}
	// get user by name -> check if password matches -> check if new username is taken -> update username

	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(oldusername);
	if (!user) {
		return res.status(404).json({ error: 'User not found' });
	}

	const isValid = bcrypt.compareSync(password, user.passwordHash);
	if (!isValid) {
		return res.status(401).json({ error: 'Invalid password' });
	}

	const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(newusername);
	if (existingUser) {
		return res.status(409).json({ error: 'Username already taken' });
	}

	const updateUser = db.prepare("UPDATE users SET username = ? WHERE id = ?");
	updateUser.run(newusername, user.id);
	res.json({ message: 'Username updated successfully' });
});
/**
 * @swagger
 * /api/user/changerank:
 *   put:
 *     summary: User rank change by username, requires admin token (rank 1)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               newrank:
 *                 type: integer
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User rank updated successfully
 *       404:
 *         description: User not found
 *       400:
 *         description: No body
 */
app.put("/api/user/changerank", verifyTokenAdmin, (req, res) => {
	const { newrank, username } = req.body;
	if (newrank === undefined || !username) {
		return res
			.status(400)
			.json({ error: "New rank and username are required" });
	}

	const user = db
		.prepare("SELECT * FROM users WHERE username = ?")
		.get(username);
	if (!user) {
		return res.status(404).json({ error: "User not found" });
	}

	const updateUser = db.prepare("UPDATE users SET rank = ? WHERE id = ?");
	updateUser.run(newrank, user.id);
	res.json({ message: "User rank updated successfully" });
});
/**
 * @swagger
 * /api/user/delete/{id}:
 *   delete:
 *     summary: Delete a user by ID, requires admin token (rank 1)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       404:
 *         description: User not found
 *       400:
 *         description: No body
 */
app.delete('/api/user/delete/:id', verifyTokenAdmin, (req, res) => {
	const { id } = req.params;
	if (!id) {
		return res.status(400).json({ error: 'User ID is required' });
	}

	const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
	if (!user) {
		return res.status(404).json({ error: 'User not found' });
	}

	const deleteUser = db.prepare("DELETE FROM users WHERE id = ?");
	deleteUser.run(user.id);
	res.json({ message: 'User deleted successfully' });
});
/**
 * @swagger
 * /api/user/getall:
 *   get:
 *     summary: Get all users, requires admin token (rank 1)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *       404:
 *         description: No users found
 *       400:
 *         description: No body
 */
app.get('/api/user/getall', verifyTokenAdmin, (req, res) => {
	const dbselector = db.prepare("SELECT * FROM users");
	const users = dbselector.all();
	if (!users || users.length === 0) {
		return res.status(404).json({ error: 'No users found' });
	}
	res.json(users);
});
/**
 * @swagger
 * /api/user/get/{id}:
 *   get:
 *     summary: Get a specific user by ID, requires admin token (rank 1)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *       404:
 *         description: User not found
 *       400:
 *         description: No body
 */
app.get("/api/user/get/:id", verifyTokenAdmin, (req, res) => {
	const { id } = req.params;
	if (!id) {
		return res.status(400).json({ error: "User ID is required" });
	}

	const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
	if (!user) {
		return res.status(404).json({ error: "User not found" });
	}
	res.json(user);
});

app.listen(1234, () => {
	console.log('API server is running on http://localhost:1234');
});