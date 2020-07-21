const express = require("express");
const cors = require("cors");
const bcryptjs = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const usersRouter = require("./users/usersRouter");
const authRouter = require("./auth/authRouter");
const dbConnection = require("./data/dbConfig");
const authenticate = require("./auth/authMiddleware");

const server = express();

const sessionConfiguration = {
    name: "users",
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!",
    cookie: {
        maxAge: 1000 * 60 * 30,
        secure: process.env.USE_SECURE_COOKIES || false, 
        httpOnly: true, 
    },
    resave: false,
    saveUninitialized: true,
    store: new KnexSessionStore({
        knex: dbConnection,
        tablename: "sessions",
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 1000 * 60 * 30, 
    }),
};

server.use(session(sessionConfiguration)); 
server.use(express.json());
server.use(cors());

server.use("/api/users", authenticate, usersRouter);
server.use("/api/auth", authRouter);

server.get("/", (req, res) => {
    res.json({ api: "up" });
});

server.get("/hash", (req, res) => {
    const password = req.headers.authorization;
    const secret = req.headers.secret;

    const hash = hashString(secret);

    if (password === "dolphin") {
        res.json({ welcome: "user", secret, hash });
    } else {
        res.status(401).json({ error: "unauthorized" });
    }
});

function hashString(str) {
    const rounds = process.env.HASH_ROUNDS || 8;
    const hash = bcryptjs.hashSync(str, rounds);

    return hash;
}

module.exports = server;