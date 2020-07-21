const bcryptjs = require("bcryptjs");
const router = require("express").Router();

const users = require("../users/usersModel");

router.post("/register", (req, res) => {
    let creds = req.body;
    const rounds = process.env.HASH_ROUNDS || 8;

    const hash = bcryptjs.hashSync(creds.password, rounds);

    creds.password = hash;

    users.add(creds)
        .then(info => {
            res.status(201).json({ data: info });
        })
        .catch(err => {
            res.status(500).json({ error: err.message });
        });
});

router.post("/login", (req, res) => {
    const { username, password } = req.body;

    users.findBy({ username })
        .then(users => {
            const user = users[0];

            if (user && bcryptjs.compareSync(password, user.password)) {
                req.session.loggedIn = true;
                req.session.username = user.username;

                res.status(200).json({ message: "welcome!", session: req.session });
            } else {
                res.status(401).json({ message: "Invalid credentials" });
            }
        })
        .catch(err => {
            res.status(500).json({ error: err.message });
        });
});

router.get("/logout", (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                res.status(500).json({ message: "error logging out, please try later" });
            } else {
                res.status(204).end();
            }
        });
    } else {
        res.status(200).json({ message: "already logged out" });
    }
});

module.exports = router;
