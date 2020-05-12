const express = require("express")
const Users = require("./users-model")
const restrict = require("../middleware/restrict")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const router = express.Router()

// This endpoint is only available to logged-in users due to the `restrict` middleware
router.get("/users", restrict(), async (req, res, next) => {
	try {
		res.json(await Users.find())
	} catch(err) {
		next(err)
	}
})

router.post("/register", async (req, res, next) => {
	try {
		const { username } = req.body
		const user = await Users.findBy({ username }).first()

		if (user) {
			return res.status(409).json({
				message: "Username is already taken",
			})
		}

		res.status(201).json(await Users.add(req.body))
	} catch(err) {
		next(err)
	}
})

router.post("/login", async (req, res, next) => {
	const authError = {
		message: "Invalid Credentials",
	}

	try {
		const user = await Users.findBy({ username: req.body.username }).first()
		if (!user) {
			return res.status(401).json(authError)
		}

		// since bcrypt hashes generate different results due to the salting,
		// we rely on the magic internals to compare hashes rather than doing it
		// manually with "!=="
		const passwordValid = await bcrypt.compare(req.body.password, user.password)
		if (!passwordValid) {
			return res.status(401).json(authError)
		}

		// creates a new session for the user and saves it in memory.
		// it's this easy since we're using `express-session`
		// req.session.user = user

		const tokenPayload = {
			userId: user.id,
			userRole: "normal",
		}

		const token = jwt.sign(tokenPayload, "secret key")

		res.cookie("token", token)
		res.json({
			message: `Welcome ${user.username}!`,
			token: token,
		})
	} catch(err) {
		next(err)
	}
})

module.exports = router