const jwt = require("jsonwebtoken")

const roles = ["basic", "admin"]

function restrict(role) {
	return async (req, res, next) => {
		try {
			// get the token from a manual header and make sure it's not empty
			const token = req.cookies.token

			if (!token) {
				return res.status(401).json({
					message: "Invalid credentials",
				})
			}

			// make sure the signature on the token is valid and still matches the payload
			// (we need to use the same secret string that was used to sign the token)
			jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
				if (err) {
					return res.status(401).json({
						message: "Invalid credentials",
					})
				}

				// use an index-based scale for checking permissions rather than a hard equality check, since admins should still be able to access regular routes
				if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
					return res.status(401).json({
						message: "Invalid credentials",
					})
				}

				// make the token's decoded payload available to other middleware functions or route handlers, in case we want to use it for something
				req.token = decoded

				// at this point, we know the token is valid and the user is authorized
				next()
			})
		} catch(err) {
			next(err)
		}
	}
}

module.exports = {
	restrict,
}