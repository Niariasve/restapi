var jwt = require('jsonwebtoken');

var jwtVerification = (req, res, next) => {
    const token = req.params.token;
    const secret = "hola"

    try {
        const decoded = jwt.verify(token, secret)
        return next();
    } catch (error) {
        res.status(401).send('Invalid Token')
    }
}

module.exports = jwtVerification;