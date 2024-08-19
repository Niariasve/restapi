var jwt = require('jsonwebtoken');

var jwtVerification = (req, res, next) => {
    const token = req.headers.token;
    console.log(token);
    const secret = process.env.TOKEN_SECRET

    try {
        const decoded = jwt.verify(token, secret)
        return next();
    } catch (error) {
        console.log(error)
        res.status(401).send('Invalid Token')
    }
}

module.exports = jwtVerification;