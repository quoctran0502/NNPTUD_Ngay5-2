let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

const publicKey = fs.readFileSync(path.join(__dirname, '../keys/jwtRS256.key.pub'), 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith("Bearer")) {
                console.log("No token or standard Bearer missing:", token);
                res.status(403).send({ message: "ban chua dang nhap" })
                return;
            }
            token = token.split(' ')[1]
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            
            console.log("Token verified successfully:", result);
            
            if (result.exp * 1000 < Date.now()) {
                console.log("Token expired");
                res.status(403).send({ message: "ban chua dang nhap" })
                return;
            }
            let getUser = await userController.GetUserById(result.id);
            if (!getUser) {
                console.log("User not found by id:", result.id);
                res.status(403).send({ message: "ban chua dang nhap" })
            } else {
                req.user = getUser;
                next();
            }
        } catch (error) {
            console.log("JWT Verification Error:", error.message);
            res.status(403).send({ message: "ban chua dang nhap" })
        }

    }
}