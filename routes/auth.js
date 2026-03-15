var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, validatedResult } = require('../utils/validator')
let {CheckLogin} = require('../utils/authHandler')
//login
router.post('/login',async function (req, res, next) {
    let { username, password } = req.body;
    let result = await userController.QueryLogin(username,password);
    if(!result){
        res.status(404).send("thong tin dang nhap khong dung")
    }else{
        res.send(result)
    }
    
})
router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
        username, password, email, '69b6231b3de61addb401ea26'
    )
    res.send(newUser)
})
router.get('/me',CheckLogin,function(req,res,next){
    res.send(req.user)
})

router.post('/changepassword', CheckLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    let { oldpassword, newpassword } = req.body;
    
    let userId = req.user[0]._id; // Get the user ID from req.user (which is an array based on GetUserById implementation)

    let result = await userController.ChangePassword(userId, oldpassword, newpassword);
    
    if (result.success) {
        res.send({ message: result.message });
    } else {
        res.status(400).send({ message: result.message });
    }
})

//register
//changepassword
//me
//forgotpassword
//permission
module.exports = router;