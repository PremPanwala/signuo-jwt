const router = require('express').Router()
const signup = require('../Controller/auth.controller')
const {validateUser} = require('../middleware/validation');
const {loginValidation} = require('../middleware/loginvalidation');
const {forgotpassword}=require('../controller/auth.controller')
const {resetpassword}=require('../controller/auth.controller')
const login = require('../controller/auth.controller')
router.post('/signup',validateUser,signup.signup)
router.post('/login',loginValidation,login.login)
router.put('/forgotpassword',forgotpassword)
router.put('/resetpassword',resetpassword)
module.exports = router