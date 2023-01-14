const router = require('express').Router()
const bcrypt = require('bcryptjs')
const { mongo, default: mongoose } = require('mongoose')
const User = require('../models/User.model')
const saltRounds = 10
const {isLoggedIn,isLoggedOut} = require("../middleware/route-guard")

router.get('/signup',(req,res)=>{
    res.render('auth/signup')
})


router.get('/login',(req,res)=>{
    res.render('auth/login')
})

router.post('/signup',(req,res)=>{
    console.log(req.body)
   
    const {email, password} = req.body
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

    if(!email || !password){
        //actually, the user side control gives better visual for mandatory fields
        res.render("auth/signup", {errorMessage: "Please provide email and password"})
        return;
    }else if(!regex.test(password)){
        res.render("auth/signup", {email, password:"", errorMessage: "The password has to have minimum 6 characters with at least one lower case and one upper case letter"})
        return;
    }

    bcrypt
    .genSalt(saltRounds)
    .then((salt)=>{
        console.log("Salt: ",salt)
        //hash() is the method that hashes/encrypts our password
        //takes two arguements: 1. is the password 2. is the salt
       return bcrypt.hash(password,salt)
    })
    .then(hashedPassword=>{
        console.log("Hashed Password: ", hashedPassword)
        return User.create({
            email:email,
            passwordHash:hashedPassword
        })})
    .then(()=> res.redirect('/profile'))
    .catch(error=>{
        if(error instanceof mongoose.Error.ValidationError){
            res.status(500).render('auth/signup',{errorMessage: error.message})
        }else if(error.code = 11000){
            res.render("auth/signup", {errorMessage: "There is already an account associated with this email, Log in instead"})
        }else{
            next(error)
        }
        console.log(error)
    })
})

router.post('/login', (req, res)=>{
    const {email, password} = req.body

    if(!email|| !password){
        res.render("auth/login", {email,password, errorMessage:"Please enter correct account information"})
        return
    }
    // even findOne return an array not one single result. 
    // findById returns the exact document found. so no need to convert to object
    // while being passed to res.render
    User.findOne({email})
    .then(user => {
        if(!user){
            res.render("auth/login", {email,password, errorMessage:"User not found, create a new account on our signup page"})
            return
        }else if(bcrypt.compareSync(password, user.passwordHash)){
            req.session.currentUser = user
            res.redirect("userProfile")
            return 
        }else{
            res.render("auth/login", {email,password, errorMessage:"Incorrect password"})
            return 
        }})
    .catch(error => next(error))
})


router.get('/userProfile',isLoggedIn, (req,res)=>{
    res.render('user/user-profile', {userInSession:req.session.currentUser})
})


router.post("/logout", (req,res)=>{
    req.session.destroy(err =>{
        if(err) next(err)
        res.redirect("login")
    })
})



module.exports = router
