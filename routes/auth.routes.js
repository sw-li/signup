const router = require('express').Router()
const bcrypt = require('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10

router.get('/signup',(req,res)=>{
    res.render('auth/signup')
})

router.post('/signup',(req,res)=>{
    console.log(req.body)
   
    const {email, password} = req.body

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
        User.create({
            email:email,
            passwordHash:hashedPassword
        })
        res.redirect('/profile')
    })
    .catch(error=>{
        console.log(error)
    })

    
})

router.get('/profile',(req,res)=>{
    res.render('user/user-profile')
})

module.exports = router
