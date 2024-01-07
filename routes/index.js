require('dotenv').config()
const express = require('express');
const bcrypt = require("bcrypt")
const passport = require("passport")
const { body, validationResult } = require('express-validator');
const router = express.Router();
const mongoose = require("mongoose")

const jwt = require('jsonwebtoken')

const JwtStrategy = require('passport-jwt').Strategy, ExtractJwt = require('passport-jwt').ExtractJwt;
let opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.SECRET;
passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
  try {
    console.log(jwt_payload.email)
    Users.findOne({email: jwt_payload.email})
    .then((user) => {
      if (user) {
          return done(null, user);
      } else {
          return done(null, false);
      }
    });
  }
  catch(err) {
    return done(err, false);
  }
}));

mongoose.connect("mongodb://127.0.0.1:27017/testdb")
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'))

const userSchema = mongoose.Schema({
  email: String,
  password: String
})

const todoSchema = mongoose.Schema({
  user: String,
  items: Array
})

const Users = mongoose.model("Users", userSchema)
const Todos = mongoose.model("Todos", todoSchema)

const isAuthenticated = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  let authToken = null
  
  if (authHeader) {
    authToken = authHeader.split(" ")[1]
    jwt.verify(authToken, process.env.SECRET, (err, user) => {
      req.user = user
      console.log("req.user added")
    })
  }
  
  next()
}

router.get("/", (req, res) => {
  console.log(req.user)
  res.render("index", {user: req.user})
})

router.get('/register.html', (req, res) => {
  res.render("register")
});

router.get('/login.html', (req, res) => {
  res.render("login")
});

router.post(
  "/api/user/register",
  body("email").isEmail(),
  body('password').custom( value => {
    if (value.length < 8) {
      throw new Error("too short");
    }
    else if (!/[a-z]/.test(value)) {
      throw new Error("lowercase letter missing")
    }
    else if (!/[A-Z]/.test(value)) {
      throw new Error("uppercase letter missing")
    }
    else if (!/[0-9]/.test(value)) {
      throw new Error("number missing")
    }
    else if (!/[~`!#$%\^&*+=\-\[\]\\';,/{}|\\":<>\?]/.test(value)) {
      throw new Error("special character missing")
    }
    return true
  }),
  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).send(errors.errors[0].msg)
    }

    try {
      const existingUsers = await Users.find()
      const found = existingUsers.find((user) => user.email == req.body.email);

      if (found) {
        return res.status(403).send("Email already in use.")
      }

      const hashedPassword = await bcrypt.hash(req.body.password, 10)
      newUser = {
          id: Date.now().toString(),
          email: req.body.email,
          password: hashedPassword
      }
      await Users.create(newUser)
      res.redirect("/login.html")
    } catch {
        res.send("shit's fucked")
    }
})

router.post("/api/user/login", async (req, res) => {
  try {
    const existingUsers = await Users.find()
    const found = existingUsers.find((user) => user.email == req.body.email);

    if (!found) {
      return res.send(JSON.stringify({"success": false, "token": "no user"}))
    } else if (await bcrypt.compare(req.body.password, found.password) == false) {
      return res.send(JSON.stringify({"success": false, "token": "wrong password"}))
    }

    const token = jwt.sign({email: req.body.email}, process.env.SECRET)
    res.send(JSON.stringify({
      "success": true,
      "token": token
    }))

  } catch {
    res.send(JSON.stringify({
      "success": false,
      "token": "shit's fucked"
    }))
  }
})

router.get("/api/private", passport.authenticate('jwt', {session: false}), (req, res) => {
  res.send({
    email:req.user.email
  })
})

router.post("/api/todos", passport.authenticate('jwt', {session: false}), async (req, res) => {
  const newTodos = req.body.items
  const id = req.user._id
  let todos = await Todos.findOne({user: id})

  if (todos && todos.length != 0) {
    await Todos.updateOne({user:id}, {$push: {items: {$each: newTodos}}})
  } else {
    await Todos.create({
      user: id,
      items: newTodos
    })
  }
  todos = await Todos.findOne({user:id})
  console.log(todos)
  return res.send(todos)
})

module.exports = router;
