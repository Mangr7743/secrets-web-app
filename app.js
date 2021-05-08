
// Require packages
//require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const { stringify } = require('qs');

// Setup express app
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

// Setup and initialize sessions
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));


// initialize passport.js
app.use(passport.initialize());
app.use(passport.session());

// Connect to db
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false});

mongoose.set("useCreateIndex", true);

//setup mongoose schema
const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// setup passport plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// setup user model
const User = mongoose.model("User", userSchema);

/// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

// google oauth passport strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://mangr7743secrets.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// setup home route
app.get("/", (req, res) => {
    res.render("home");
});

// setup login route
app.get("/login", (req, res) => {
    res.render("login");
});

//setup route for auth google
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

// setup register route
app.get("/register", (req, res) => {
    res.render("register");
});

// setup secrets route 
app.get("/secrets", (req, res) => {
    
    // Print all secrets
    User.find({"secret": {$ne: null}}, (err, foundUsers) => {
        if (err) {
            console.log(err);
        } else {
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    });

});

// setup logout route
app.get("/logout", (req, res) => {
    // deauthenticate
    req.logout();
    res.redirect("/");
});

app.get("/submit", (req, res) => {
    // Check for user authentication
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;

    console.log(req.user.secret);

    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save();
                res.redirect("/secrets");
            }
        }
    })

});

// Post route for register
app.post("/register", (req, res) => {

    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    })

});


// post route for login
app.post("/login", (req, res) => {

    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });

    // passport login function
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    })

});


// Listen on port
app.listen(3000, () => {
    console.log("Server started on port 3000");
});