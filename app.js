require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");



const app = express();
const PORT = process.env.PORT || 3000;

//console.log(process.env.API);

app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(bodyParser.urlencoded({
    extended:true
}));


app.use(session({
    secret: "Our littile Secret",
    resave: false,
    saveUninitialized: true
}));


app.use(passport.initialize());
app.use(passport.session());

// connection with mongodb

async function main(){
    await mongoose.connect(process.env.MONGO_URI);
}

main().catch(function(err){
    console.log(err);
});


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});
 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


passport.serializeUser(function(user, done) {
    done(null,user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id).then(function(user, err){
        done(err,user);
    });
});
  


/// callbackURL: "http://localhost:3000/auth/google/secrets",   ///for testing

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-404.cyclic.app/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    scope: ['profile', 'email'],
  },
  function(accessToken, refreshToken, profile, cb) {

    //console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


///////////////////////////// Home route ///////////////////////

app.route("/")

.get(function(req,res){
    res.render("home");
});


///////////////////////////// Login route ///////////////////////

app.route("/login")

.get(function(req,res){
    res.render("login");
})

.post(function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        } else {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });     
        }
    });
});


///////////////////////////// Register route ///////////////////////

app.route("/register")

.get(function(req,res){
    res.render("register");
})

.post(function(req,res){

    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if(err){ 
            console.log(err);
            res.redirect("/register");
        } else {
      
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        
        }
    });

});



///////////////////////////// Secrets route ///////////////////////

app.route("/secrets")

.get(function(req,res){
    User.find({"secret": {$ne: null}}).then(function(foundUsers,err){
        if(err){
            console.log(err);
        } else {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});


///////////////////////////// Submit route ///////////////////////

app.route("/submit")

.get(function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

.post(function(req,res){
    const submittedSecret = req.body.secret;

    console.log(submittedSecret);

    User.findById(req.user.id).then(function(foundUser,err){
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save().then(function(){
                res.redirect("/secrets");
            });
        } else {
            console.log(err);
        }
    });
});

///////////////////////////// Logout route ///////////////////////

app.get("/logout", function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        } else{
            res.redirect("/");
        }
    });
    
});


///////////////////////////// Google authentication route ///////////////////////

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);


app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});


app.listen(PORT, function(){
    console.log(`Server running on port ${PORT}`);
});