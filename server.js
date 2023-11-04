const fs = require("fs");
const path = require("path");
const https = require("https");
const helmet = require("helmet");
const express = require("express");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");
const { verify } = require("crypto");

require("dotenv").config();

const PORT = 3000;

//isi key dan idnya ada di .env
const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

//verifikasi akun
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google profile", profile);
  done(null, profile); //langsung return profile karena yang verifikasi akun adalah google
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

//serialize user = mengirim data user ke jaringan
//save the session to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//menyimpan data user agar dapat digunakan kembali
//read the session from the cookie
passport.deserializeUser((id, done) => {
  // user.findById(id).then((user) => {
  //   done(null, user);
  // });
  done(null, id);
});

const app = express();

app.use(helmet());

app.use(
  cookieSession({
    name: "session",
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);

app.use(passport.initialize());
app.use(passport.session()); //konfirmasi bahwa session sudah mulai

//middleware function untuk mengecek login
function checkLoggedIn(req, res, next) {
  console.log("Current user is:", req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: "You must log in!",
    });
  }
  next();
}

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back!");
  }
);

app.get("/auth/logout", (req, res, next) => {
  //Removes req.user and clears any logged in session
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/"); //redirect user to homepage
  });
});

//checkLoggedIn adalah memanggil function middleware diatas untuk memastikan user udah login
app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your personal number are 11");
});

app.get("/failure", (req, res) => {
  return res.send("Failed to log in!");
});

//menyatukan file sehingga bisa konek
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

//command : openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
  });
