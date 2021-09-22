// const http = require('http');
const fs = require('fs');
const https = require('https');
const path = require('path');
const cors = require('cors');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
require('dotenv').config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, cb) {
  // console.log('GoogleProfile', profile);
  cb(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to the cookie
passport.serializeUser((user, done) => {
  console.log('serialize');
  done(null, user.id);
});

// Read the session from the cookie
passport.deserializeUser((id, done) => {
  console.log('deserialize', id);
  done(null, id);
});

const app = express();

app.use(helmet());
app.use(cors());
app.use(
  cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);
// middleware to setup password session
app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
  console.log(`Current user is :`, req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  // TODO:
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You must log in!',
    });
  }
  next();
}

const passportGoogleLogin = passport.authenticate('google', {
  scope: ['email', 'profile'],
});

app.get('/auth/google', passportGoogleLogin, (req, res) => {});

const passportGoogleCallback = passport.authenticate('google', {
  failureRedirect: '/failure',
  successRedirect: '/',
  session: true,
});

app.get('/auth/google/callback', passportGoogleCallback, (req, res) => {
  console.log('Google called us back');
});

app.get('/failure', (req, res) => {
  return res.send('Failed to log in');
});

app.get('/auth/logout', (req, res) => {
  req.logout(); // Remove req.user and clears any logged in session
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('Your personal secret value is 42!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https
  .createServer(
    {
      cert: fs.readFileSync('cert.pem'),
      key: fs.readFileSync('key.pem'),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on PORT ${PORT}...`);
  });

// app.listen(PORT, () => {
//   console.log(`Listening on PORT ${PORT}...`);
// });
