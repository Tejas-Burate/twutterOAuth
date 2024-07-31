const util = require('util');
const express = require('express');
const passport = require('passport');
const TwitterStrategy = require('@superfaceai/passport-twitter-oauth2');
const session = require('express-session');
require('dotenv').config();

// Define the OAuth2 scopes required
const SCOPES = [
  'tweet.read',
  'tweet.write',
  'users.read',
  'follows.read',
  'offline.access',
];

// Flag to exit the process on successful authentication
const EXIT_ON_SUCCESS = true;

// Serialize user to store in session
passport.serializeUser(function (user, done) {
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

// Function to handle successful authentication
function onAuthSuccess({ accessToken, refreshToken }) {
  if (process.stdout.isTTY) {
    console.error(`\nPaste this into "tokens.json" file:`);
  }
  console.log(JSON.stringify({ accessToken, refreshToken }));
  if (EXIT_ON_SUCCESS) {
    setTimeout(() => {
      process.exit();
    }, 1000);
  }
}

// Use the Twitter OAuth2 strategy within Passport
passport.use(
  new TwitterStrategy(
    {
      clientID: process.env.TWITTER_CLIENT_ID,
      clientSecret: process.env.TWITTER_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/twitter/callback`,
      clientType: 'private',
    },
    (accessToken, refreshToken, profile, done) => {
      // Log the authentication tokens and profile
      onAuthSuccess({ accessToken, refreshToken });
      return done(null, {
        displayName: profile.displayName,
      });
    }
  )
);

const app = express();

// Initialize Passport and use sessions for persistent login sessions
app.use(passport.initialize());
app.use(
  session({ secret: 'keyboard cat', resave: false, saveUninitialized: true })
);

// Redirect to Twitter login on the root route
app.get('/', function (req, res) {
  res.redirect('/auth/twitter');
});

// Route to start the authentication process with Twitter
app.get(
  '/auth/twitter',
  passport.authenticate('twitter', {
    scope: SCOPES,
  })
);

// Callback route that Twitter will redirect to after authentication
app.get(
  '/auth/twitter/callback',
  passport.authenticate('twitter', {
    failureRedirect: '/error?login',
    failureMessage: true,
  }),
  function (req, res) {
    res.end(
      '<h1>Authentication succeeded</h1>See the console for the initial access and refresh tokens.<br>You can close this page.'
    );
  }
);

// Error handling route
app.get('/error', (req, res, next) => {
  res.send(
    `<h1>Login error</h1>${req.session.messages?.join(
      '<br>'
    )}<br><a href='/'>Try again?</a>`
  );
});

// Error handler middleware
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.end(
    `<h1>Error</h1><pre>${util.format(err)}</pre><a href='/'>Try again?</a>`
  );
});

// Start the Express server
app.listen(3000, () => {
  console.error(`👉 Visit ${process.env.BASE_URL}`);
});
