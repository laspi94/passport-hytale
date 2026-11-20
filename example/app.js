// Minimal Express application using passport-hytale.
//
//   HYTALE_CLIENT_ID      client ID issued by Hytale (required)
//   HYTALE_CLIENT_SECRET  client secret, for confidential clients
//   HYTALE_SCOPE          space-separated scopes (default: "hytale:profile")
//   SESSION_SECRET        secret used to sign the session cookie
//   PORT                  port to listen on (default: 3000)

var express = require('express');
var session = require('express-session');
var passport = require('passport');
var HytaleStrategy = require('passport-hytale');

var PORT = process.env.PORT || 3000;

if (!process.env.HYTALE_CLIENT_ID) {
  console.error('Set HYTALE_CLIENT_ID (and HYTALE_CLIENT_SECRET for a confidential client).');
  process.exit(1);
}

passport.use(new HytaleStrategy({
    clientID: process.env.HYTALE_CLIENT_ID,
    clientSecret: process.env.HYTALE_CLIENT_SECRET,
    callbackURL: 'http://localhost:' + PORT + '/oauth2/redirect/hytale',
    scope: process.env.HYTALE_SCOPE || 'hytale:profile'
  },
  function verify(accessToken, refreshToken, profile, cb) {
    // A real application would find or create a user record keyed on
    // `profile.id` here.
    return cb(null, { id: profile.id, displayName: profile.displayName, claims: profile._json });
  }
));

passport.serializeUser(function(user, cb) { cb(null, user); });
passport.deserializeUser(function(user, cb) { cb(null, user); });

var app = express();
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace this secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.authenticate('session'));

app.get('/', function(req, res) {
  if (!req.user) {
    return res.type('html').send('<a href="/login/hytale">Sign in with Hytale</a>');
  }
  res.type('html').send(
    '<p>Signed in as ' + escapeHTML(req.user.displayName || req.user.id) + '</p>' +
    '<pre>' + escapeHTML(JSON.stringify(req.user.claims, null, 2)) + '</pre>' +
    '<form method="post" action="/logout"><button>Sign out</button></form>'
  );
});

app.get('/login/hytale', passport.authenticate('hytale'));

app.get('/oauth2/redirect/hytale', passport.authenticate('hytale', {
  successRedirect: '/',
  failureRedirect: '/failure',
  failureMessage: true
}));

app.get('/failure', function(req, res) {
  var messages = req.session.messages || [];
  req.session.messages = [];
  res.status(401).type('html').send(
    '<p>Sign-in failed: ' + escapeHTML(messages.join(', ') || 'unknown error') + '</p><a href="/">Back</a>'
  );
});

app.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.listen(PORT, function() {
  console.log('Listening on http://localhost:' + PORT);
});

function escapeHTML(text) {
  return String(text).replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
