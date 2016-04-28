const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local Strategy
const localOpts = {usernameField: 'email'};
const localLogin = new LocalStrategy(localOpts, function(email, password, done) {
  User.findOne({ email: email }, function(err, user) {
    if (err) { return done(err); }
    if (!user) {return done(null, false); }

    // compare the passwords
    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err); }
      if(!isMatch) { return done(null, false); }

      return done(null, user);
    })
  });
});


// Create JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); }

    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});


// Tell passport to use the strategy
passport.use(jwtLogin);
passport.use(localLogin);
