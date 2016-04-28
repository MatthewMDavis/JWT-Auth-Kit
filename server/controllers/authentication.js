const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function (req, res, next) {
  const email = req.body.email;
  const pwd = req.body.password;

  if (!email || !pwd) {
    return res.status(422).send({ error: 'Both email and pwd required' });
  }

  // see if given user exists
  User.findOne({ email: email }, function(err, existingUser) {
    if (err) { return next(err) };
    // if user with that email exists, return err msg
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use'});
    }
  });

  // if email not already in DB, create/save user record
  const user = new User({
    email: email,
    password: pwd
  });

  user.save(function(err) {
    if (err) { return next(err) };
    // send response indicating successful creation
    res.json({ token: tokenForUser(user) });
  });

}
