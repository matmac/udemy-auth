const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUsers(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  res.send({ token: tokenForUsers(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide email and password' });
  }

  // See if a user with a given email exists
  User.findOne({ email: email }, function(err, existingUser) {
    if (err) { return next(err); }

    if (existingUser) {
      return res.status(422).send({ error: 'Email already used.' })
    }

    const user = new User({
      email: email,
      password: password
    });
    user.save(function() {
      if (err) { return next(err); }
      res.json({ token: tokenForUsers(user) });
    });
  });
}
