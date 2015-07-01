var request    = require('request');
var auth       = require('../libs/auth');
var express    = require('express');
var router     = express.Router();
var verifyUser = require('../libs/verifyUser');
var redis		= require('../util/redisConnection');


// GET route to get the register site
router.get('/', function(req, res)
{
  res.render('register');
});

// POST route to register
module.exports = function(cmd_args) {

  return function (req, res, next) {

    if ( !req.body.username || !req.body.password ) {
      res.render('login', { error: 'Missing username and/or password', register: true });
      //res.render('error', {error : 'Missing username and/or password'});
      //res.send('respond with a resource');
      return;
    }


    if ( req.body.password.length < 8 || req.body.password.length > 80 ) {
      res.render('login', { error: 'The password length must be between 6 and 80 characters.' });
      return;
    }

    if ( !validateEmail(req.body.email) ) {
      res.render('login', { error: 'The email you entered must be a valid email adress.' });
      return;
    }

    auth.createUser(req.body.username, req.body.password, function (err, body) {
      if ( err ) {
        res.render('login', { error: 'An account with that username already exists.', register: true });
        //res.redirect(400,'/');
        return;
      }

      var rootDomain = req.protocol + '://'+ req.get('Host');

      verifyUser.generateVerificationSet(req.body.username, req.body.email)
         .then(function (verificationSet) {
           // first param is the rootDomain for the verification request
           // (e.g. rootDomain + '/verify/'' + token +'/'+ username)
           // second params comes from generateVerificationSet via resolve(verificationSet)
           verifyUser.sendVerificationMail(rootDomain, verificationSet)
              .then(function (data) {
                console.log(data);
                res.render('login', {
                  error   : 'You got an verification mail. Please confirm your email by using the link provided in this verification mail.',
                  register: true
                });
              })
              .catch(function (err) // some error happens during the send verification mail
              {
                res.render('error', { error: err });
              });
         })
         .catch(function (err) {		// some error happens during the verification generation
           res.render('error', { error: err });
         });

      /*auth.createSession(req.body.username, req.body.password, function (err, body) {
        if ( err ) {
          console.error(err);
          res.redirect(400, '/');
          return;
        }
        res.cookie('session', body.session, {
          maxAge  : 1800000, // 30min
          httpOnly: true,
          path    : '/user',
          signed  : true
        });
        res.redirect('/user');
      });*/
    });

    function validateEmail(email) {
      // another email regex
      // [a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?

      // email regex
      var re = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i;
      return re.test(email);
    }
  };
};

