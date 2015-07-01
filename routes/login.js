var request = require('request');
var jwt     = require('jsonwebtoken');
var auth    = require('../libs/auth');

var express = require('express');
var router  = express.Router();
var redis   = require('../util/redisConnection');

// GET route to get access to the login site


module.exports = function (cmd_args) {

   router.get('/', function (req, res) {
      res.render('login');
   });

   router.post('/', function (req, res) {
      if ( !req.body.username || !req.body.password ) {
         res.render('login', { 'error': 'Incorrect credentials, please try again.' });
         return;
      }

      // check if user is activated by email -> then login in
      //              else remind user to verify the email adress -> redirect to get verification mail
      redis.get(req.body.username, function (err, result) {
         if ( err ) res.render('error', { error: err });

         verificationSet = JSON.parse(result);

         // if the user is activated he is able to login
         // otherwise he should verify his mail first
         if ( verificationSet.activated === true ) {

            auth.createSession(req.body.username, req.body.password, function (err, body) {
               if ( err ) {
                  console.error(err);
                  res.render('login', { 'error': 'Login failure, please try again.' });
                  return;
               }
               res.cookie('session', body.session, {
                  maxAge  : 1800000/* 30min */,
                  httpOnly: true,
                  path    : '/user',
                  signed  : true
               });
               res.redirect(301, '/user');
            });
         }
         else
            {
               // do not login user because he has not activated his account via mail
               res.render('login', { 'error': 'Your email is not verified. Please verify your email first.' });
               return;
            }


      });
   });

   return router
};
