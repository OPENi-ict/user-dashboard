var request = require('request');
var express = require('express');
var util    = require('util');

var verifyUser = require('../libs/verifyUser');
var redis      = require('../util/redisConnection');

var router = express.Router();

// GET route to get a user activated with the system
router.get('/:token/:username', function (req, res) {
   var verificationSet;

   redis.get(req.params.username, function (err, result) {
      if ( err ) util.log(err);
      verificationSet = JSON.parse(result);

      var username           = verificationSet.user,				// user from db
          usermail           = verificationSet.mail,				// user mail from db
          token              = req.params.token,				// verification code
          dbVerificationHash = verificationSet.token, 			// verification code from db
          actualTime         = new Date().getTime(),			// timestamp of verification request
          dbTimestamp        = verificationSet.timestamp;		// timestamp from db

      if ( token !== dbVerificationHash ) { // ERROR: wrong hash
         res.render('verify', { error: 'No verification prozess found.', user: username });
         return;
      }

      if ( (actualTime - dbTimestamp) > 1800000 /* 30min */ ) { // ERROR: verification code expired

         // gather data for the verification process
         var rootDomain = req.protocol + '://' + req.get('Host');

         // delete expired verification credentials from redis DB
         verifyUser.deleteExpiredVerificationCredentials(token)
            .then(function (data) {
               util.log(data);
            })
            .catch(function (err) {
               util.log(err);
               // some error happens during the deletion of old verification credentials
               res.render('error', { error: error });
            });

         /*
          *	create a new verification mail, because the old one is expired but was correct.
          */
         verifyUser.generateVerificationSet(username, usermail)
            .then(function (verificationSet) {
               // first param is the rootDomain for the verification request
               // (e.g. rootDomain + '/verify/'' + token +'/'+ username)
               // second params comes from generateVerificationSet via resolve(verificationSet)
               verifyUser.sendVerificationMail(rootDomain, verificationSet)
                  .then(function (data) {
                     util.log(data);
                     res.render('verify',
                        {
                           error  : 'Your verification code is expired.',
                           user   : username,
                           newLink: 'You\'ve got a new verification mail, please verify your mail adress in the next 30 min.'
                        })
                  })
                  .catch(function (err) {	// some error happens during the send verification mail
                     res.render('error', { error: err });
                  });
            })
            .catch(function (err) {	// some error happens during the verification generation
               res.render('error', { error: err });
            });
         return;
      }

      verificationSet.activated = true;
      redis.set(req.params.username, JSON.stringify(verificationSet));
      res.render('verify', { user: username });

   });

});

module.exports = router;

