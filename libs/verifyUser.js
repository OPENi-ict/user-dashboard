'use strict'

var when 			= require('when'),
    uuid 			= require('node-uuid'),
    nodemailer 	= require('nodemailer'),
    redis			= require('../util/redisConnection');

// ---------------------------------------------------------------------------
/*
 *	-= SMTP connection Pooling example =-
 * If you need to send a large amout of e-mails via smtp.
 * This smtp pooling would be a good solution.
 */
/*
 var smtpPool 	= require('nodemailer-smtp-pool');

 // create reusable transporter object using SMTP transport.
 // NB! No need to recreate the transporter object. You can use
 // the same transporter object for all e-mails
 var transporter = nodemailer.createTransport(smtpPool({
 host: 'localhost',
 port: 25,
 auth: {
 user: 'username',
 pass: 'password'
 },
 // use up to 5 parallel connections
 maxConnections: 5,
 // do not send more than 10 messages per connection
 maxMessages: 10,
 // no not send more than 5 messages in a second
 rateLimit: 5
 }));
 */

// ---------------------------------------------------------------------------
/*
 *					-= sendmail tranport for nodemailer =-
 *	If you want to send the verification mails via the sendmail command. 
 *	Example givin below.
 */
/*
 var sendmailTransport 	= require('nodemailer-sendmail-transport');

 // create reusable transporter object using SMTP transport.
 // NB! No need to recreate the transporter object. You can use
 // the same transporter object for all e-mails
 var transporter = nodemailer.createTransport(sendmailTransport({
 path: '/usr/share/sendmail',
 args: [
 "-f",
 "verify@peat-platform.org"
 ]
 }));
 */


// ---------------------------------------------------------------------------

// googlemail account just to testing the verification mail
var senderMail = 'verify.test.openi@gmail.com';

// create reusable transporter object using SMTP transport. 
// NB! No need to recreate the transporter object. You can use 
// the same transporter object for all e-mails
var transporter = nodemailer.createTransport({
   service: 'Gmail',
   auth: {
      user: senderMail,
      pass: '0p3n1Pe4t'
   }
});


/*
 *	create unique hash and timestamp for activation email. Sign user with "activated = false".
 */
var generateVerificationSet = function( username, usermail )
{
   return when.promise(function(resolve, reject) {
      var verificationToken = uuid.v4(); 		//Simple generation of RFC4122 UUIDS, v4 = (random) id, v1 = (timebased) id
      var verificationSet =
          {
             activated : false,						// activation flag
             user : username,						// username of user
             mail : usermail,							// user mail adress
             timestamp : new Date().getTime(),		// actual time in milis
             token :  verificationToken				// unique verification token
          };
      redis.set(username, JSON.stringify(verificationSet) );
      redis.get(username, function (err, result) {
         if(!err) {
            resolve( verificationSet );
         } else reject( err );
      });
   });
};

/*
 * build up and send mail to registered user email with unique activation url.
 */
var sendVerificationMail = function( rootDomain, verificationSet )
{
   return when.promise(function(resolve, reject) {
      // unique verification url for mail verification / account activation
      var userVerificationURL = rootDomain + '/verify/'+verificationSet.token+'/'+verificationSet.user;

      // An example users object with formatted email function
      var verifyUser = {
         email: verificationSet.mail,
         subject: '✔ Please verify your email - PEAT platform',
         html: 	'<b>Hello '+verificationSet.user+' ✔</b>,'+
         '</br>'+
         '<p>Please verify your E-mail by clicking the verification link below.</p>'+
         '<a href="'+userVerificationURL+'">'+userVerificationURL+'</a>' // html body,
      };

      transporter.sendMail({
         from: 'Peat-platform Verification<'+senderMail+'>',		// sender address
         to: verifyUser.email,										// receiver mail
         subject: verifyUser.subject,									// mail subject
         html: verifyUser.html										// html body
      }, function(err, info) {
         if (err) {
            reject(err);
         } else {
            resolve('Mail sent: ' + info.response);
         }
      });
   });
}

var deleteExpiredVerificationCredentials = function( username )
{
   return when.promise(function(resolve, reject) {
      redis.del( username, function(err, result){
         if(err) reject(err);
         resolve('Old verification creddentials deleted: '+ result);

      });
   });
}

module.exports.deleteExpiredVerificationCredentials = deleteExpiredVerificationCredentials;
module.exports.generateVerificationSet = generateVerificationSet;
module.exports.sendVerificationMail = sendVerificationMail;