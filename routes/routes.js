/**
 * Created by dconway on 09/06/15.
 */

var wrap = function(args){


   var express = require('express');
   var router  = express();

   var index = require('./index')(args);

   // Simple_Auth
   var addSubscription  = require('./addSubscription')(args);
   var apps             = require('./apps')(args);
   var permissions      = require('./permissions')(args);
   var permsupdate      = require('./permsupdate')(args);
   var charts           = require('./charts')(args);
   var ajax             = require('./ajax')(args);
   var data             = require('./data')(args);
   var login            = require('./login')(args);
   var logout           = require('./logout')(args);
   var register         = require('./register')(args);
   var subscriptions    = require('./subscriptions')(args);
   var verifyUser       = require('./verifyUser');


   router.use('/',                  index           );
   router.use('/addSubscription',   addSubscription );
   router.use('/charts',            charts          );
   router.use('/ajax',              ajax            );
   router.use('/data',              data            );
   router.use('/apps',              apps            );
   router.use('/permissions',       permissions     );
   router.use('/permsupdate',       permsupdate     );
   router.use('/dashboard',         index           );
   router.use('/login',             login           );
   router.use('/login',             login           );
   router.use('/logout',            logout          );
   router.use('/register',          register        );
   router.use('/subscriptions',     subscriptions   );
   router.use('/verify',            verifyUser      );

   return router
};


module.exports = wrap;
