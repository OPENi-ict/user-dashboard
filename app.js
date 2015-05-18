var express      = require('express');
var path         = require('path');
var favicon      = require('serve-favicon');
var logger       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var engines      = require('consolidate');

var config = {
   trusted_public_key: '-----BEGIN PUBLIC KEY-----\n'+
   'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKT8kGk6ZNo3sC4IIo29leRLVD23T2r0\n'+
   'vWXBEkk2pV42HsxKAmPs789AGHH9XwbGpD7FvrcBWWgb65v32Hg/NGkCAwEAAQ==\n'+
   '-----END PUBLIC KEY-----'
}

/*****************************
*       IMPLEMENT ROUTES     *
*****************************/
// Overview Dashboard
var index = require('./routes/index');

// Simple_Auth
var addSubscription = require('./routes/addSubscription');
var apps            = require('./routes/apps');
var charts          = require('./routes/charts');
var data            = require('./routes/data');
var apps            = require('./routes/apps');
var login           = require('./routes/login');
var logout          = require('./routes/logout');
var register        = require('./routes/register');
var subscriptions   = require('./routes/subscriptions');




/*****************************
*        INITIALIZE APP      *
*****************************/
var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
//app.engine('jade', require('jade').__express);
//app.engine('html', require('ejs').renderFile);
//
//app.engine('haml', engines.haml);
//app.engine('html', engines.hogan);
app.set('view engine', 'jade');
//app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser('4e3d00e7-7fc4-480f-b785-bafebbdcb74f'));

/*app.use(session({
  secret: '4e3d00e7-7fc4-480f-b785-bafebbdcb74f',
  //resave: false,
  //saveUninitialized: true,
  //rolling: true,
  //unset: 'destroy',
  cookie: { secure: true, maxAge: 3600000, foo: '' }
}))*/


app.use(express.static(path.join(__dirname, 'public')));
//app.use(express.static(path.join(__dirname, 'bower_components')));
app.use('/bower_components', express.static(path.join(__dirname, 'bower_components')));

// Authentification check
app.use('/user', function(req, res, next){
  if(req.signedCookies.session || req.path === '/login' || req.path === '/register') {
    next();
  } else {
    res.redirect('/user/login');
  }
});

app.use('/', login);

app.use('/user/addSubscription',    addSubscription);
app.use('/user/charts',             charts);
app.use('/user/data',               data);
app.use('/user/apps',               apps);
app.use('/user',                    index(config));
app.use('/user/dashboard',          index(config));
app.use('/login',                   login);
app.use('/user/login',              login);
app.use('/user/logout',             logout);
app.use('/user/register',           register);
app.use('/user/subscriptions',      subscriptions);


// catch 404 and forward to error handler
app.use(function(req, res, next) {
   console.log(req);
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


module.exports = app;
