var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));



// passport.js に対するsession設定 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// OIDCのStrategyではstate管理（OIDCのハッキング対策の仕様）その他のため、
// セッションの利用が必要。これをしないと、
// 「OpenID Connect authentication requires session support when using state. 
//   Did you forget to use express-session middleware?'」
// のエラーが出る。
// ※passport-openidconnect\lib\state\session.js
// 　の以下でチェックされている。
//  > SessionStore.prototype.store = function(req, meta, callback) {
//  > if (!req.session) { return callback(new Error('OpenID Connect authentication requires session support when using state. Did you forget to use express-session middleware?')); }
// 
// なお、「passport = require("passport");」はシングルトンとして同一の
// インスタンスが返却される。
// ※「passport\lib\index.js】の以下で
//   > exports = module.exports = new Passport();
//   > 
//   と1回のみインスタンスを生成して、それが返却されてくる。
//   従って、他ファイルで「passport = require("passport");」としたときに、
//   取得されるインスタンスは同一。
// 
var session = require("express-session");
app.use(
  session({
    // クッキー改ざん検証用ID
    secret: process.env.COOKIE_ID,
    // クライアント側でクッキー値を見れない、書きかえれないようにするか否か
    httpOnly: true,
    // セッションの有効期限
    maxAge: 30*1000,
    // その他のオプションは以下を参照
    // https://github.com/expressjs/session#sessionoptions
    resave: false,
    saveUninitialized: false
  })
);
var passport = require("passport");
app.use(passport.initialize());
app.use(passport.session());

// ミドルウェアである passport.authenticate() が正常処理したときに done(errorObject, userObject)で
// 通知された情報を、セッションに保存して、任意のcallback中でセッションから取り出せるようにする。
// 「何をセッションに保存すべきか？」を選択的に行うためのフックcallback関数。
//
// なお、「正常終了したときに呼ばれる」と言う公式の記載にはたどり着けず。。。
// 一応以下の非公式QAで
// > Passport uses serializeUser function to persist user data 
// > (after successful authentication) into session. 
// との記載はある。
// https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize
// 
passport.serializeUser(function (user, done) {
  console.log("+++[serializeUser called with the following parameter]+++");
  console.log(JSON.stringify(user));
  console.log("---[serializeUser]---------------------------------------\n");

  // 本サンプルでは、それぞれのauth_login_xxx.jsでのdone()にて
  // title, keyNam, profileフィールドを持つオブジェクトを渡している。
  // なので、それを取り出して、セッションに格納しておくこととする。
  // 
  // なお、本来は「セッションにはuserIdのみを格納して、他の情報は
  // サーバー側のDBに保管する。その上で、deserializeUser()にて
  // 保管したDBから取り出して提供する」実装が望ましい。
  // が、本サンプルはあくまで「試行」なので、セッションにそのまま格納しておく。
  // （※この場合であっても、ブラウザ側のcookieに保持されるのはセッションIDのみであって、
  //     セッションの中身そのものではないことに留意）
  var sessionPassportUserObject = {};
  sessionPassportUserObject.title = user.title;
  sessionPassportUserObject.type = user.typeName;
  sessionPassportUserObject.profile = user.profile;
  

  done(null, sessionPassportUserObject);
});
// 上記と対となる、取り出し処理。
passport.deserializeUser(function (obj, done) {
  // 本来は、上述のように「objに格納されたuserIdをキーとして、別途保管してある
  // 情報をDBから取得して渡す」のが望ましいが、本サンプルでは簡易化のため、
  // セッション「obj」に必要な情報をすべて保管してあるので、
  // 「obj」をそのまま渡すことが「取り出し」となる。
  done(null, obj);
});
//*/
// --- ここまで ----------------------------------------------------------



app.use('/auth-gcp',   require('./routes/auth_login_gcp'));   // 追記 for Google
app.use('/auth-azure', require('./routes/auth_login_azure')); // 追記 for Azure
app.use('/auth-yahoo', require('./routes/auth_login_yahoo')); // 追記 for Yahoo



app.use('/', indexRouter);
app.use('/users', usersRouter);

module.exports = app;
