var express = require('express');
var router = express.Router();
var path = require('path');
var createError = require('http-errors');
var createInstance4OpenidConnectStrategy = require('./auth_oidc_common.js').createInstance4OpenidConnectStrategy;


/**
 * 下記のOIDC連携ログインの情報は、Azureは以下のコンソールから設定と取得を行う。
 * https://portal.azure.com/
 * 
 */
var THIS_ROUTE_PATH = 'auth-azure'; // ※本サンプルでは「どのOIDCに対して？」の区別にも利用。
var THIS_STRATEGY_NAME = 'openidconnect-azure'; // passport.use()で指定するOIDC-Strategyの識別子
var OIDC_CONFIG = {
  ISSUER        : process.env.AZURE_ISSUER,
  AUTH_URL      : process.env.AZURE_AUTH_URL,
  TOKEN_URL     : process.env.AZURE_TOKEN_URL,
  USERINFO_URL  : process.env.AZURE_USERINFO_URL,  

  CLIENT_ID     : process.env.AZURE_CLIENT_ID,
  CLIENT_SECRET : process.env.AZURE_CLIENT_SECRET,
  RESPONSE_TYPE : 'code', // Authentication Flow、を指定
  SCOPE : 'profile email', // 「openid 」はデフォルトで「passport-openidconnect」側が付与するので、指定不要。
  REDIRECT_URI_DIRECTORY : 'callback', // 「THIS_ROUTE_PATH + この値」が、OIDCプロバイダーへ登録した「コールバック先のURL」になるので注意。
  PROTOCOL_AND_DOMAIN : (process.env.PROTOCOL_AND_DOMAIN) 
    ? process.env.PROTOCOL_AND_DOMAIN 
    : ''
    // 公開時＝httpsプロトコル動作時は、明示的にドメインを指定する必要がある。
    // 例えば「PROTOCOL_AND_DOMAIN=https://XXXX.azurewebsites.net」など。
    // ローカル動作時は上記の環境変数「PROTOCOL_AND_DOMAIN」は指定不要。
};
// https://docs.microsoft.com/ja-jp/azure/active-directory/develop/quickstart-register-app



// ここで、
// 「OpenidConnectStrategy = require("passport-openidconnect")」を
// Passport.jsのStrategyに設定した場合、Passportとしてのsessino初期化が必須となる。
// 
// OIDCのIdPの違いに依存せずに同一処理となるため、
// app.jsの方で以下を記載している。
// 
// > app.use(passport.initialize());
// > app.use(passport.session());



// OIDCの認可手続きを行うためのミドルウェアとしてのpassportをセットアップ。-------------------------------------------------
var OpenidConnectStrategy = require("passport-openidconnect").Strategy;
var Instance4AzureOIDC = createInstance4OpenidConnectStrategy(
  OpenidConnectStrategy,
  OIDC_CONFIG,
  THIS_ROUTE_PATH
);


/**
 * Strategies used for authorization are the same as those used for authentication. 
 * However, an application may want to offer both authentication and 
 * authorization with the same third-party service. 
 * In this case, a named strategy can be used, 
 * by overriding the strategy's default name in the call to use().
 * 
 * https://www.passportjs.org/docs/configure/
 * の、大分下の方に、上述の「a named strategy can be used」の記載がある。
*/
var passport = require("passport");
passport.use(THIS_STRATEGY_NAME, Instance4AzureOIDC);



// ログイン要求を受けて、OIDCの認可プロバイダーへリダイレクト。-------------------------------------------------
router.get(
  '/login', 
  passport.authenticate(THIS_STRATEGY_NAME)
);




// OIDCの認可プロバイダーからのリダイレクトを受ける。---------------------------------------------------------
// ※この時、passport.authenticate() は、渡されてくるクエリーによって動作を変更する仕様。
router.get(
  '/' + OIDC_CONFIG.REDIRECT_URI_DIRECTORY,
  passport.authenticate(
    THIS_STRATEGY_NAME, 
    {
      failureRedirect: "loginfail",
    }
  ),
  function (req, res) {
    console.log('+++ Successful authentication, redirect home. +++')
    console.log("IDトークンのリクエストに用いた認可コード:" + req.query.code);
    req.session.user = req.session.passport.user.displayName;
    console.log('[req.session]');
    console.log(req.session);
    console.log('--- Successful authentication, ------------------\n')
    res.redirect("loginsuccess");
  }
);





// THIS_ROUTE_PATH (='../auth') 配下のファイルへのアクセス要求の、上記（login/callback）以外の処理を記載する。---------------

// ログインに失敗したときに表示されるページ
router.get('loginfail', function (req, res, next) {
  var htmlStr = '<html lang="ja">';
  htmlStr += '<head>';
  htmlStr += '<meta charset="UTF-8">';
  htmlStr += '<title>login failed.</title>';
  htmlStr += '</head>'
  htmlStr += '<body>';
  htmlStr += 'ログインに失敗しました。';
  htmlStr += '</body>';
  htmlStr += '</html>';

  res.header({"Content-Type" : "text/html; charset=utf-8"})
  res.status(200).send(htmlStr);
  res.end();
});


// ログインに成功したときに表示されるページ
router.get('/loginsuccess', function(req, res, next) {
  console.log("+++ login by "+THIS_ROUTE_PATH+" - /loginsuccess +++");
  console.log(req.session.passport);
  console.log("---[/loginsuccess]----------------------------------\n");
  var htmlStr = '<html lang="ja">';
  htmlStr += '<head>';
  htmlStr += '<meta charset="UTF-8">';
  htmlStr += '<title>login success.</title>';
  htmlStr += '</head>'
  htmlStr += '<body>';
  htmlStr += 'Azure ODIC連携ログインに成功しました。as ' + req.session.passport.user.profile.displayName;
  htmlStr += '</body>';
  htmlStr += '</html>';

  res.header({"Content-Type" : "text/html; charset=utf-8"})
  res.status(200).send(htmlStr);
  res.end();
});




// 「get()」ではなく「use()」であることに注意。
// ref. https://stackoverflow.com/questions/15601703/difference-between-app-use-and-app-get-in-express-js
router.use(
  '/', 
  function(req, res, next) {
    console.log('任意の'+THIS_ROUTE_PATH+'配下へのアクセス');
    console.log("+++ req.session.passport +++");
    console.log(req.session);
    console.log('[req.session.passport.user.profile]')
    console.log(JSON.stringify(req.session.passport.user.profile));
    console.log("----------------------------");

    if( 
      req.session 
      && req.session.passport 
      && req.session.passport.user 
      && req.session.passport.user.type == THIS_ROUTE_PATH
    ){
      console.log('Azure へのOIDCでログインしたセッションを取得できた')
      console.log(path.join(__dirname, '../' + THIS_ROUTE_PATH));
      next();
    }else{
      console.log('Azureへログインしてない＝セッション取れない')
      next(createError(401, 'Please login to view this page.'));
    }
  }, 
  express.static(path.join(__dirname, '../' + THIS_ROUTE_PATH)) 
);
  



// catch 404 and forward to error handler +++add
router.use(function (req, res, next) {
  next(createError(404));
});



module.exports = router;




