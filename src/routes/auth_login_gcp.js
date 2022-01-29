var express = require('express');
var router = express.Router();
var path = require('path');
var createError = require("http-errors");


/**
 * 下記のOIDC連携ログインの情報は、GCPは以下のコンソールから設定と取得を行う。
 * https://cloud.google.com/
 * 
 */
var THIS_ROUTE_PATH = 'auth-gcp'; // ※本サンプルでは「どのOIDCに対して？」の区別にも利用。
var OIDC_CONFIG = {
  ISSUER        : process.env.GCP_ISSUER,
  AUTH_URL      : process.env.GCP_AUTH_URL,
  TOKEN_URL     : process.env.GCP_TOKEN_URL,
  USERINFO_URL  : process.env.GCP_USERINFO_URL,  

  CLIENT_ID : process.env.GCP_CLIENT_ID,
  CLIENT_SECRET : process.env.GCP_CLIENT_SECRET,
  RESPONSE_TYPE : 'code', // Authentication Flow、を指定
  SCOPE : 'profile email', // 「openid 」はデフォルトで「passport-openidconnect」側が付与するので、指定不要。
  REDIRECT_URI_DIRECTORY : 'callback' // 「THIS_ROUTE_PATH + この値」が、OIDCプロバイダーへ登録した「コールバック先のURL」になるので注意。
};
// https://console.developers.google.com/


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
var Instance4GoogleOIDC = new OpenidConnectStrategy(
    {
      issuer:           OIDC_CONFIG.ISSUER,
      authorizationURL: OIDC_CONFIG.AUTH_URL,
      tokenURL:         OIDC_CONFIG.TOKEN_URL,
      userInfoURL:      OIDC_CONFIG.USERINFO_URL,
      clientID:     OIDC_CONFIG.CLIENT_ID,
      clientSecret: OIDC_CONFIG.CLIENT_SECRET,
      callbackURL:  THIS_ROUTE_PATH + '/' + OIDC_CONFIG.REDIRECT_URI_DIRECTORY,
      scope:        OIDC_CONFIG.SCOPE // ['profile' 'email]でも'profile email'でもどちらでも内部で自動変換してくれる。
      /**
       * 公開情報（EndPointとか）は以下を参照
       * https://developers.google.com/identity/protocols/oauth2/openid-connect
       * https://accounts.google.com/.well-known/openid-configuration
       */
    },
    /**
     * 第一引数のパラメータでOIDCの認証に成功（UserInfoまで取得成功）時にcallbackされる関数
     * 引数は、node_modules\passport-openidconnect\lib\strategy.js のL220～を参照。
     * 指定した引数の数に応じて、返却してくれる。この例では最大数を取得している。
     * @param {*} issuer    idToken.iss
     * @param {*} profile   UserInfo EndoPointのレスポンス（._json）＋name周りを独自に取り出した形式
     * @param {*} context   認証コンテキストに関する情報。acr, amr, auth_timeクレームがIDトークンに含まれる場合に抽出される（v0.1.0以降）
     *                      ref. https://github.com/jaredhanson/passport-openidconnect/blob/master/CHANGELOG.md#010---2021-11-17
     * @param {*} idToken
     * @param {*} accessToken 
     * @param {*} refreshToken 
     * @param {*} tokenResponse トークンエンドポイントが返却したレスポンスそのもの（idToken, accessToken等を含む）
     * @param {*} done 「取得した資格情報が有効な場合に、このverify()を呼び出して通知する」のがPassport.jsの仕様
     * > If the credentials are valid, the verify callback invokes done 
     * > to supply Passport with the user that authenticated.
     * - https://www.passportjs.org/docs/configure/
     * @returns 上述のdone()の実行結果を返却する.
     */
    function (
      issuer,
      profile,
      context,
      idToken,
      accessToken,
      refreshToken,
      tokenResponse,
      done
    ) {
      // [For Debug]
      // 認証成功したらこの関数が実行される
      // ここでID tokenの検証を行う
      console.log("+++[Success Authenticate by GCP OIDC]+++");
      console.log("issuer: ", issuer);
      console.log("profile: ", profile);
      console.log("context: ", context);
      console.log("idToken: ", idToken);
      console.log("accessToken: ", accessToken);
      console.log("refreshToken: ", refreshToken);
      console.log("tokenResponse: ", tokenResponse);
      console.log("------[End of displaying for debug]------");

      // セッションを有効にしている場合、この「done()」の第二引数に渡された値が、
      // 「passport.serializeUser( function(user, done){} )」のuserの引数として
      // 渡される、、、はず（動作からはそのように見える）だが、その旨が掛かれた
      // （serializeUserの仕様）ドキュメントには辿り着けず。。。at 2022-01-08
      // 一応、「../app.js」側の「passport.serializeUser()」のコメントも参照のこと。
      return done(null, {
        title : 'OIDC by GCP',
        typeName : THIS_ROUTE_PATH,
        profile: profile,
        accessToken: {
          token: accessToken,
          scope: tokenResponse.scope,
          token_type: tokenResponse.token_type,
          expires_in: tokenResponse.expires_in,
        },
        idToken: {
          token: tokenResponse.id_token,
          claims: idToken,
        },
      });
    }
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
passport.use('openidconnect-gcp', Instance4GoogleOIDC)



// ログイン要求を受けて、OIDCの認可プロバイダーへリダイレクト。-------------------------------------------------
router.get(
  '/login', 
  passport.authenticate("openidconnect-gcp")
);



// OIDCの認可プロバイダーからのリダイレクトを受ける。---------------------------------------------------------
// ※この時、passport.authenticate() は、渡されてくるクエリーによって動作を変更する仕様。
router.get(
  '/' + OIDC_CONFIG.REDIRECT_URI_DIRECTORY,
  passport.authenticate(
    "openidconnect-gcp", {
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
  htmlStr += 'Google OIDC連携ログインに成功しました。as ' + req.session.passport.user.profile.displayName;
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
      console.log('GCP へのOIDCでログインしたセッションを取得できた')
      console.log(path.join(__dirname, '../' + THIS_ROUTE_PATH));
      next();
    }else{
      console.log('GCPへログインしてない＝セッション取れない')
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




