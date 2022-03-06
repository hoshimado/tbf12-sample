exports.createInstance4OpenidConnectStrategy = function (OpenidConnectStrategy, OIDC_CONFIG, THIS_ROUTE_PATH) {
    return new OpenidConnectStrategy(
        {
            issuer:           OIDC_CONFIG.ISSUER,
            authorizationURL: OIDC_CONFIG.AUTH_URL,
            tokenURL:         OIDC_CONFIG.TOKEN_URL,
            userInfoURL:      OIDC_CONFIG.USERINFO_URL,
            clientID:     OIDC_CONFIG.CLIENT_ID,
            clientSecret: OIDC_CONFIG.CLIENT_SECRET,
            callbackURL:  OIDC_CONFIG.PROTOCOL_AND_DOMAIN + '/' + THIS_ROUTE_PATH + '/' + OIDC_CONFIG.REDIRECT_URI_DIRECTORY,
            // ↑公式サンプルを見るに、「https://」から直に指定している様子。
            // https://www.npmjs.com/package/passport-idaas-openidconnect#example
            // ※指定しない場合は、(req, res)=>{} の「req.connection.encrypted」から（optionもあるが無指定なので略）
            // 　「http or https」を判断したうえで、reqのhost, passメンバーから絶対パスを再構成する仕様
            // 　の様子（passport-openidconnect\lib\strategy.jsのL281「if (callbackURL) {}」の部分）。
            // 　ただ、一般にhttpsはリバースプロキシサーバー or Load Balancerで終端されて、このExpress.js
            // 　が動作するWebアプリサーバーには「http」で接続される事が多いので、その処理に任せると
            // 　「http」として扱われてしまう（ことが大半のはず）。
            // 　なので、外部公開時は（https必須なので）、明示的にプロトコルとドメイン込みで指定する必要がある。
            scope:        OIDC_CONFIG.SCOPE // ['profile' 'email]でも'profile email'でもどちらでも内部で自動変換してくれる。
            /**
             * 公開情報（EndPointとか）は以下を参照
             * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/quickstart-register-app
             * https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration
             */
        },
        /**
         * 第一引数のパラメータでOIDCの認証に成功（UserInfoまで取得成功）時にcallbackされる関数
         * 引数は、node_modules\passport-openidconnect\lib\strategy.js のL220～を参照。
         * 指定した引数の数に応じて、返却してくれる。この例では最大数を取得している。
         * @param {*} issuer    idToken.iss
         * @param {*} uiProfile UserInfo EndoPointのProfileレスポンス（._json）＋name周りを独自に取り出した形式
         * @param {*} idProfile トークン EndoPointのレスポンスから以下のものを取り出した形式
         *     displayNam(name), username(preferred_username), family_name, given_name, middle_name, email
         *     ※IdPによって、family_name等はIDトークンではなくProfile側でのみ提供される場合があるので注意。
         * @param {*} context   認証コンテキストに関する情報。acr, amr, auth_timeクレームがIDトークンに含まれる場合に抽出される（v0.1.0以降）
         *                      ref. https://github.com/jaredhanson/passport-openidconnect/blob/master/CHANGELOG.md#010---2021-11-17
         * @param {*} idToken      IDトークンそのもの
         * @param {*} accessToken  アクセストークンそのもの
         * @param {*} refreshToken リフレッシュトークンそのもの
         * @param {*} tokenResponse トークンエンドポイントが返却したレスポンスそのもの（idToken, accessToken等を含む）
         * @param {*} done 「取得した資格情報が有効な場合に、このverify()を呼び出して通知する」のがPassport.jsの仕様
         * > If the credentials are valid, the verify callback invokes done 
         * > to supply Passport with the user that authenticated.
         * - https://www.passportjs.org/docs/configure/
         * @returns 上述のdone()の実行結果を返却する.
         */
         function (
          issuer,
          uiProfile,
          idProfile,
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
            console.log("+++[Success Authenticate by Azure OIDC]+++");
            console.log("issuer: ", issuer);
            console.log("profile: ", uiProfile);
            console.log("idTokenParts", idProfile);
            console.log("context: ", context);
            console.log("idToken: ", idToken);
            console.log("accessToken: ", accessToken);
            console.log("refreshToken: ", refreshToken);
            console.log("tokenResponse: ", tokenResponse);
            console.log("------[End of displaying for debug]------");
            // OIDCライブラリの0.1.1でのcallback関数の引数変更に対応済み。
            // UserInfoにアクセスするか否か？を選べるようになって、デフォルト「しない」に仕様変更されてた。
            // https://github.com/jaredhanson/passport-openidconnect/blob/master/CHANGELOG.md#010---2021-11-17
    
    
            // セッションを有効にしている場合、この「done()」の第二引数に渡された値が、
            // 「passport.serializeUser( function(user, done){} )」のuserの引数として
            // 渡される、、、はず（動作からはそのように見える）だが、その旨が掛かれた
            // （serializeUserの仕様）ドキュメントには辿り着けず。。。at 2022-01-08
            // 一応、「../app.js」側の「passport.serializeUser()」のコメントも参照のこと。
            return done(null, {
              title : 'OIDC by ' + THIS_ROUTE_PATH,
              typeName : THIS_ROUTE_PATH,
              profile: uiProfile,
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
};



