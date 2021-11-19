// Load modules.
var passport = require('passport-strategy')
  , url = require('url')
  , uid = require('uid2')
  , crypto = require('crypto')
  , base64url = require('base64url')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , NullStore = require('./state/null')
  , NonceStore = require('./state/session')
  , StateStore = require('./state/store')
  , PKCEStateStore = require('./state/pkcesession')
  , AuthorizationError = require('./errors/authorizationerror')
  , TokenError = require('./errors/tokenerror')
  , InternalOAuthError = require('./errors/internaloautherror')
  , Profile = require('./profile');


/**
 * Creates an instance of `TrovoStrategy`, based on Oauth 2.0
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new TrovoStrategy({
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function TrovoStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  /*  Set our trovo defaults */
  options.authorizationURL = options.authorizationURL || 'https://open.trovo.live/page/login.html';
  options.tokenURL = options.tokenURL || 'https://open-api.trovo.live/openplatform/exchangetoken';
  options.userInfoUrl = options.userInfoUrl || 'https://open-api.trovo.live/openplatform/getuserinfo';

  if (!verify) { throw new TypeError('TrovoStrategy requires a verify callback'); }
  if (!options.authorizationURL) { throw new TypeError('TrovoStrategy requires a authorizationURL option'); }
  if (!options.tokenURL) { throw new TypeError('TrovoStrategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('TrovoStrategy requires a clientID option'); }

  passport.Strategy.call(this);
  this.name = 'trovo';
  this._verify = verify;

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
                            '', options.authorizationURL, options.tokenURL, options.customHeaders);

  this._accessTokenUrl = options.tokenURL;
  this._userInfoUrl = options.userInfoUrl;
  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._clientId = options.clientID;
  this._clientSecret = options.clientSecret;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._pkceMethod = (options.pkce === true) ? 'S256' : options.pkce;
  this._key = options.sessionKey || ('trovo:' + url.parse(options.authorizationURL).hostname);

  if (options.store && typeof options.store == 'object') {
    this._stateStore = options.store;
  } else if (options.store) {
    this._stateStore = options.pkce ? new PKCEStateStore({ key: this._key }) : new StateStore({ key: this._key });
  } else if (options.state) {
    this._stateStore = options.pkce ? new PKCEStateStore({ key: this._key }) : new NonceStore({ key: this._key });
  } else {
    if (options.pkce) { throw new TypeError('TrovoStrategy requires `state: true` option when PKCE is enabled'); }
    this._stateStore = new NullStore();
  }
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

// Inherit from `passport.Strategy`.
util.inherits(TrovoStrategy, passport.Strategy);

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
TrovoStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId,
    callbackURL: callbackURL
  }

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }

      var code = req.query.code;

      var params = self.tokenParams(options);
      params.grant_type = 'authorization_code';
      if (callbackURL) { params.redirect_uri = callbackURL; }
      if (typeof ok == 'string') { // PKCE
        params.code_verifier = ok;
      }

      // console.log({code: code, params: params});
      self.getOAuthAccessToken(code, params, function(err, accessToken, refreshToken, params) {
          // console.log({err: err, accessToken:accessToken, refreshToken:refreshToken, params:params});
          
          if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
          if (!accessToken) { return self.error(new Error('Failed to obtain access token')); }

          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); }
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }
            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }

    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var verifier, challenge;

    if (this._pkceMethod) {
      verifier = base64url(crypto.pseudoRandomBytes(32))
      switch (this._pkceMethod) {
      case 'plain':
        challenge = verifier;
        break;
      case 'S256':
        challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
        break;
      default:
        return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
      }

      params.code_challenge = challenge;
      params.code_challenge_method = this._pkceMethod;
    }

    var state = options.state;
    if (state && typeof state == 'string') {
      // NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
      //       an object.  However, it would result in an empty string being
      //       serialized as the value of the query parameter by `url.format()`,
      //       effectively ignoring the option.  This implies that `state` was
      //       only functional when passed as a string value.
      //
      //       This fact is taken advantage of here to fall into the `else`
      //       branch below when `state` is passed as an object.  In that case
      //       the state will be automatically managed and persisted by the
      //       state store.
      params.state = state;

      var parsed = url.parse(this._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query['client_id'] = this._oauth2._clientId;
      delete parsed.search;
      var location = url.format(parsed);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
        var parsed = url.parse(self._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query['client_id'] = self._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }

      try {
        var arity = this._stateStore.store.length;
        if (arity == 5) {
          this._stateStore.store(req, verifier, state, meta, stored);
        } else if (arity == 4) {
          this._stateStore.store(req, state, meta, stored);
        } else if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

TrovoStrategy.prototype.getOAuthAccessToken = function(code, params, callback) {
  var self = this;
  var params= params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;

  var post_data= JSON.stringify( params );
  var post_headers= {
   'Content-Type': 'application/json',
   'Accepts': 'application/json',
   'Client-Id': this._clientId
  };


  self._oauth2._request("POST", this._accessTokenUrl, post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results= JSON.parse( data );
      }
      catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results= querystring.parse( data );
      }
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
};

/**
 * Retrieve user profile from service provider.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to load the user's profile from the service provider.  This assists
 * applications (and users of those applications) in the initial registration
 * process by automatically submitting required information.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
TrovoStrategy.prototype.userProfile = function(accessToken, done) {
  var json;
  const headers = {
    'Accept': 'application/json',
    'Client-Id': this._clientId,
    'Authorization': 'OAuth ' + accessToken
  };
  this._oauth2._request("GET", this._userInfoUrl, headers, null, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      try {
        json = JSON.parse(data);
      }
      catch(e) {
        return done(new Error('Failed to parse user profile'));
      }

      const profile = Profile.parse(json);
      profile.provider = 'trovo';
      // this shit was the important part!
      profile.accessToken = accessToken;
      profile._raw = data;
      return done(null, profile);
    }
  });
};

TrovoStrategy.prototype.formattedProfile = function(json, _provider) {

}

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
TrovoStrategy.prototype.authorizationParams = function(options) {
  return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
TrovoStrategy.prototype.tokenParams = function(options) {
  const params = Object.assign({}, options);
  params.client_secret = this._clientSecret;
  return params;
};

/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to parse error responses received from the token endpoint, allowing the
 * most informative message to be displayed.
 *
 * If this function is not overridden, the body will be parsed in accordance
 * with RFC 6749, section 5.2.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
TrovoStrategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);
  if (json.error) {
    return new TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
TrovoStrategy.prototype._loadUserProfile = function(accessToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
TrovoStrategy.prototype._createOAuthError = function(message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }
  if (!e) { e = new InternalOAuthError(message, err); }
  return e;
};


// Expose constructor.
module.exports = TrovoStrategy;
