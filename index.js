const request = require('request'),
  crypto = require('crypto'),
  url = require('url'),
  querystring = require('querystring'),
  fs = require('fs'),
  path = require('path');

const isValidJson = json => {
  try {
    JSON.parse(json);
  } catch (err) {
    return false;
  }
  return true;
};

module.exports = {
  Strategy: function(obj, callback) {
    if (!obj.name || !obj.returnURL || !obj.apiKey)
      throw new Error(
        'Missing name, returnURL or apiKey parameter. These are required.'
      );

    this.apiKey = Buffer.from(obj.apiKey + ':', 'ascii').toString('base64');
    this.siteName = obj.name;
    this.returnURL = obj.returnURL;
    this.mobile = obj.mobile;
    this.scopes = obj.scopes || 'identity';
    this.states = [];
    this.mobileStr = obj.mobile ? `&mobile=1` : ``;
    this.permanentStr = obj.permanent ? `&duration=permanent` : ``;
    this.clientID = null;
    this.clientSecret = null;
    this.name = 'opskins';
    this.debug = obj.debug || null;
    this.callback = callback;
    this.passReqToCallback = obj.passReqToCallback || false;
    this.canKeepSecret = obj.canKeepSecret || 1;

    this.setIdAndSecret = (id, secret) => {
      this.clientID = String(id).trim();
      this.clientSecret = String(secret).trim();

      console.log('clientID: ', this.clientID);
      console.log('clientSecret: ', this.clientSecret);
    };

    this.getLocalSavedClientList = () => {
      if (!fs.existsSync(path.join(__dirname, 'clients.json'))) return [];

      const data = fs.readFileSync(
        path.join(__dirname, 'clients.json'),
        'utf8'
      );

      if (!isValidJson(data)) return [];

      return JSON.parse(data).clients;
    };

    this.pushToLocalSavedClientList = client => {
      if (!fs.existsSync(path.join(__dirname, 'clients.json')))
        fs.writeFileSync(
          path.join(__dirname, 'clients.json'),
          JSON.stringify({
            clients: [],
          })
        );

      let jsonObj = fs.readFileSync(
        path.join(__dirname, 'clients.json'),
        'utf8'
      );
      if (!isValidJson(jsonObj))
        fs.writeFileSync(
          path.join(__dirname, 'clients.json'),
          JSON.stringify({
            clients: [],
          })
        );

      jsonObj = JSON.parse(jsonObj);
      jsonObj.clients.push(client);

      fs.writeFileSync(
        path.join(__dirname, 'clients.json'),
        JSON.stringify(jsonObj)
      );
    };

    this.deleteClient = clientid => {
      const options = {
        url: 'https://api.opskins.com/IOAuth/DeleteClient/v1/',
        headers: {
          authorization: `Basic ${this.apiKey}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `client_id=${clientid}`,
      };

      request.post(options, (err, response, body) => {
        if (err) console.error(err);
      });
    };

    this.getApiKey = () => {
      return this.apiKey;
    };

    this.getClientList = cb => {
      const options = {
        url: 'https://api.opskins.com/IOAuth/GetOwnedClientList/v1/',
        headers: {
          authorization: `Basic ${this.getApiKey()}`,
          'Content-Type': 'application/json; charset=utf-8',
        },
      };

      request.get(options, (err, response, body) => {
        if (err) return cb(err);

        if (!isValidJson(body)) return cb(new Error(`Invalid JSON response`));

        const realBody = JSON.parse(body);

        if (realBody.status !== 1)
          return cb(new Error(`Error retrieving clients: ${realBody.message}`));

        cb(null, realBody.response.clients);
      });
    };

    this.getOrMakeClient = () => {
      const localSavedClients = this.getLocalSavedClientList();
      const datApiKey = this.apiKey;

      console.log('=========== getOrMakeClient ===============');

      console.log('localSavedClients:  ', localSavedClients);
      console.log('datApiKey: ', datApiKey);

      this.getClientList((err, clients) => {
        if (err) return console.error(err);

        const _dat = this;

        let existingClient = null;

        clients.forEach(function(client) {
          localSavedClients.forEach(function(localClient) {
            if (
              localClient.client_id === client.client_id &&
              localClient.name === client.name &&
              localClient.redirect_uri === client.redirect_uri &&
              _dat.returnURL === client.redirect_uri
            )
              existingClient = localClient;
          });
        });

        console.log(' ===== EXISTING CLIENT =====');
        console.log('existingClient: ', existingClient);

        //CACHE DISABLED
        // if (existingClient) {
        //   return this.setIdAndSecret(
        //     existingClient.client_id,
        //     existingClient.secret
        //   );
        // }

        const options = {
          url: 'https://api.opskins.com/IOAuth/CreateClient/v1/',
          headers: {
            authorization: `Basic ${datApiKey}`,
            'Content-Type': 'application/json; charset=utf-8',
          },
          body: `{"name": "${this.siteName}","redirect_uri": "${
            this.returnURL
          }","can_keep_secret" : ${this.canKeepSecret}}`,
        };

        console.log('no user exist');
        console.log('options: ', options);
        request.post(options, (err, response, body) => {
          if (err) return console.error(err);

          if (!isValidJson(body))
            return console.error(new Error(`Invalid JSON response`));

          body = JSON.parse(body);

          if (
            !body.response ||
            !body.response.client ||
            !body.response.client.client_id ||
            !body.response.secret
          )
            throw new Error(body.message);

          body.response.client.secret = body.response.secret;

          this.pushToLocalSavedClientList(body.response.client);
          this.setIdAndSecret(
            body.response.client.client_id,
            body.response.secret
          );
        });
      });
    };

    this.getOrMakeClient();

    this.updateStates = states => {
      this.states = states;
    };

    this.getStates = () => {
      return this.states;
    };

    this.getReturnUrl = () => {
      return this.returnURL;
    };

    this.getAuth = () => {
      return (
        'Basic ' +
        Buffer.from(this.clientID + ':' + this.clientSecret).toString('base64')
      );
    };

    this.goLogin = () => {
      const rand = crypto.randomBytes(4).toString('hex');
      this.states.push(rand);

      setTimeout(() => {
        console.log('----------------------');
        console.log('exec setTimeout');

        for (let i = 0; i < this.states.length; i++) {
          if (this.states[i] == rand) {
            this.states.splice(i, 1);
            this.updateStates(this.states);
          }
        }
      }, 600000);

      console.log(' =================== LOGIN ===================');
      console.log('clientID: ', this.clientID);
      console.log('scopes: ', this.scopes);
      console.log('permanentStr: ', this.permanentStr);

      return `https://oauth.opskins.com/v1/authorize?state=${rand}&client_id=${
        this.clientID
      }&response_type=code&scope=${this.scopes}${this.mobileStr}${
        this.permanentStr
      }`;
    };

    const _this = this;
    this.authenticate = function(data, redirect) {
      const { originalUrl, _parsedUrl } = data;

      console.log('=================== AUTHENTICATING ===================');
      console.log('originalUrl: ', originalUrl);
      console.log('_parsedUrl: ', _parsedUrl);

      console.log(
        'getReturn url pathname: ',
        url.parse(_this.getReturnUrl()).pathname
      );
      console.log('original pathname: ', url.parse(originalUrl).pathname);

      if (
        url.parse(_this.getReturnUrl()).pathname !==
        url.parse(originalUrl).pathname
      ) {
        console.log(' --- REDIRECT ---');
        data.res.redirect(_this.goLogin());

        return;
      }

      console.log(' --- PARSING ---');

      const parsedQuery = querystring.parse(_parsedUrl.query);

      console.log('parsedQuery: ', parsedQuery);
      console.log('parsedQuery - code: ', parsedQuery.code);

      let originated;

      _this.getStates().forEach(function(state) {
        if (state == parsedQuery.state) {
          originated = true;
        }
      });

      if (!originated) {
        const err = new Error(
          `Authentication did not originate on this server`
        );

        if (_this.debug) return this.error(err);

        console.error(err);
        return this.fail(err);
      }

      const options = {
        url: 'https://oauth.opskins.com/v1/access_token',
        method: 'POST',
        headers: {
          Authorization: `${_this.getAuth()}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `grant_type=authorization_code&code=${parsedQuery.code}`,
      };

      console.log('--- ACCESS TOKEN ----- ');
      console.log('options: ', options);

      request.post(options, (err, response, bodyObj) => {
        if (err) {
          if (_this.debug) return this.error(err);

          console.error(err);
          return this.fail(err);
        }

        if (!isValidJson(bodyObj)) {
          const err = new Error(`Invalid JSON response`);

          if (_this.debug) return this.error(err);

          console.error(err);
          return this.fail(err);
        }

        const body = JSON.parse(bodyObj);

        if (body.error) {
          const err = new Error(
            `Failed to serialize user into session: ${body.error}`
          );

          if (_this.debug) return this.error(err);

          console.error(err);
          return this.fail(err);
        }

        const options2 = {
          url: 'https://api.opskins.com/IUser/GetProfile/v1/',
          headers: {
            authorization: `Bearer ${body.access_token}`,
          },
        };

        console.log('==== GET PROFILE ====');
        console.log('access_token: ', `${body.access_token}`);

        request.get(options2, (err, response, body3) => {
          console.log('---- request ----');
          console.log('body3: ', body3);

          if (err) {
            if (_this.debug) return this.error(err);

            console.error(err);
            return this.fail(err);
          }

          if (!isValidJson(body3)) {
            const err = new Error(`Invalid JSON response`);

            if (_this.debug) return this.error(err);

            console.error(err);
            return this.fail(err);
          }

          let realBody = JSON.parse(body3);

          if (realBody.error) {
            const err = new Error(
              `Failed to serialize user into session: ${realBody.error}`
            );

            if (_this.debug) return this.error(err);

            console.error(err);
            return this.fail(err);
          }

          let userObj = realBody.response;

          userObj.access = body;
          userObj.access.code = parsedQuery.code;

          console.log(' ==== USER OBJ =====');
          console.log('userObj: ', userObj);

          let datErr = _this.debug ? this.error : this.fail;
          let datSuccess = this.success;

          if (this.passReqToCallback) {
            _this.callback(data, userObj, function(err, user) {
              if (err) {
                if (!_this.debug) console.error(err);
                return datErr(err);
              }
              datSuccess(user);
            });
          } else {
            _this.callback(userObj, function(err, user) {
              if (err) {
                if (!_this.debug) console.error(err);
                return datErr(err);
              }
              datSuccess(user);
            });
          }
        });
      });
    };
    this.refreshAccessToken = (refreshToken, cb) => {
      const options = {
        url: 'https://oauth.opskins.com/v1/access_token',
        method: 'POST',
        headers: {
          Authorization: `${this.getAuth()}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `grant_type=refresh_token&refresh_token=${refreshToken}`,
      };
      request.post(options, (err, response, body) => {
        if (err) return cb(err);

        if (!isValidJson(body)) return cb(new Error(`Invalid JSON response`));

        body = JSON.parse(body);

        if (body.error) return cb(new Error(body.error));

        cb(null, body.access_token);
      });
    };
  },
};
