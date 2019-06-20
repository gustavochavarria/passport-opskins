const request = require('request'),
      crypto = require('crypto'),
      url = require('url'),
      querystring = require('querystring'),
      fs = require('fs'),
      path = require('path');


const isValidJson = (json) => {
  try {
    JSON.parse(json);
  } catch(err) {
    return false;
  }
  return true;
}

module.exports = {
  Strategy: function(obj, callback) {
    if (!obj.name || !obj.returnURL || !obj.apiKey)
      throw new Error('Missing name, returnURL or apiKey parameter. These are required.');

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
      if (!fs.existsSync(path.join(__dirname, 'clients.json')))
        return [];

      let data = fs.readFileSync(path.join(__dirname, 'clients.json'), 'utf8');

      if (!isValidJson(data))
        return [];

      return JSON.parse(data).clients;
    };

    this.pushToLocalSavedClientList = (client) => {
      if (!fs.existsSync(path.join(__dirname, 'clients.json')))
        fs.writeFileSync(path.join(__dirname, 'clients.json'), JSON.stringify({
          clients: []
        }));

      let jsonObj = fs.readFileSync(path.join(__dirname, 'clients.json'), 'utf8');
      if (!isValidJson(jsonObj))
        fs.writeFileSync(path.join(__dirname, 'clients.json'), JSON.stringify({
          clients: []
        }));

      jsonObj = JSON.parse(jsonObj);
      jsonObj.clients.push(client);

      fs.writeFileSync(path.join(__dirname, 'clients.json'), JSON.stringify(jsonObj));
    };

    this.deleteClient = (clientid) => {
      let options = {
        url: 'https://api.opskins.com/IOAuth/DeleteClient/v1/',
        headers: {
          'authorization': `Basic ${this.apiKey}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `client_id=${clientid}`
      };
      request.post(options, (err, response, body) => {
        if (err) console.error(err);
      });
    };

    this.getApiKey = () => {
      return this.apiKey;
    };

    this.getClientList = (cb) => {
      let options = {
        url: 'https://api.opskins.com/IOAuth/GetOwnedClientList/v1/',
        headers: {
          'authorization': `Basic ${this.getApiKey()}`,
          'Content-Type': 'application/json; charset=utf-8'
        }
      };

      request.get(options, (err, response, body) => {
        if (err)
          return cb(err);
        if (!isValidJson(body))
          return cb(new Error(`Invalid JSON response`));
        let realBody = JSON.parse(body);
        if (realBody.status !== 1)
          return cb(new Error(`Error retrieving clients: ${realBody.message}`));
        cb(null, realBody.response.clients);
      });
    };

    this.getOrMakeClient = () => {
      let localSavedClients = this.getLocalSavedClientList();
      let datApiKey = this.apiKey;

      this.getClientList((err, clients) => {
        if (err) return console.error(err);

        let existingClient = null;

        clients.forEach((client) => {
          localSavedClients.forEach((localClient) => {
            if (localClient.client_id == client.client_id && localClient.name == client.name && localClient.redirect_uri == client.redirect_uri && this.returnURL == client.redirect_uri)
              existingClient = localClient;
          });
        });

        if (existingClient) {
          return this.setIdAndSecret(existingClient.client_id, existingClient.secret);
        }

        let options = {
          url: 'https://api.opskins.com/IOAuth/CreateClient/v1/',
          headers: {
            'authorization': `Basic ${datApiKey}`,
            'Content-Type': 'application/json; charset=utf-8'
          },
          body: `{"name": "${this.siteName}", "redirect_uri": "${this.returnURL}", "can_keep_secret" : "${this.canKeepSecret}"}`
        };
        request.post(options, (err, response, body) => {
          if (err)
            return console.error(err);
          if (!isValidJson(body))
            return console.error(new Error(`Invalid JSON response`));
          body = JSON.parse(body);
          if (!body.response || !body.response.client || !body.response.client.client_id || !body.response.secret)
            throw new Error(body.message);

          body.response.client.secret = body.response.secret;

          this.pushToLocalSavedClientList(body.response.client);
          this.setIdAndSecret(body.response.client.client_id, body.response.secret);
        });
      });
    };

    this.getOrMakeClient();

    this.updateStates = (states) => {
      this.states = states;
    };
    this.getStates = () => {
      return this.states;
    };
    this.getReturnUrl = () => {
      return this.returnURL;
    };
    this.getAuth = () => {
      return 'Basic ' + Buffer.from(`${this.clientID}:${this.clientSecret}`).toString('base64');
    }

    this.goLogin = () =>  {
      const rand = crypto.randomBytes(4).toString('hex');
      this.states.push(rand);

      console.log('go login....');

      setTimeout(() => {
        console.log('relogin...');
        for (let i = 0; i < this.states.length; i++) {
          if (this.states[i] == rand) {
            this.states.splice(i, 1);
            this.updateStates(this.states);
          }
        }
      }, 600000);

      console.log(`https://oauth.opskins.com/v1/authorize?state=${rand}&client_id=${this.clientID}&response_type=code&scope=${this.scopes}${this.mobileStr}${this.permanentStr}`);

      return `https://oauth.opskins.com/v1/authorize?state=${rand}&client_id=${this.clientID}&response_type=code&scope=${this.scopes}${this.mobileStr}${this.permanentStr}`;
    };

    this.authenticate = (data, redirect) => {
      let urlOptions = data._parsedUrl;
      let originalUrl = data.originalUrl;

      if (url.parse(this.getReturnUrl()).pathname == url.parse(originalUrl).pathname) {
        let parsedQuery = querystring.parse(urlOptions.query);

        let originated;
        this.getStates().forEach((state) => {
          if (state == parsedQuery.state) {
            originated = true;
          }
        });


        if (!originated) {
          let err = new Error(`Authentication did not originate on this server`);

          if (this.debug)
            return this.error(err);

          console.error(err);
          return this.fail(err);
        }

        let auth = this.getAuth();

        let headers = {
          'Authorization': auth,
          'Content-Type': 'application/x-www-form-urlencoded'
        };
        let options = {
          url: 'https://oauth.opskins.com/v1/access_token',
          method: 'POST',
          headers: headers,
          body: `grant_type=authorization_code&code=${parsedQuery.code}`
        };
        request.post(options, (err, response, body) => {
          if (err) {
            if (this.debug)
              return this.error(err);

            console.error(err);
            return this.fail(err);
          }

          if (!isValidJson(body)) {
            let err = new Error(`Invalid JSON response`);
            if (this.debug)
              return this.error(err);

            console.error(err);
            return this.fail(err);
          }

          body = JSON.parse(body);

          if (body.error) {
            let err = new Error(`Failed to serialize user into session: ${body.error}`);

            if (this.debug)
              return this.error(err);

            console.error(err);
            return this.fail(err);
          }

          let headers2 = {
            'Authorization': `Bearer ${body.access_token}`
          };
          let options2 = {
            url: 'https://api.opskins.com/IUser/GetProfile/v1/',
            headers: headers2
          };
          request.get(options2, (err, response, body3) => {
            if (err) {
              if (this.debug)
                return this.error(err);

              console.error(err);
              return this.fail(err);
            }

            if (!isValidJson(body3)) {
              let err = new Error(`Invalid JSON response`);

              if (this.debug)
                return this.error(err);

              console.error(err);
              return this.fail(err);
            }

            let realBody = JSON.parse(body3);

            if (realBody.error) {
              let err = new Error(`Failed to serialize user into session: ${realBody.error}`);

              if (this.debug)
                return this.error(err);

              console.error(err);
              return this.fail(err);
            }

            let userObj = realBody.response;


            console.log('realBody: ', realBody);

            userObj.access = body;
            userObj.access.code = parsedQuery.code;

            let datErr = this.debug ? this.error : this.fail;
            let datSuccess = this.success;

            if(this.passReqToCallback) {
              this.callback(data, userObj, (err, user) => {
                if (err) {
                  if (!this.debug)
                    console.error(err);
                  return datErr(err);
                }
                datSuccess(user);
              });
            } else {
              this.callback(userObj, (err, user) => {
                if (err) {
                  if (!this.debug)
                    console.error(err);
                  return datErr(err);
                }
                datSuccess(user);
              });
            }
          });
        });
      } else {
        data.res.redirect(this.goLogin());
      }
    };
    this.refreshAccessToken = (refreshToken, cb) => {
      let auth = this.getAuth();

      let headers = {
        'Authorization': auth,
        'Content-Type': 'application/x-www-form-urlencoded'
      };
      let options = {
        url: 'https://oauth.opskins.com/v1/access_token',
        method: 'POST',
        headers: headers,
        body: `grant_type=refresh_token&refresh_token=${refreshToken}`
      };
      request.post(options, (err, response, body) => {
        if (err)
          return cb(err);

        if (!isValidJson(body))
          return cb(new Error(`Invalid JSON response`));

        body = JSON.parse(body);

        if (body.error)
          return cb(new Error(body.error));

        cb(null, body.access_token);
      });
    };
  }
};