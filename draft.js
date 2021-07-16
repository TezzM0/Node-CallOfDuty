const axios = require('axios');
const axiosCookieJarSupport = require('axios-cookiejar-support').default;
const tough = require('tough-cookie');
const rateLimit = require('axios-rate-limit');
// const puppeteer = require('puppeteer');

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36w";
let baseCookie = "new_SiteId=cod; ACT_SSO_LOCALE=en_US;country=US;";
let ssoCookie;  // TODO: Not sure where to get this from now
let loggedIn = false;
let debug = 0;

// let browser;
// let page;

// let apiAxios = axios.create({
//     headers: {
//         common: {
//             "content-type": "application/json",
//             "cookie": baseCookie,
//             "userAgent": userAgent,
//             "x-requested-with": userAgent,
//             "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
//             "Connection": "keep-alive"
//         },
//     },
//     withCredentials: true,
//     timeout: 60000,
// });

axiosCookieJarSupport(axios);
const cookieJar = new tough.CookieJar();
axios.defaults.jar = cookieJar;
axios.defaults.withCredentials = true;
axios.defaults.timeout = 30000;
axios.defaults.headers = {
  common : {
    "content-type": "application/json",
    "Cookie": baseCookie,
    "User-Agent": userAgent,
    "x-requested-with": userAgent,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Connection": "keep-alive",
  }
};

// let loginAxios = apiAxios;
let defaultBaseURL = "https://my.callofduty.com/api/papi-client/";
let defaultProfileURL = "https://profile.callofduty.com/";

class helpers {
    buildUri(str) {
        return `${defaultBaseURL}${str}`;
    }

    buildProfileUri(str) {
        return `${defaultProfileURL}${str}`;
    }

    cleanClientName(gamertag) {
        return encodeURIComponent(gamertag);
    }

    sendRequestUserInfoOnly(url) {
        return new Promise((resolve, reject) => {
            if (!loggedIn) reject("Not Logged In.");
            axios.get(url).then(body => {
                if (body.status == 403) reject("Forbidden. You may be IP banned.");
                if (debug === 1) {
                    console.log(`[DEBUG]`, `Build URI: ${url}`);
                    console.log(`[DEBUG]`, `Round trip took: ${body.headers['request-duration']}ms.`);
                    console.log(`[DEBUG]`, `Response Size: ${JSON.stringify(body.data).length} bytes.`);
                }
                resolve(JSON.parse(body.data.replace(/^userInfo\(/, "").replace(/\);$/, "")));
            }).catch(err => reject(err));
        });
    }

    sendRequest(url) {
        return new Promise((resolve, reject) => {
            if (!loggedIn) reject("Not Logged In.");
            axios.get(url).then(response => {
                if (debug === 1) {
                    console.log(`[DEBUG]`, `Build URI: ${url}`);
                    console.log(`[DEBUG]`, `Round trip took: ${response.headers['request-duration']}ms.`);
                    console.log(`[DEBUG]`, `Response Size: ${JSON.stringify(response.data.data).length} bytes.`);
                }

                if (response.data.status !== undefined && response.data.status === 'success') {
                    resolve(response.data.data);
                } else {
                    reject(this.apiErrorHandling({response: response}));
                }
            }).catch((error) => {
                reject(this.apiErrorHandling(error));
            });
        });
    }

    sendPostRequest(url, data) {
        return new Promise((resolve, reject) => {
            if (!loggedIn) reject("Not Logged In.");
            axios.post(url, JSON.stringify(data)).then(response => {
                if (debug === 1) {
                    console.log(`[DEBUG]`, `Build URI: ${url}`);
                    console.log(`[DEBUG]`, `Round trip took: ${response.headers['request-duration']}ms.`);
                    console.log(`[DEBUG]`, `Response Size: ${JSON.stringify(response.data.data).length} bytes.`);
                }

                if (response.data.status !== undefined && response.data.status === 'success') {
                    resolve(response.data.data);
                } else {
                    reject(this.apiErrorHandling({response: response}));
                }
            }).catch((error) => {
                reject(this.apiErrorHandling(error));
            });
        });
    }

    postReq(url, data, headers = null) {
        return new Promise((resolve, reject) => {
            axios.post(url, data, headers).then(response => {
                resolve(response.data);
            }).catch((error) => {
                reject(this.apiErrorHandling(error));
            });
        });
    }

    apiErrorHandling(error) {
        if (!!error) {
            let response = error.response;
            if (!!response) {
                switch (response.status) {
                    case 200:
                        const apiErrorMessage = (response.data !== undefined && response.data.data !== undefined && response.data.data.message !== undefined) ? response.data.data.message : (response.message !== undefined) ? response.message : 'No error returned from API.';
                        switch (apiErrorMessage) {
                            case 'Not permitted: user not found':
                                return '404 - Not found. Incorrect username or platform? Misconfigured privacy settings?';
                            case 'Not permitted: rate limit exceeded':
                                return '429 - Too many requests. Try again in a few minutes.';
                            case 'Error from datastore':
                                return '500 - Internal server error. Request failed, try again.';
                            default:
                                return apiErrorMessage;
                        }
                        break;
                    case 401:
                        return '401 - Unauthorized. Incorrect username or password.';
                    case 403:
                        return '403 - Forbidden. You may have been IP banned. Try again in a few minutes.';
                    case 500:
                        return '500 - Internal server error. Request failed, try again.';
                    case 502:
                        return '502 - Bad gateway. Request failed, try again.';
                    default:
                        return `We Could not get a valid reason for a failure. Status: ${response.status}`;
                }
            } else {
                return `We Could not get a valid reason for a failure. Status: ${error}`;
            }
        } else {
            return `We Could not get a valid reason for a failure.`;
        }
    }
}

module.exports = function(config = {}) {
    console.log('Constructing module...', { config });
    var module = {};
    if (config.platform == undefined) config.platform = "psn";

    // if (config.debug === 1) {
        // debug = 1;
        axios.interceptors.request.use((resp) => {
            console.debug('INTERCEPTED', resp);
            resp.headers['request-startTime'] = process.hrtime();
            return resp;
        });
        axios.interceptors.response.use((response) => {
            const start = response.config.headers['request-startTime'];
            const end = process.hrtime(start);
            const milliseconds = Math.round((end[0] * 1000) + (end[1] / 1000000));
            response.headers['request-duration'] = milliseconds;
            return response;
        });
    //}

    try {
        if (typeof config.ratelimit === "object") { 
          axios = rateLimit(axios, config.ratelimit);
        }
    } catch (Err) {
        console.warn("Could not parse ratelimit object. ignoring.");
    }

    _helpers = new helpers();

    module.platforms = {
        battle: "battle",
        steam: "steam",
        psn: "psn",
        xbl: "xbl",
        acti: "acti",
        uno: "uno",
        all: "all"
    };

    module.login = function(username, password) {
      console.log('begin login...');

      // axios.interceptors.request.use((resp) => {
      //     resp.headers['request-startTime'] = process.hrtime();
      //     return resp;
      // });
      // axios.interceptors.response.use((response) => {
      //     const start = response.config.headers['request-startTime'];
      //     const end = process.hrtime(start);
      //     const milliseconds = Math.round((end[0] * 1000) + (end[1] / 1000000));
      //     response.headers['request-duration'] = milliseconds;
      //     return response;
      // });

      return new Promise(async(resolve, reject) => {
          const cookies = {};
          axios.get("https://profile.callofduty.com/cod/login").then((response) => {

              console.log(cookieJar);

              const config = response.config;
              console.log(config.jar.toJSON().cookies);
              
              config.jar.toJSON().cookies.forEach((c) => {
                  cookies[c.key] = c.value;
              });

              console.log('cookies from jar', cookies);

              var cookie = `${Object.keys(cookies).map(name => `${name}=${cookies[name]}`).join(';')};`;
              console.log(cookie, cookies["XSRF-TOKEN"]);
      
              axios.defaults.headers.common["content-type"] = "application/x-www-form-urlencoded";
              let data = new URLSearchParams({ username: encodeURIComponent(username), password, remember_me: true, _csrf: cookies["XSRF-TOKEN"] });
              data = decodeURIComponent(data);
              console.log("about to make the request")
              axios.post('https://profile.callofduty.com/do_login', data, { headers: { 'Cookie': cookie } }).then((response) => {
                console.log(response.data);
                loggedIn = true;
                resolve("done");
            }).catch((err) => {
              console.log('error logging in', { error: err });
              if (typeof err === "string") reject(err);
              reject(err.message);
            });
          }).catch((err) => {
              console.log('error logging in', { error: err });
              if (typeof err === "string") reject(err);
              reject(err.message);
          });
          // try {
          //   console.log('begin get cookies...');
          //   if (!browser) {
          //     browser = await puppeteer.launch();
          //     // const incognitoContext = await browser.createIncognitoBrowserContext();
          //   }
          //   if (!page) {
          //     page = await browser.newPage();
          //   }

          //   console.log('actually get cookies...');
          //   await page.goto("https://profile.callofduty.com/cod/login", { waitUntil: 'networkidle2' });
          //   console.log('got cookies');

          //   const allCookies = await page._client.send('Network.getAllCookies');

          //   allCookies.cookies.forEach((c) => {
          //       cookies[c.name] = c.value;
          //   });

          //   console.log('done with getting cookies');
          // } catch (err) {
          //   console.log('error getting cookies', { error: err });
          //   if (typeof err === "string") reject(err);
          //   reject(err.message);
          // }

          //   console.log('cookies', Object.keys(cookies));

          //   loginAxios.defaults.headers.common["content-type"] = "application/x-www-form-urlencoded";
          //   let data = new URLSearchParams({ username: encodeURIComponent(username), password, remember_me: true, _csrf: cookies["XSRF-TOKEN"] });
          //   data = decodeURIComponent(data);
          //   const headers = { 'cookie': `${Object.keys(cookies).map(name => `${name}=${cookies[name]}`).join(';')}` };
          //   console.log('posting login request...');
          //   loginAxios.post('https://profile.callofduty.com/do_login', data, { headers }).then((response) => {
          //     console.log('post login response complete');
          //     apiAxios.defaults.headers.common["cookie"] = `XSRF-TOKEN=${cookies['XSRF-TOKEN']};bm_sz=${cookies["bm_sz"]};new_SiteId=cod;comid=cod;`;
          //     loggedIn = true;
          //     resolve("done");
          //   }).catch((err) => {
          //     console.log('error logging in', { error: err });
          //     if (typeof err === "string") reject(err);
          //     reject(err.message);
          // });
      });
    }

    module.BO4Stats = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/mp`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4zm = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/zm`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4mp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/mp`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4blackout = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/wz`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4friends = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") reject("Battlenet does not support Friends.");
            let urlInput = _helpers.buildUri(`leaderboards/v2/title/bo4/platform/${platform}/time/alltime/type/core/mode/career/gamer/${gamertag}/friends`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4combatmp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/mp/start/0/end/0/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4combatmpdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/mp/start/${start}/end/${end}/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4combatzm = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/zombies/start/0/end/0/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4combatzmdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/zombies/start/${start}/end/${end}/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4combatbo = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/warzone/start/0/end/0/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4combatbodate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/warzone/start/${start}/end/${end}/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.BO4leaderboard = function(page, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
            let urlInput = _helpers.buildUri(`leaderboards/v2/title/bo4/platform/${platform}/time/alltime/type/core/mode/career/page/${page}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWleaderboard = function(page, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            let urlInput = _helpers.buildUri(`leaderboards/v2/title/mw/platform/${platform}/time/alltime/type/core/mode/career/page/${page}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWcombatmp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/0/end/0/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWcombatmpdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/${start}/end/${end}/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWcombatwz = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/0/end/0/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWcombatwzdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/${start}/end/${end}/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWfullcombatmp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/0/end/0`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWfullcombatmpdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/${start}/end/${end}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWfullcombatwz = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/0/end/0`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWfullcombatwzdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/${start}/end/${end}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWmp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/mw/platform/${platform}/${lookupType}/${gamertag}/profile/type/mp`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWwz = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/mw/platform/${platform}/${lookupType}/${gamertag}/profile/type/wz`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWBattleData = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            brDetails = {};
            this.MWwz(gamertag, platform).then(data => {
                let lifetime = data.lifetime;
                if (typeof lifetime !== "undefined") {
                    let filtered = Object.keys(lifetime.mode).filter(x => x.startsWith("br")).reduce((obj, key) => {
                        obj[key] = lifetime.mode[key];
                        return obj;
                    }, {});
                    if (typeof filtered.br !== "undefined") {
                        filtered.br.properties.title = "br";
                        brDetails.br = filtered.br.properties;
                    }
                    if (typeof filtered.br_dmz !== "undefined") {
                        filtered.br_dmz.properties.title = "br_dmz";
                        brDetails.br_dmz = filtered.br_dmz.properties;
                    }
                    if (typeof filtered.br_all !== "undefined") {
                        filtered.br_all.properties.title = "br_all";
                        brDetails.br_all = filtered.br_all.properties;
                    }
                }
                resolve(brDetails);
            }).catch(e => reject(e));
        });
    };

    module.MWfriends = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            if (platform === "battle") reject(`Battlenet friends are not supported. Try a different platform.`);
            if (platform === "uno") gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/mw/platform/${platform}/${lookupType}/${gamertag}/profile/friends/type/mp`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWWzfriends = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            if (platform === "battle") reject(`Battlenet friends are not supported. Try a different platform.`);
            if (platform === "uno") gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/mw/platform/${platform}/${lookupType}/${gamertag}/profile/friends/type/wz`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWstats = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/mw/platform/${platform}/${lookupType}/${gamertag}/profile/type/mp`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };


    module.MWwzstats = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/mw/platform/${platform}/${lookupType}/${gamertag}/profile/type/wz`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWweeklystats = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            weeklyStats = {};
            this.MWstats(gamertag, platform).then((data) => {
                if (typeof data.weekly !== "undefined") weeklyStats.mp = data.weekly;
                this.MWwzstats(gamertag, platform).then((data) => {
                    if (typeof data.weekly !== "undefined") weeklyStats.wz = data.weekly;
                    resolve(weeklyStats);
                }).catch(e => reject(e));
            }).catch(e => reject(e));
        });
    };

    module.MWloot = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`loot/title/mw/platform/${platform}/${lookupType}/${gamertag}/status/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWAnalysis = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`ce/v2/title/mw/platform/${platform}/gametype/all/gamer/${gamertag}/summary/match_analysis/contentType/full/end/0/matchAnalysis/mobile/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWMapList = function(platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`ce/v1/title/mw/platform/${platform}/gameType/mp/communityMapData/availability`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWFullMatchInfomp = function(matchId, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/fullMatch/mp/${matchId}/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.MWFullMatchInfowz = function(matchId, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/fullMatch/wz/${matchId}/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    //CW
    module.CWmp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for CW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`stats/cod/v1/title/cw/platform/${platform}/${lookupType}/${gamertag}/profile/type/mp`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };
    
    module.CWloot = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`loot/title/cw/platform/${platform}/${lookupType}/${gamertag}/status/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };
    
    module.CWAnalysis = function(gamertag, platform = config.platform) {  //could be v1
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`ce/v2/title/cw/platform/${platform}/gametype/all/gamer/${gamertag}/summary/match_analysis/contentType/full/end/0/matchAnalysis/mobile/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };
    
    module.CWMapList = function(platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`ce/v1/title/cw/platform/${platform}/gameType/mp/communityMapData/availability`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.CWcombatmp = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for CW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/cw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/0/end/0/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.CWcombatdate = function(gamertag, start = 0, end = 0, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "steam") reject("Steam Doesn't exist for CW. Try `battle` instead.");
            gamertag = _helpers.cleanClientName(gamertag);let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/cw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/${start}/end/${end}/details`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };
    
    module.CWFullMatchInfo = function(matchId, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/title/cw/platform/${platform}/fullMatch/mp/${matchId}/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    //https://my.callofduty.com/api/papi-client/inventory/v1/title/cw/platform/psn/purchasable/public/en
    module.GetPurchasablePublic = function() {
        return new Promise((resolve, reject) => {
            let urlInput = _helpers.buildUri(`inventory/v1/title/cw/platform/psn/purchasable/public/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    //https://my.callofduty.com/api/papi-client/inventory/v1/title/cw/bundle/22497100/en
    module.getBundleInformation = function(title, bundleId) {
        return new Promise((resolve, reject) => {
            let urlInput = _helpers.buildUri(`inventory/v1/title/${title}/bundle/${bundleId}/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.friendFeed = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            gamertag = _helpers.cleanClientName(gamertag);
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`userfeed/v1/friendFeed/platform/${platform}/gamer/${gamertag}/friendFeedEvents/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getEventFeed = function() {
        return new Promise((resolve, reject) => {
            let urlInput = _helpers.buildUri(`userfeed/v1/friendFeed/rendered/en/${ssoCookie}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getLoggedInIdentities = function() {
        return new Promise((resolve, reject) => {
            let urlInput = _helpers.buildUri(`crm/cod/v2/identities/${ssoCookie}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getLoggedInUserInfo = function() {
        return new Promise((resolve, reject) => {
            let urlInput = _helpers.buildProfileUri(`cod/userInfo/${ssoCookie}`);
            _helpers.sendRequestUserInfoOnly(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.FuzzySearch = function(query, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "battle" || platform == "uno" || platform == "all") query = _helpers.cleanClientName(query);
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/platform/${platform}/username/${query}/search`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getBattlePassInfo = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "battle" || platform == "uno" || platform === "acti") gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`loot/title/mw/platform/${platform}/${lookupType}/${gamertag}/status/en`);
            console.log(urlInput);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getCodPoints = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`inventory/v1/title/mw/platform/${platform}/gamer/${gamertag}/currency`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getBattlePassLoot = function(season, platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`loot/title/mw/platform/${platform}/list/loot_season_${season}/en`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getPurchasable = function(platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`inventory/v1/title/mw/platform/${platform}/purchasable`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };
    
    module.purchaseItem = function(gamertag, item = "battle_pass_upgrade_bundle_4", platform = config.platform) {
        return new Promise((resolve, reject) => {
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`inventory/v1/title/mw/platform/${platform}/gamer/${gamertag}/item/${item}/purchaseWith/CODPoints`);
            _helpers.sendPostRequest(urlInput, {}).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.getGiftableFriends = function(unoId, itemSku = "432000") {
        return new Promise((resolve, reject) => {
            let urlInput = _helpers.buildUri(`gifting/v1/title/mw/platform/uno/${unoId}/sku/${itemSku}/giftableFriends`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.sendGift = function(gamertag, recipientUnoId, senderUnoId, itemSku = "432000", sendingPlatform = config.platform, platform = config.platform) {
        return new Promise((resolve, reject) => {
            let data = {
                recipientUnoId: recipientUnoId,
                senderUnoId: senderUnoId,
                sendingPlatform: sendingPlatform,
                sku: Number(itemSku)
            };
            gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`gifting/v1/title/mw/platform/${platform}/gamer/${gamertag}`);
            _helpers.sendPostRequest(urlInput, data).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.ConnectedAccounts = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            gamertag = _helpers.cleanClientName(gamertag);
            let lookupType = "gamer";
            if (platform === "uno") lookupType = "id";
            if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
            let urlInput = _helpers.buildUri(`crm/cod/v2/accounts/platform/${platform}/${lookupType}/${gamertag}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.Presence = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`crm/cod/v2/friends/platform/${platform}/gamer/${gamertag}/presence/1/${ssoCookie}`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };

    module.Settings = function(gamertag, platform = config.platform) {
        return new Promise((resolve, reject) => {
            gamertag = _helpers.cleanClientName(gamertag);
            let urlInput = _helpers.buildUri(`preferences/v1/platform/${platform}/gamer/${gamertag}/list`);
            _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
        });
    };
    
    module.isLoggedIn = function() {
        return loggedIn;
    };

    return module;
};