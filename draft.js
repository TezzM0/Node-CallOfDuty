const axios = require('axios');
const axiosCookieJarSupport = require('axios-cookiejar-support').default;
const tough = require('tough-cookie');
const rateLimit = require('axios-rate-limit');
const puppeteer = require('puppeteer');
require("dotenv").config();
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
let baseCookie = "new_SiteId=cod; ACT_SSO_LOCALE=en_US;country=US;";
let ssoCookie;  // TODO: Not sure where to get this from now
let loggedIn = false;
let debug = 0;
let axiosTimeout = parseInt(process.env.AXIOS_TIMEOUT) || 20000;
let apiAxios = axios.create({
  headers: {
    common: {
      "Content-Type": "application/json",
      "cookie": baseCookie,
      "User-Agent": userAgent,
      "x-requested-with": userAgent,
      "Accept": "application/json",
      "Accept-Language": "en-AU,en;q=0.9,en-US;q=0.8",
      "Connection": "keep-alive",

    },
  },
  withCredentials: true,
  timeout: axiosTimeout,
});
axiosCookieJarSupport(apiAxios);

let loginAxios = axios.create({
  headers: {
    common: {
      "Content-Type": "application/x-www-form-urlencoded",
      // "cookie": baseCookie,
      "User-Agent": userAgent,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Accept-Language": "en-AU,en;q=0.9,en-US;q=0.8",
      "Connection": "keep-alive",
      "Cache-Control": "max-age=0",
      "Host": "profile.callofduty.com",
      "Origin": "https://profile.callofduty.com",
      "sec-ch-ua": '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
      "sec-ch-ua-mobile": "?0",
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "same-origin",
      "Sec-Fetch-User": "?1",
      "Upgrade-Insecure-Requests": "1",
},
  },
  withCredentials: true,
  timeout: axiosTimeout,
  // proxy: {
  //   host: 'localhost',
  //   port: 8888
  // }
});
axiosCookieJarSupport(loginAxios);

let browser;
let incognitoContext;
let puppeteerPage;
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

  isJson(str) {
    try {
      JSON.parse(str);
    } catch (e) {
      return false;
    }
    return true;
  }

  sendRequestUserInfoOnly(url) {
    return new Promise((resolve, reject) => {
      if (!loggedIn) reject("Not Logged In.");
      apiAxios.get(url).then(body => {
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
      apiAxios.get(url).then(response => {
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

  sendPuppeteerRequest(url) {
    return new Promise(async (resolve, reject) => {
      if (!loggedIn) reject("Not Logged In.");
      const httpResponse = await puppeteerPage.goto(url,{waitUntil: 'networkidle2'});

      let jsonResponse = await puppeteerPage.evaluate(() => document.body.innerText);
      let response = {};
      if(!this.isJson(jsonResponse)){
        reject(this.apiErrorHandling({response: response}));
      }
      response.data = JSON.parse(jsonResponse); // Set up structure so other code works
      try {
        if (debug === 1) {
          console.log(`[DEBUG]`, `Build URI: ${url}`);
          console.log(`[DEBUG]`, `Response Size: ${JSON.stringify(response.data.data).length} bytes.`);
        }

        if (response.data.status !== undefined && response.data.status === 'success') {
          resolve(response.data.data);
        } else {
          if (httpResponse.status()) response.status = httpResponse.status();
          reject(this.apiErrorHandling({response: response}));
        }
      } catch(error) {
        if (!error.response) error.response = {};
        if (httpResponse.status()) error.response.status = httpResponse.status();
        if (response.data) error.response.data = response.data;
        reject(this.apiErrorHandling(error));
      }
    });
  }

  sendPostRequest(url, data) {
    return new Promise((resolve, reject) => {
      if (!loggedIn) reject("Not Logged In.");
      apiAxios.post(url, JSON.stringify(data)).then(response => {
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
      loginAxios.post(url, data, headers).then(response => {
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
              case 'Not permitted: not authenticated':
                return '403 - Forbidden. Not authenticated. You may have been IP banned. Try again in a few minutes.';
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

module.exports = function (config = {}) {
  var module = {};
  if (config.platform == undefined) config.platform = "psn";

  if (config.debug === 1) {
    debug = 1;
    // apiAxios.interceptors.request.use((resp) => {
    //   resp.headers['request-startTime'] = process.hrtime();
    //   return resp;
    // });
    // apiAxios.interceptors.response.use((response) => {
    //   const start = response.config.headers['request-startTime'];
    //   const end = process.hrtime(start);
    //   const milliseconds = Math.round((end[0] * 1000) + (end[1] / 1000000));
    //   response.headers['request-duration'] = milliseconds;
    //   return response;
    // });
  }

  try {
    if (typeof config.ratelimit === "object") apiAxios = rateLimit(apiAxios, config.ratelimit);
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

  module.logout = async function () {
    if (!puppeteerPage) {
      return;
    }

    try {
      console.log("Logging out...");
      await puppeteerPage.goto(`https://profile.callofduty.com/do_logout?${Date.now()}`, {waitUntil: 'networkidle2'});
    } catch (error) {
      console.log("Unable to log out", { error })
    } finally {
      if (!!puppeteerPage) {
        try {
          await puppeteerPage.close();
        } catch (innerError) {
          console.log('Unable to close page', { error: innerError });
        } finally {
          puppeteerPage = undefined;
        }
      }

      if (!!incognitoContext) {
        try {
          await incognitoContext.close();
        } catch (innerError) {
          console.log('Unable to close incognito context', { error: innerError });
        } finally {
          incognitoContext = undefined;
        }
      }

      if (!!browser) {
        try {
          await browser.close();
        } catch (innerError) {
          console.log('Unable to close browser', { error: innerError });
        } finally {
          browser = undefined;
        }
      }
    }
  }

  module.login = function (username, password) {

    // loginAxios.interceptors.request.use((resp) => {
    //   resp.headers['request-startTime'] = process.hrtime();
    //   return resp;
    // });
    // loginAxios.interceptors.response.use((response) => {
    //   const start = response.config.headers['request-startTime'];
    //   const end = process.hrtime(start);
    //   const milliseconds = Math.round((end[0] * 1000) + (end[1] / 1000000));
    //   response.headers['request-duration'] = milliseconds;
    //   return response;
    // });

    const sharedCookieJar = new tough.CookieJar();
    apiAxios.defaults.jar = sharedCookieJar;
    loginAxios.defaults.jar = sharedCookieJar;

    return new Promise(async (resolve, reject) => {
      const cookies = {};
      try {
        const puppeteerOptions = {
          // args: [ '--proxy-server=http://localhost:8888' ]
        }
        browser = await puppeteer.launch(puppeteerOptions);
        incognitoContext = await browser.createIncognitoBrowserContext();
        puppeteerPage = await incognitoContext.newPage();
        await puppeteerPage.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');

        await puppeteerPage.goto("https://profile.callofduty.com/cod/login", {waitUntil: 'networkidle2'});

        const randomness = Math.floor(Math.random() * 501);
        await new Promise(e => setTimeout(e, 500 + randomness));

        // Add fixed header and cookie interceptor
        await puppeteerPage.setRequestInterception(true)
        await puppeteerPage.on('request', (req) => {
          if (!req.isNavigationRequest()) {
            req.continue()
            return
          }

          const headers = req.headers()
          headers['Cookie'] = headers['Cookie'] + ';' + `API_CSRF_TOKEN=3844e7b2-ac07-4c97-8c72-0fa9f43fdd26;`;
          headers['X-CSRF-TOKEN'] = '3844e7b2-ac07-4c97-8c72-0fa9f43fdd26';
          req.continue({ ...headers });
        });
        // Enter username
        await puppeteerPage.evaluate( () => document.getElementById("username").value = "")
        await puppeteerPage.type('#username', username);
        // Enter password
        await puppeteerPage.evaluate( () => document.getElementById("password").value = "")
        await puppeteerPage.type('#password', password);
        // Submit
        await puppeteerPage.click('#login-button');

        // const form = await page.$('frmLogin');
        // await form.evaluate(form => form.submit());

        const loginResponse = await puppeteerPage.waitForNavigation();
        const pageStatus = loginResponse.status();
        console.log('New Page URL:', puppeteerPage.url());


        const allCookies = await puppeteerPage._client.send('Network.getAllCookies');

        allCookies.cookies.forEach((browserCookie) => {
          cookies[browserCookie.name] = browserCookie.value;
          if (browserCookie.domain.includes('.callofduty.com')) {
            const cookie = new tough.Cookie({
              key: browserCookie.name,
              value: browserCookie.value,
              expires: browserCookie.expires && browserCookie.expires !== -1 ? new Date(browserCookie.expires) : Infinity,
              // maxAge: null,
              domain: browserCookie.domain,
              path: browserCookie.path,
              secure: browserCookie.secure,
              httpOnly: browserCookie.httpOnly,
              // extensions: null,
              // // set by the CookieJar:
              // hostOnly: null,
              // pathIsDefault: null,
              // creation: null,
              // lastAccessed: null,
              sameSite: browserCookie.sameSite
            });
            sharedCookieJar.setCookie(cookie, 'https://profile.callofduty.com');
          }
        });
      } catch (err) {
        if (typeof err === "string") reject(err);
        reject(err.message);
      }
      loggedIn = true;
      resolve("done");

      // let data = new URLSearchParams({
      //   username: encodeURIComponent(username),
      //   password,
      //   remember_me: true,
      //   _csrf: cookies["XSRF-TOKEN"]
      // });
      // data = decodeURIComponent(data);
      // // const headers = { 'cookie': `${Object.keys(cookies).map(name => `${name}=${cookies[name]}`).join(';')}` };
      // const headers = {
      //   'Host': 'profile.callofduty.com',
      //   'Origin': 'https://profile.callofduty.com',
      //   'Referer': 'https://profile.callofduty.com/cod/login?redirectUrl=https%3A%2F%2Fwww.callofduty.com%2Fau%2Fen%2F'
      // };
      // loginAxios.post('https://profile.callofduty.com/do_login?new_SiteId=cod', data, {headers}).then((response) => {
      //   apiAxios.defaults.headers.common['x-activision-regioncode'] = response.headers['x-activision-regioncode'];
      //   loggedIn = true;
      //   resolve("done");
      // }).catch((err) => {
      //   if (typeof err === "string") reject(err);
      //   reject(err.message);
      // });
    });
  }

  module.BO4Stats = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/mp`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4zm = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/zm`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4mp = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/mp`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4blackout = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/profile/type/wz`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4friends = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") reject("Battlenet does not support Friends.");
      let urlInput = _helpers.buildUri(`leaderboards/v2/title/bo4/platform/${platform}/time/alltime/type/core/mode/career/gamer/${gamertag}/friends`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4combatmp = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/mp/start/0/end/0/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4combatmpdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/mp/start/${start}/end/${end}/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4combatzm = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/zombies/start/0/end/0/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4combatzmdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/zombies/start/${start}/end/${end}/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4combatbo = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/warzone/start/0/end/0/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4combatbodate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      if (platform === "battle") gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/bo4/platform/${platform}/gamer/${gamertag}/matches/warzone/start/${start}/end/${end}/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.BO4leaderboard = function (page, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for BO4. Try `battle` instead.");
      let urlInput = _helpers.buildUri(`leaderboards/v2/title/bo4/platform/${platform}/time/alltime/type/core/mode/career/page/${page}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWleaderboard = function (page, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      let urlInput = _helpers.buildUri(`leaderboards/v2/title/mw/platform/${platform}/time/alltime/type/core/mode/career/page/${page}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWcombatmp = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/0/end/0/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWcombatmpdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/${start}/end/${end}/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWcombatwz = function (gamertag, platform = config.platform) {
    return new Promise(async (resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/0/end/0/details`);
      _helpers.sendPuppeteerRequest(urlInput)
        .then(data => resolve(data))
        .catch(sendPuppeteerRequestError => {
          console.log('Error in MWcombatwz.sendPuppeteerRequest', sendPuppeteerRequestError);
          reject(sendPuppeteerRequestError)
        }
        );
      // _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWcombatwzdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/${start}/end/${end}/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWfullcombatmp = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/0/end/0`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWfullcombatmpdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/${start}/end/${end}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWfullcombatwz = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/0/end/0`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWfullcombatwzdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/${lookupType}/${gamertag}/matches/wz/start/${start}/end/${end}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWmp = function (gamertag, platform = config.platform) {
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

  module.MWwz = function (gamertag, platform = config.platform) {
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

  module.MWBattleData = function (gamertag, platform = config.platform) {
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

  module.MWfriends = function (gamertag, platform = config.platform) {
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

  module.MWWzfriends = function (gamertag, platform = config.platform) {
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

  module.MWstats = function (gamertag, platform = config.platform) {
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


  module.MWwzstats = function (gamertag, platform = config.platform) {
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

  module.MWweeklystats = function (gamertag, platform = config.platform) {
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

  module.MWloot = function (gamertag, platform = config.platform) {
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

  module.MWAnalysis = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`ce/v2/title/mw/platform/${platform}/gametype/all/gamer/${gamertag}/summary/match_analysis/contentType/full/end/0/matchAnalysis/mobile/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWMapList = function (platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`ce/v1/title/mw/platform/${platform}/gameType/mp/communityMapData/availability`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWFullMatchInfomp = function (matchId, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/fullMatch/mp/${matchId}/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.MWFullMatchInfowz = function (matchId, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/mw/platform/${platform}/fullMatch/wz/${matchId}/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  //CW
  module.CWmp = function (gamertag, platform = config.platform) {
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

  module.CWloot = function (gamertag, platform = config.platform) {
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

  module.CWAnalysis = function (gamertag, platform = config.platform) {  //could be v1
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for MW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`ce/v2/title/cw/platform/${platform}/gametype/all/gamer/${gamertag}/summary/match_analysis/contentType/full/end/0/matchAnalysis/mobile/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.CWMapList = function (platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`ce/v1/title/cw/platform/${platform}/gameType/mp/communityMapData/availability`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.CWcombatmp = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for CW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/cw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/0/end/0/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.CWcombatdate = function (gamertag, start = 0, end = 0, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "steam") reject("Steam Doesn't exist for CW. Try `battle` instead.");
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/cw/platform/${platform}/${lookupType}/${gamertag}/matches/mp/start/${start}/end/${end}/details`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.CWFullMatchInfo = function (matchId, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/title/cw/platform/${platform}/fullMatch/mp/${matchId}/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  //https://my.callofduty.com/api/papi-client/inventory/v1/title/cw/platform/psn/purchasable/public/en
  module.GetPurchasablePublic = function () {
    return new Promise((resolve, reject) => {
      let urlInput = _helpers.buildUri(`inventory/v1/title/cw/platform/psn/purchasable/public/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  //https://my.callofduty.com/api/papi-client/inventory/v1/title/cw/bundle/22497100/en
  module.getBundleInformation = function (title, bundleId) {
    return new Promise((resolve, reject) => {
      let urlInput = _helpers.buildUri(`inventory/v1/title/${title}/bundle/${bundleId}/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.friendFeed = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      gamertag = _helpers.cleanClientName(gamertag);
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`userfeed/v1/friendFeed/platform/${platform}/gamer/${gamertag}/friendFeedEvents/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getEventFeed = function () {
    return new Promise((resolve, reject) => {
      let urlInput = _helpers.buildUri(`userfeed/v1/friendFeed/rendered/en/${ssoCookie}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getLoggedInIdentities = function () {
    return new Promise((resolve, reject) => {
      let urlInput = _helpers.buildUri(`crm/cod/v2/identities/${ssoCookie}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getLoggedInUserInfo = function () {
    return new Promise((resolve, reject) => {
      let urlInput = _helpers.buildProfileUri(`cod/userInfo/${ssoCookie}`);
      _helpers.sendRequestUserInfoOnly(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.FuzzySearch = function (query, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "battle" || platform == "uno" || platform == "all") query = _helpers.cleanClientName(query);
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/platform/${platform}/username/${query}/search`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getBattlePassInfo = function (gamertag, platform = config.platform) {
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

  module.getCodPoints = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`inventory/v1/title/mw/platform/${platform}/gamer/${gamertag}/currency`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getBattlePassLoot = function (season, platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`loot/title/mw/platform/${platform}/list/loot_season_${season}/en`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getPurchasable = function (platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`inventory/v1/title/mw/platform/${platform}/purchasable`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.purchaseItem = function (gamertag, item = "battle_pass_upgrade_bundle_4", platform = config.platform) {
    return new Promise((resolve, reject) => {
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`inventory/v1/title/mw/platform/${platform}/gamer/${gamertag}/item/${item}/purchaseWith/CODPoints`);
      _helpers.sendPostRequest(urlInput, {}).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.getGiftableFriends = function (unoId, itemSku = "432000") {
    return new Promise((resolve, reject) => {
      let urlInput = _helpers.buildUri(`gifting/v1/title/mw/platform/uno/${unoId}/sku/${itemSku}/giftableFriends`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.sendGift = function (gamertag, recipientUnoId, senderUnoId, itemSku = "432000", sendingPlatform = config.platform, platform = config.platform) {
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

  module.ConnectedAccounts = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      gamertag = _helpers.cleanClientName(gamertag);
      let lookupType = "gamer";
      if (platform === "uno") lookupType = "id";
      if (platform === "uno" || platform === "acti") platform = this.platforms["uno"];
      let urlInput = _helpers.buildUri(`crm/cod/v2/accounts/platform/${platform}/${lookupType}/${gamertag}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.Presence = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`crm/cod/v2/friends/platform/${platform}/gamer/${gamertag}/presence/1/${ssoCookie}`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.Settings = function (gamertag, platform = config.platform) {
    return new Promise((resolve, reject) => {
      gamertag = _helpers.cleanClientName(gamertag);
      let urlInput = _helpers.buildUri(`preferences/v1/platform/${platform}/gamer/${gamertag}/list`);
      _helpers.sendRequest(urlInput).then(data => resolve(data)).catch(e => reject(e));
    });
  };

  module.isLoggedIn = function () {
    return loggedIn;
  };

  module.apiAxios = apiAxios;

  return module;
};
