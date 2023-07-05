/*
 ****************************************************
 * 
 * Javascript to enable SSO and ZSO on APPLE Phase1
 *
 ***************************************************
 *
 */
var deviceToken;
var endpoints;
var lightHouseURL = "http://tv.proximus.be/api/public/lighthouse/environments/signaltypes/signal_type_type?signal=signal_signal";
var signal_type = "APPLE_USER_TOKEN"; //Lighthouse signalType
var realm = "apple-tv";
//Staging Configs
var redirect_uriStaging = "https://www.getpostman.com/oauth2/callback";
var cliendIdStaging = "2e4a533e6433cf467331d8d007af8cfe";
var cookieStartStaging = "tiamsid_uat=";
var appSubscriptionBundleIDStaging = "be.proximus.proximustv-debug";
//Prod Configs
var redirect_uriProd = "https://tv-proximus.be/apple/redirect";
var cliendIdProd = "2e4a533e6433cf467331d8d007af8cfe";
var cookieStartProd = "tiamsid=";
var appSubscriptionBundleIDProd = "be.proximus.proximustv";

//ERRORS
var ERROR_NO_TOKENID_FOUND = "There was an error retrieving the TokenID!";
var ERROR_GENERIC = "There was an Error!";
var ERROR_LOGIN_FAIL = "Username or password incorrect";

//Logging function
function logToServer(output) {
    /*
        var hostname = "http://13fdb2e2.ngrok.io";
        var url = hostname + "/api/logs/";
    
        var data = JSON.stringify({
            "output": output
        });
        var xhr = new XMLHttpRequest();
        xhr.withCredentials = false;
    
        xhr.open("POST", url);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(data);
    */
}

function loadVariables(env, baseURL) {
    var endpoints = {};
    if (typeof env != 'undefined' && env != null) {
        endpoints.environment = env;
    } else {
        endpoints.environment = "PRODUCTION";
    }
    if (typeof baseURL != 'undefined' && baseURL != null) {
        endpoints.baseURL = baseURL;
    } else {
        endpoints.baseURL = "https://tv.proximus.be";
    }

    endpoints.loginURL = endpoints.baseURL + "/apple/authentication";
    endpoints.loginByIpURL = endpoints.baseURL + "/apple/zso";
    endpoints.logoutURL = endpoints.baseURL + "/sessions/?_action=logout";
    endpoints.auhtorizeURL = endpoints.baseURL + "/apple/oauth2/authorize";
    endpoints.acccessTokenURL = endpoints.baseURL + "/apple/oauth2/access_token";
    return endpoints;
}

/*
* Generate the Subscription for PixxApp to be sent on the ResponsePalyload
*/
function pixxAppSubscription() {
    var subscription = new App.Subscription();
    subscription.accessLevel = 1;
    if (endpoints.environment == 'STAGING') {
        subscription.bundleId = appSubscriptionBundleIDStaging;
    } else {
        subscription.bundleId = appSubscriptionBundleIDProd;
    }

    return subscription;
}

/*
* Function to get the URL to used.
*/
function getURLFromLightHouse(options, callback) {
    var signal, pxtv_version, xhr;

    signal = deviceToken; //signal="apple-tv-signal-test";
    logToServer("CALL: getURLFromLightHouse LH SIGNAL: " + signal);
    pxtv_version = "appleTV/-/appleTV/-/-";//format: {PxTV client product}/{PxTV client version}/{platform-os}/{devicetype}/OSversion | "STB/V100R001C00B139/STB/V6/-"

    if (typeof signal === 'undefined' || signal === null || signal === '') {
        try {
            signal = JSON.parse(options.request.currentAuthentication).gid;

        } catch (ex) {
            signal = getActiveDocument().getElementById("username").getFeature("Keyboard").text;
        }
    }

    logToServer("CALL: getURLFromLightHouse LH SIGNAL V2 = " + signal);

    var lightHouseResponse = function (responseObject, options, callback) {
        var env, baseURL;
        if (typeof responseObject != 'undefined' && responseObject != null) {
            env = responseObject[0].name;
            baseURL = responseObject[0].auth_base_url;
        }
        endpoints = loadVariables(env, baseURL);
        // options.callback(true, null);

        logToServer("CALL: getURLFromLightHouse END | baseURL = " + baseURL + " | env = " + env + " | options = " + JSON.stringify(options));
        callback(options, false);
    };

    logToServer("CALL: getURLFromLightHouse START");

    xhr = new XMLHttpRequest();
    xhr.open('GET', lightHouseURL.replace("signal_type_type", signal_type).replace("signal_signal", signal), false);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.setRequestHeader("X-PXTV-VERSION", pxtv_version);
    xhr.addEventListener("timeout", function () { lightHouseResponse(null, options, callback); });
    xhr.addEventListener("error", function () { lightHouseResponse(null, options, callback); });
    xhr.addEventListener("abort", function () { lightHouseResponse(null, options, callback); });
    xhr.addEventListener("load", function () {
        if (xhr.readyState === 4) {
            var responseObject = JSON.parse(xhr.response);
            lightHouseResponse(responseObject, options, callback);
        }
    });
    xhr.send(null);
}

/*
 * Create ResponsePayload or Error object and send result to callback
 */
function generateResponseOK(responseObject, options) {
    var responsePayload;
    responsePayload = new App.ResponsePayload();

    try {
        if (options.request.requestType == "logout") {
            responsePayload.logout = responseObject;
        } else if (options.request.requestType == "userMetadata") {
            responseObject.base_url = endpoints.baseURL;
            responseObject.env = endpoints.environment;
            responseObject.realm = '/' + realm;
            responseObject.access_token = responseObject.access_token + ':' + realm;
            responsePayload.userMetadata = JSON.stringify(responseObject);
            responsePayload.subscriptions = [pixxAppSubscription()];
            var aux = JSON.parse(options.request.currentAuthentication);
            aux.accessToken = {};
            aux.accessToken = responseObject;
            responsePayload.authN = JSON.stringify(aux);
            responsePayload.expirationDate = aux.expirationDate;

            logToServer("CALL: generateResponseOK TYPE = userMetadata | RESPONSE OBJ = " + JSON.stringify(responseObject) + " | expiry date = " + aux.expirationDate + " | tokenID = " + aux.tokenId);
        } else { // UIAuthN and AuthN
            // var expirationDate = (new Date()).setSeconds((new Date()).getSeconds() + 3); //set expiration date 3Months from now 
            var expirationDate = (new Date()).setMonth((new Date()).getMonth() + 3); //set expiration date 3Months from now 
            responseObject.expirationDate = expirationDate;
            responsePayload.authN = JSON.stringify(responseObject);
            responsePayload.username = responseObject.username;
            responsePayload.expirationDate = expirationDate;
            responsePayload.subscriptions = [pixxAppSubscription()];

            logToServer("CALL: generateResponseOK TYPE = OTHER | RESPONSE OBJ = " + JSON.stringify(responseObject) + " | expiry date = " + expirationDate + " | tokenID = " + responseObject.tokenId);
        }

        responsePayload.authenticationScheme = "API";
        responsePayload.statusCode = "200";
        responsePayload.expectedAction = 1;

        logToServer("CALL: generateResponseOK = " + JSON.stringify(options) + " | PAYLOAD = " + JSON.stringify(responseObject));

        options.callback(responsePayload, null);

    } catch (ex) {
        logToServer("CALL: generateResponseOK Exception: " + ex);
        generateResponseNOK(options, 4, ERROR_GENERIC + '(code: 6)', null, false);
    }
}

/*
 * Will be execute if the authication endpoint return an error
 */
function generateResponseNOK(options, errorCode, errorMsg, statusCode, showUI) {
    var error, responsePayload;
    responsePayload = null;
    error = new Error();
    error.code = errorCode;
    error.message = errorMsg;
    if (showUI || (options.request.requestType == "userMetadata" && statusCode == 401)) {
        responsePayload = new App.ResponsePayload();
        responsePayload.statusCode = statusCode != null ? statusCode : "401";
        responsePayload.authenticationScheme = "API";
        responsePayload.expectedAction = 2;

        logToServer("CALL: generateResponseNOT OK | Endpoint return error = " + responsePayload.statusCode);
    }

    logToServer("CALL: generateResponseNOT OK = " + JSON.stringify(options) + " | PAYLOAD = " + JSON.stringify(responsePayload) + " | ERROR = " + errorMsg);

    options.callback(responsePayload, error);

}

/**
 * Generate random string for Code challenge for OAUTH PKCE flow
 */
function generateRandomString(length) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < length; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}

/*
 * XML Authentication Context 
 */
function showAuthenticationContext() {

    logToServer("CALL: showAuthenticationContext")

    var parser = new DOMParser();
    var xmlString = '<document>' +
        '<authenticationTemplate>' +
        // '<img srcset="https://www.proximus.be/dam/jcr:5411f90f-ae6e-4d87-a4c9-583a7f2e4e47/cdn/brand/logos/proximus~2017-08-29-13-57-34~cache.png" height="" width=""/>' +
        '<img srcset="https://www.proximus.be/dam/cdn/sites/pickx/assets-0.3.3-login-sso-logo-appletv-2020-05-13/logo-pickx-horizontal--3x.png 4k, https://www.proximus.be/dam/cdn/sites/pickx/assets-0.3.3-login-sso-logo-appletv-2020-05-13/logo-pickx-horizontal--2x.png 1080h, https://www.proximus.be/dam/cdn/sites/pickx/assets-0.3.2-login-sso-logo-iPhone-2020-05-13/logo-pickx-horizontal--2x.png 2x, https://www.proximus.be/dam/cdn/sites/pickx/assets-0.3.2-login-sso-logo-iPhone-2020-05-13/logo-pickx-horizontal--3x.png 3x" height="" width=""/>' +
        '<textFieldGroup>' +
        '<textField id="username" type="emailAddress" label="UserName">Username</textField>' +
        '<textField id="password" secure="true" label="Password">Password</textField>' +
        '</textFieldGroup>' +
        '<displayLink src="https://www.proximus.be/forgotpassword" label="Forgot my password"/>' +
        '</authenticationTemplate>' +
        '</document>';
    var xmlDocument = parser.parseFromString(xmlString, 'application/xml');
    return xmlDocument;
}

/*
 * Initicialize Default XML request
 */
function inicializeXMLRequest(credentials, options, showUI, errorMsg) {
    var xhr = new XMLHttpRequest();
    xhr.withCredentials = credentials;
    xhr.addEventListener("timeout", function () {
        generateResponseNOK(options, 4, 'Timeout. ' + ERROR_GENERIC, xhr.status, showUI);
    });

    xhr.addEventListener("error", function () {
        generateResponseNOK(options, 4, errorMsg != null ? errorMsg : ERROR_GENERIC, xhr.status, showUI);
    });

    xhr.addEventListener("abort", function () {
        generateResponseNOK(options, 4, ERROR_GENERIC, xhr.status, showUI);
    });

    return xhr;
}

function loginWithCreds(options, userCred, showUI = false) {
    var xhr = inicializeXMLRequest(true, options, false, ERROR_LOGIN_FAIL);

    //ResponseEvents
    xhr.addEventListener("load", function () {
        if (xhr.readyState === 4) {
            if (xhr.status == 200) {
                var responseObject = JSON.parse(xhr.response);
                responseObject.username = userCred.username;
                responseObject.password = userCred.password;

                logToServer("CALL: loginWithCreds FINAL RESP = " + JSON.stringify(responseObject));

                generateResponseOK(responseObject, options);
            } else {
                generateResponseNOK(options, 1, ERROR_LOGIN_FAIL, xhr.status, showUI);
            }
        }
    });

    xhr.open("POST", endpoints.loginURL, false);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.setRequestHeader("X-OpenAM-Username", userCred.username);
    xhr.setRequestHeader("X-OpenAM-Password", userCred.password);
    xhr.setRequestHeader("Accept-API-Version", "resource=2.0, protocol=1.0");
    xhr.send(null);
}


function pickxRefreshToken(options, clientID, refreshToken) {

    logToServer("CALL: pickxRefreshToken = " + JSON.stringify(options) + " | clientID = " + clientID + " | refreshToken = " + refreshToken);

    var xhr, data;
    xhr = inicializeXMLRequest(true, options, false, null);
    data = 'grant_type=refresh_token' +
        '&client_id=' + clientID +
        '&refresh_token=' + refreshToken;

    xhr.open('POST', endpoints.acccessTokenURL, false);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.addEventListener("load", function () {
        if (xhr.readyState === 4) {
            //Saving response on Metadata to send to APP
            if (xhr.status === 200) {
                var finalResponse = JSON.parse(xhr.response);

                logToServer("CALL: pickxRefreshToken FINAL RESP = " + JSON.stringify(finalResponse));

                generateResponseOK(finalResponse, options);
            } else {
                logToServer("CALL: pickxRefreshToken = Error refreshing Token");
                // generateResponseNOK(options, 4, ERROR_GENERIC, xhr.status, true);
                authenticationFlow(options, true);
            }

        }
    });

    logToServer("CALL: pickxRefreshToken CALL START | ENDPOINT = " + endpoints.acccessTokenURL + " | data = " + data);

    xhr.send(data);
}

/*
* Main function
* Will decide the flow based on the requestType
*/
function authenticationFlow(options, skipRefreshToken) {

    logToServer("CALL: authenticationFlow | requestType = " + options.request.requestType + " | options = " + JSON.stringify(options) + " | skipRefreshToken = " + skipRefreshToken)

    var xhr;
    //SSO 
    if (options.request.requestType == "UIAuthN") {
        logToServer("Type: UIAuthN" + endpoints.loginURL);
        var userCred;
        userCred = {};
        userCred.username = getActiveDocument().getElementById("username").getFeature("Keyboard").text;
        userCred.password = getActiveDocument().getElementById("password").getFeature("Keyboard").text;
        loginWithCreds(options, userCred);
    } else if (options.request.requestType == "authN") {
        // ZSO ->  AM Module Authentication
        // Also called when UIAuthN authentication expires
        logToServer("Type: authN");

        const requestCurrentAuthentication = options.request.currentAuthentication;

        // CurrentAuthentication is only null for ZSO.
        if (requestCurrentAuthentication != null) {
            const currentAuthentication = JSON.parse(requestCurrentAuthentication);
            const username = currentAuthentication.username;
            const password = currentAuthentication.password;

            logToServer("CALL: authN IS re-authentication request (EXPIRED)");

            if (username != null && password != null) {
                logToServer("CALL: authN IS EXPIRED! WILL REFRESH FOR | TOKENID = " + currentAuthentication.tokenId);

                let userCred = {};
                userCred.username = username;
                userCred.password = password;

                // Perform re-authentication
                loginWithCreds(options, userCred, true);

                logToServer("CALL: authN EXP IS REFRESHED");
            } else {
                // Show error and default to prompt the user for credentials
                generateResponseNOK(options, 1, ERROR_LOGIN_FAIL, null, true);

                logToServer("CALL: authN EXP IS EXPIRED Error! Username or Password not found!");
            }

            return;
        }

        logToServer("CALL: authN ZSO request");

        xhr = inicializeXMLRequest(true, options, true, null);
        //ResponseEvents  
        xhr.addEventListener("load", function () {
            if (xhr.readyState === 4) {
                if (xhr.status == 200) {
                    var responseObject = JSON.parse(xhr.response);
                    responseObject.username = responseObject.gid;
                    generateResponseOK(responseObject, options);
                } else {
                    generateResponseNOK(options, 1, ERROR_LOGIN_FAIL, xhr.status, true);
                }
            }
        });
        //Will use IP Adress to authenticate 
        xhr.open("POST", endpoints.loginByIpURL, false);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("Accept-API-Version", "resource=2.0, protocol=1.0");
        xhr.send(null);
    } else if (options.request.requestType == "userMetadata") {
        //Pickx ->  Pickx Authentication 
        logToServer("Type: userMetadata");

        var data, code_challenge, redirect_uri, clientId, currentAuthentication, token, cookie, scopes;
        currentAuthentication = JSON.parse(options.request.currentAuthentication);

        if (typeof currentAuthentication == 'undefined' || typeof currentAuthentication.tokenId == 'undefined') {
            generateResponseNOK(options, 2, ERROR_NO_TOKENID_FOUND + '(code: 1)', null, true);
            return;
        }

        token = currentAuthentication.tokenId;

        logToServer("CALL: userMetadata = " + JSON.stringify(options) + " | currentAuthentication = " + JSON.stringify(currentAuthentication));

        if (endpoints.environment == 'STAGING') {
            clientId = cliendIdStaging;
            cookie = cookieStartStaging + token;
            redirect_uri = redirect_uriStaging;
        } else {
            clientId = cliendIdProd;
            cookie = cookieStartProd + token;
            redirect_uri = redirect_uriProd;
        }

        if (skipRefreshToken == false && typeof currentAuthentication.accessToken != 'undefined' && typeof currentAuthentication.accessToken.refresh_token != 'undefined') {
            try {
                pickxRefreshToken(options, clientId, currentAuthentication.accessToken.refresh_token);

            } catch (ex) {

                logToServer("Exception: " + ex);
            }
        } else {
            scopes = "metadata pxtv_avr pxtv_broker_csc pxtv_broker_bta pxtv_push pxtv_replay";
 
            xhr = inicializeXMLRequest(true, options, false, null);

            code_challenge = generateRandomString(50);
            data = 'redirect_uri=' + redirect_uri +
                '&scope=' + scopes +
                '&response_type=code&client_id=' + clientId +
                '&decision=allow&code_challenge_method=plain&code_challenge=' + code_challenge +
                '&csrf=' + token;

            //Override Response event
            xhr.addEventListener("load", function () {
                var responseJson, location, code, xhr2, params;
                if (xhr.readyState === 4) {

                    if (xhr.status == 200) {
                        //getting acccess token
                        responseJson = JSON.parse(xhr.response);
                        location = responseJson.location;
                        code = location.match("code=(.*)&iss=");
                        xhr2 = inicializeXMLRequest(true, options, false, null);
                        try {
                            params = 'grant_type=authorization_code&redirect_uri=' + redirect_uri +
                                '&client_id=' + clientId +
                                '&code_verifier=' + code_challenge +
                                '&code=' + code[1];
                        } catch (ex) {
                            generateResponseNOK(options, 4, ERROR_NO_TOKENID_FOUND + '(code: 2)', null, true);
                            logToServer("Error getting data for request to accessToken.");
                            return;
                        }
                        xhr2.open('POST', endpoints.acccessTokenURL, false);
                        xhr2.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                        xhr2.addEventListener("load", function () {
                            if (xhr2.readyState === 4) {
                                //Saving response on Metada to send to APP
                                if (xhr2.status == 200) {
                                    var finalResponse = JSON.parse(xhr2.response);
                                    generateResponseOK(finalResponse, options);
                                } else {
                                    logToServer("Error getting access Token");
                                    generateResponseNOK(options, 4, ERROR_NO_TOKENID_FOUND + '(code: 3)', xhr2.status, false);
                                }

                            }
                        });
                        xhr2.send(params);
                    } else {
                        logToServer("Error getting auhtorize Token");
                        generateResponseNOK(options, 4, ERROR_NO_TOKENID_FOUND + '(code: 4)', xhr.status, false);
                    }
                }

            });

            logToServer("CALL: userMetadata AUTHORIZE WITH DATA = " + data);

            xhr.open("POST", endpoints.auhtorizeURL, false);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.setRequestHeader("token", cookie);
            xhr.send(data);
        }
    } else if (options.request.requestType == "logout") {
        xhr = inicializeXMLRequest(true, options, false, null);
        xhr.addEventListener("load", function () {
            if (xhr.readyState === 4) {
                if (xhr.status == 200) {
                    generateResponseOK(xhr.responseText, options);
                } else {
                    generateResponseNOK(options, 4, ERROR_GENERIC + '(code: 5)', null, false);
                }
            }
        });

        //logout
        xhr.open("POST", endpoints.logoutURL, false);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("Cache-Control", "no-cache");
        xhr.setRequestHeader("Accept-API-Version", "resource=3.1, protocol=1.0");
        xhr.send(null);
    } else {
        logToServer("Not a valid Type");
        return;
    }
}

/*
 ****************************************************
 * APPLE TV FUNCTIONS
 * Documentation: https://help.apple.com/itc/tvpsso/#
 *
 ***************************************************
 */

/*
 * First function to be executed
 * Documentation: https://help.apple.com/itc/tvpsso/#/itc02e3964c6
 */
App.onLaunch = function (options) {
    logToServer("OnLaunchInput: " + JSON.stringify(options));
    deviceToken = options.userToken;
    options.callback(true, null);
};

/*
 * This fucntion is executed before Interface is shown to user
 */
App.onShowUserInterface = function (options) {
    App.presentDocument(showAuthenticationContext());
};

/*
 * Triggers authetication Module on AM
 */
App.onRequest = function (options) {
    logToServer("OnRequestInput");

    //Load environment from Lighthouse
    getURLFromLightHouse(options, authenticationFlow);

};


/*
 * App.onError
 *
 * App.onError Log 
 */
App.onError = function (message, sourceURL, line) {
    // Log the error 
    logToServer("OnERRORs: msg:" + message + "; SourceURL:" + sourceURL + "; line:" + line);
    return;
};