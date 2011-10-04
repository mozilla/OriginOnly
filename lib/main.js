/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is OriginOnly.
 *
 * The Initial Developer of the Original Code is
 * The Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Mark Goodwin <mgoodwin@mozilla.com> (original author)
 *   Joe Walker <jwalker@mozilla.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
var {components} = require("chrome");
var ch = components.classes["@mozilla.org/security/hash;1"]
        .createInstance(components.interfaces.nsICryptoHash);
var converter = components.classes["@mozilla.org/intl/scriptableunicodeconverter"]
        .createInstance(components.interfaces.nsIScriptableUnicodeConverter);
converter.charset = "UTF-8";

var ss = require("simple-storage");
var store = ss.storage.store;
var data = [];
if (store) {
  data = JSON.parse(store);
}

/**
 * Remove the whitespace (as defined by regex \s) from the ends of a string.
 * @param str The string to trim
 * @return A version of the string with the whitespace removed
 */
function trim(str)
{
  return str.replace(/^\s+|\s+$/g, "");
};

var listener = null;
var flagStore = null;

/**
 * Display some information on a cookie for debug purposes.
 * @param cookie the nsICookie to get debug on
 * @param host a hostname string
 */
function showCookieDebug(cookie, host)
{
  console.log("cookie named: " + cookie.name + " path " + cookie.path +
              " secure: " + cookie.isSecure + " host " + cookie.host +
              " (host is " + host + ")");
};

/**
 * Determine whether the specified host is on-domain for the cookie
 * @param cookie the nsICookie we want to check against
 * @param host a string representing the hostname we're checking
 */
function checkCookieHost(cookie, host)
{
  var domainPrefix = ".";
  if (cookie.host.slice(0, domainPrefix.length) == domainPrefix) {
    if (cookie.host.substring(1) != host) {
      if (host.slice(-cookie.host.length) != cookie.host) {
        return false;
      }
    }
  }
  else {
    if (host != cookie.host) {
      if (0 == host.length) {
        return true;
      }
      return false;
    }
  }
  return true;
};

/**
 * Stores the cookies marked with OriginOnly flags; it's invasive (and rather a lot of work) to
 * change all of the cookie storage stuff in the browser, so we're storing them in the addon for now.
 * @constructor
 */
function FlagStore()
{
}

/**
 * Creates a storage key for a given cookie.
 * @param domain the cookie's domain attribute
 * @param name the name of the cookie
 * @param the path of the cookie 
 */
FlagStore.prototype.makeStorageKey = function FS_makeStorageKey(domain, name, path)
{
  ch.init(ch.SHA256);
  var plainKey = domain + ":" + name;
  var result = {};
  var keyData = converter.convertToByteArray(plainKey, result);
  ch.update(keyData, keyData.length);
  var hash = ch.finish(false);
  // return the two-digit hexadecimal code for a byte
  function toHexString(charCode) {
    return ("0" + charCode.toString(16)).slice(-2);
  }

  // convert the binary hash data to a hex string.
  var hashed = [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");
  return hashed;
};

/**
 * Check to see if a given cookie is origin restricted.
 * @param cookie the cookie to check for origin restriction
 */
FlagStore.prototype.cookieIsOriginRestricted = function FS_cookieIsOriginRestricted(cookie)
{
  var storageKey = this.makeStorageKey(cookie.host, cookie.name, cookie.path);
  if (-1 != data.indexOf(storageKey)) {
    return true;
  }
  return false;
};

/**
 * Inspect a header and, if Set-Cookie, check for OriginOnly flag (storing if set).
 * @param header a header from the nsIHTTPChannel header visitor
 * @param host the host from the destination URI for setting the domain if not in header
 */
FlagStore.prototype.storeOriginOnlyData = function FS_storeOriginOnlyData(header, host)
{
  var elements = header.split(";");
  var cookieName = "";
  var soo = false;
  var pairs = {};

  for (key in elements) {
    var trimmed = trim(elements[key]);
    if (trimmed.toLowerCase() == "originonly") {
      soo = true;
    }
    idx = trimmed.indexOf("=");
    if (-1 != idx) {
      var name = trim(trimmed.substring(0, idx));
      var value = trim(trimmed.substring(idx + 1));
      pairs[name] = value;
      if (0 == key) {
        cookieName = name;
      }
    }
  }
  if (soo) {
    try {
      var path = pairs["path"];
      var domain = pairs["domain"];
      if (!domain) {
        domain = host;
      }
      var storageKey = this.makeStorageKey(domain, cookieName, path);
      data[data.length] = storageKey;
      stored = JSON.stringify(data);
      ss.storage.store = stored;
    }
    catch (ex) {
      console.log(ex);
    }
  }
};

/**
 * An object to encapsulate cookie names and values for checking against other cookies
 * @constructor
 * @param name a string representing the name of the cookie
 * @param value a string representing the value of the cookie 
 */
function MatchCookie(name, value)
{
  this.name = name;
  this.value = value;
}

/**
 * Does the cookie match a supplied cookie?
 * @param cookie a cookie (nsICookie) to check for matching
 */
MatchCookie.prototype.matches = function(cookie)
{
  if (this.name != cookie.name) {
    return false;
  }
  if (this.value != cookie.value) {
    return false;
  }
  return true;
};

/**
 * A builder for cookie strings to send in a request header.
 * @constructor
 * @param cookieString the original cookie string that would otherwise appear in the request header
 * @param aChannel the channel the request is on (nsIHttpChannel)
 */
function CookieBuilder(cookieString, aChannel)
{
  this.channel = aChannel;
  this.cookieString = cookieString;

  this.originalCookies = this.getOriginalCookies();
}

/**
 * Get the original cookies (as would be sent in the request) as an array of MatchCookies. 
 */
CookieBuilder.prototype.getOriginalCookies = function()
{
  cookies = [];
  var elements = trim(this.cookieString).split(";");
  for (e in elements) {
    element = elements[e];
    idx = element.indexOf("=");
    if (-1 != idx) {
      var name = trim(element.substring(0, idx));
      var value = trim(element.substring(idx + 1));
      cookies[cookies.length] = new MatchCookie(name, value);
    }
  }
  return cookies;
};

/**
 * Is the specified cookie in the list of original cookies?
 * @param cookie the cookie (nsICookie) to check
 */
CookieBuilder.prototype.cookieIsOriginal = function(cookie)
{
  for (i in this.originalCookies) {
    if (this.originalCookies[i].matches(cookie)) {
      return true;
    }
  }
  return false;
};

/**
 * Build the cookie string to put in the request header.  This uses the original cookie
 * names and values as a whitelist but must get the actual cookie data from the cookie
 * manager to get the domain information needed for host checks.
 */
CookieBuilder.prototype.buildCookies = function()
{
  var host = this.channel.URI.host;
  var cookieMgr = components.classes["@mozilla.org/cookiemanager;1"]
          .getService(components.interfaces.nsICookieManager2);

  var enm = cookieMgr.getCookiesFromHost(host);
  var sep = "";
  var cs = "";

  while (enm.hasMoreElements()) {
    cookie = enm.getNext().QueryInterface(components.interfaces.nsICookie);
    try {

      // Is the cookie name / value in the original browser cookie string?
      // If not, bin the cookie
      if (!this.cookieIsOriginal(cookie)) {
        // not in whitelist, ignore
        continue;
      }

      var referrer = this.channel.referrer;
      // sometimes nsIHttpChannel.referrer is not set for security reasons
      // if this is the case, dig it out of docshell properties
      if (null == referrer) {
        var intRef = null;
        try {
          if (this.channel instanceof components.interfaces.nsIPropertyBag2) {
            intRef = this.channel
                    .getPropertyAsInterface("docshell.internalReferrer",
                            components.interfaces.nsIURI);
          }
        }
        catch (ex) {
        }
        if (null != intRef) {
          // if it's a cache URL, find the URL of the original
          // resource
          if (intRef.scheme == "wyciwyg") {
            path = intRef.path;
            url = path.substr(path.indexOf("http"));
            var ioService = components.classes["@mozilla.org/network/io-service;1"]
                    .getService(components.interfaces.nsIIOService);
            intRef = ioService.newURI(url, null, null);
            referrer = intRef;
          }
          // URI host will be null, but we don't want to allow file
          // URLs.
          if (intRef.scheme == "file") {
            continue;
          }
        }
      }

      if (referrer) {
        if (!checkCookieHost(cookie, referrer.host)) {
          if (flagStore.cookieIsOriginRestricted(cookie)) {
            continue;
          }
        }
      }
    }
    catch (ex) {
      console.log("cookie build failed: " + ex);
    }
    cs = cs + sep + cookie.name + "=" + cookie.value;
    sep = "; ";
  }
  return cs;
};

/**
 * Header visitor for finding Set-Cookie headers
 * @constructor
 * @param host a string representing the host of the destination URI.
 */
function Visitor(host)
{
  this.host = host;
}

/**
 * Visit the header and store OriginOnly data if it's a Set-Cookie header.
 */
Visitor.prototype.visitHeader = function Visitor_visitHeader(aHeader, aValue)
{
  if (aHeader.indexOf("Set-Cookie") !== -1) {
    flagStore.storeOriginOnlyData(aValue, this.host);
  }
};

/**
 * Listener for nsIHttpChannel activity - this is how we hook into requests / responses.
 * @constructor
 */
function Listener()
{
}

/**
 * Observe (intended for http-on-modify-request and http-on-examine-response).
 * @param aChannel the channel associated with the event (nsIHTTPChannel)
 * @param aTopic the topic (string) that's caused this to fire
 * @param aData I've got no idea what this is... It'll be on MDN somewhere
 */
Listener.prototype.observe = function Listener_observe(aChannel, aTopic, aData)
{
  aChannel.QueryInterface(components.interfaces.nsIHttpChannel);
  visitor = new Visitor(aChannel.URI.host);

  url = aChannel.URI.spec;
  if (aTopic == "http-on-examine-response") {
    try {
      // TODO: Having our FlagStore listening for cookie-changed events is the
      // way to go here
      aChannel.visitResponseHeaders(visitor);
    }
    catch (ex) {
      console.log(ex);
    }
  }
  if (aTopic == "http-on-modify-request") {
    try {
      var cookieSvc = components.classes["@mozilla.org/cookieService;1"]
              .getService(components.interfaces.nsICookieService);
      // var cookieString = cookieSvc.getCookieString(aChannel.URI, aChannel);
      var actualHeader = "";
      try {
        actualHeader = aChannel.getRequestHeader("Cookie");
      }
      catch (ex) {
        // meh
      }
      if (actualHeader) {
        var cookieBuilder = new CookieBuilder(actualHeader, aChannel);
        var built = cookieBuilder.buildCookies();
        if (actualHeader != built) {
          aChannel.setRequestHeader("Cookie", built, false);
        }
      }
    }
    catch (ex) {
      console.log(ex);
    }
  }
};

/**
 * Tear down; remove the observer from the observer service.
 */
Listener.prototype.removeFromListener = function Listener_removeFromListener()
{
  var observerService = components.classes["@mozilla.org/observer-service;1"]
          .getService(components.interfaces.nsIObserverService);
  observerService.removeObserver(this, "http-on-modify-request");
  observerService.removeObserver(this, "http-on-examine-response");
};

/**
 * Set up; hook the observer into the observer service
 */
Listener.prototype.addToListener = function Listener_addToListener()
{
  // Register new request and response listener
  // Should be a new version of Mozilla/Phoenix (after september 15, 2003)
  var observerService = components.classes["@mozilla.org/observer-service;1"]
          .getService(components.interfaces.nsIObserverService);
  observerService.addObserver(this, "http-on-modify-request", false);
  observerService.addObserver(this, "http-on-examine-response", false);
};

/**
 * Entry point.
 * @param options
 * @param callbacks
 */
exports.main = function OriginOnly_main(options, callbacks) {
  listener = new Listener();
  flagStore = new FlagStore();
  listener.addToListener();
};

/**
 * The addon has been unloaded.
 * @param reason (string) the reason for unload.
 */
exports.onUnload = function OriginOnly_onUnload(reason) {
  if (listener) {
    listener.removeFromListener();
  }
  console.log(reason);
};
