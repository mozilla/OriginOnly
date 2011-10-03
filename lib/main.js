// Import the APIs we need.
//var request = require("request");
const {Cc,Ci} = require("chrome");
var ss = require("simple-storage");
var ch = Components.classes["@mozilla.org/security/hash;1"].createInstance(Components.interfaces.nsICryptoHash);
var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].createInstance(Components.interfaces.nsIScriptableUnicodeConverter); 
converter.charset = "UTF-8";
var store = ss.storage.store; 
var data = [];
if(store){
  data = JSON.parse(store);
} 

String.prototype.trim = function() { return this.replace(/^\s+|\s+$/g, ''); }

var listener = null;
var flagStore = null;

// Cookie stuff
var showCookieDebug = function(c,host){
  console.log("cookie named: "+c.name+" path "+c.path+" secure: "+c.isSecure+' host '+c.host+' (host is '+host+')');
};

var checkCookieHost = function(c,host){
    var domainPrefix = '.';
    if(c.host.slice(0, domainPrefix.length) == domainPrefix){
        if(c.host.substring(1) != host){
            if(host.slice(-c.host.length) != c.host){
                return false;
            }
        }
    }
    else {
        if(host!=c.host){
            if(0==host.length){
                return true;
            }
            return false;
        }
    }
    return true;
}

// Storage stuff
function FlagStore(){
    this.makeStorageKey = function(domain,name,path){
      ch.init(ch.SHA256);
      var plainKey =  domain + ':'+name;
      var result = {};
      var keyData = converter.convertToByteArray(plainKey, result);
      ch.update(keyData, keyData.length);
      var hash = ch.finish(false); 
      // return the two-digit hexadecimal code for a byte  
      function toHexString(charCode)  
      {  
        return ("0" + charCode.toString(16)).slice(-2);  
      }  
        
      // convert the binary hash data to a hex string.  
      var hashed = [toHexString(hash.charCodeAt(i)) for (i in hash)].join(""); 
      return hashed;
    };
    
    this.cookieIsOriginRestricted = function(cookie){
      var storageKey = this.makeStorageKey(cookie.host,cookie.name,cookie.path);
      if(-1!=data.indexOf(storageKey)){
        return true;
      }
      return false;
    };
    
    this.storeOriginOnlyData = function(header, host){
      var elements = header.split(';');
      var cookieName = '';
      var soo = false;
      var pairs = {};
      for(key in elements){
        var trimmed = elements[key].trim();
        if(trimmed.toLowerCase()=='originonly'){
          soo = true;
        }
        idx = trimmed.indexOf('=');
        if(-1!=idx){
            var name = trimmed.substring(0,idx).trim();
            var value = trimmed.substring(idx+1).trim();
            pairs[name]=value;
            if(0==key){
                cookieName = name;
            }
        }
      }
      if(soo){
        try {
          var path = pairs['path'];
          var domain = pairs['domain'];
          if(!domain){
            domain = host;
          }
          var storageKey = this.makeStorageKey(domain,cookieName,path);
          data[data.length] = storageKey;
          stored = JSON.stringify(data);
          ss.storage.store = stored;
        } catch(e) {
          console.log(e);
        }
      }
    };
}

function MatchCookie(name,value){
    this.name = name;
    this.value = value;
    
    this.matches = function(cookie){
        if(this.name!=cookie.name){
            return false;
        }
        if(this.value!=cookie.value){
            return false;
        }
        return true;
    };
}

// Build cookie string stuff
function CookieBuilder(cookieString, aChannel){
    this.channel = aChannel;
    this.cookieString = cookieString;
    
    this.getOriginalCookies = function(){
        cookies = [];
        var elements = this.cookieString.trim().split(';');
        for(e in elements){
            element = elements[e];
            idx = element.indexOf('=');
            if(-1!=idx){
                var name = element.substring(0,idx).trim();
                var value = element.substring(idx+1).trim();
                cookies[cookies.length] = new MatchCookie(name,value);
            }
        }
        return cookies;
    }
    
    this.originalCookies = this.getOriginalCookies();
    
    this.cookieIsOriginal = function(cookie){
        for(i in this.originalCookies){
            if(this.originalCookies[i].matches(cookie)){
                return true;
            }
        }
        return false;
    };
    
    this.buildCookies = function(){
      var host = this.channel.URI.host;
      var cookieMgr = Components.classes["@mozilla.org/cookiemanager;1"].getService(Components.interfaces.nsICookieManager2);
      
      var enm = cookieMgr.getCookiesFromHost(host);
      var sep = '';
      var cs = '';
      
      while (enm.hasMoreElements())
      {
        cookie = enm.getNext().QueryInterface(Components.interfaces.nsICookie);
        try{
            
            // Is the cookie name / value in the original browser cookie string? If not, bin the cookie
            if(!this.cookieIsOriginal(cookie)){
                // not in whitelist, ignore
                continue;
            }
            
            var referrer = this.channel.referrer;
            // sometimes nsIHttpChannel.referrer is not set for security reasons
            // if this is the case, dig it out of docshell properties
            if(null == referrer){
                var intRef = null;
                try {
                    if (this.channel instanceof Ci.nsIPropertyBag2){
                        intRef = this.channel.getPropertyAsInterface("docshell.internalReferrer", Ci.nsIURI);
                    }
                }
                catch (e) {
                }
                if(null!=intRef){
                    // if it's a cache URL, find the URL of the original resource
                    if(intRef.scheme == 'wyciwyg'){
                        path = intRef.path;
                        url = path.substr(path.indexOf('http'));
                        var ioService = Components.classes["@mozilla.org/network/io-service;1"].getService(Components.interfaces.nsIIOService);  
                        intRef = ioService.newURI(url, null, null); 
                        referrer = intRef;
                    }
                    // URI host will be null, but we don't want to allow file URLs.
                    if(intRef.scheme == 'file'){
                        continue;
                    }
                }
            }
            
            if(referrer){
                if(!checkCookieHost(cookie,referrer.host)){
                  if(flagStore.cookieIsOriginRestricted(cookie)){
                    continue;
                  }
                }
            }
        } catch (e){
            console.log('cookie build failed: '+e);
        }
        cs = cs+sep+cookie.name+'='+cookie.value;
        sep = '; ';
      }
      return cs;
    };
}

// Header visitor for finding Set-Cookie headers
function Visitor(host){
  this.host = host;
  
  this.visitHeader = function ( aHeader, aValue ) {  
      if ( aHeader.indexOf( "Set-Cookie" ) !== -1 ) {
          flagStore.storeOriginOnlyData(aValue,this.host); 
      }  
  };
}

// Listener for nsIHttpChannel activity
function Listener(){
}

Listener.prototype = {
  observe: function(aChannel, aTopic, aData) {
    aChannel.QueryInterface(Components.interfaces.nsIHttpChannel);  
    visitor = new Visitor(aChannel.URI.host);
      
    url = aChannel.URI.spec;  
    if(aTopic == 'http-on-examine-response'){
      try{
        // TODO: Having our FlagStore listening for cookie-changed events is the way to go here
        aChannel.visitResponseHeaders(visitor);
      }
      catch(e){
        console.log(e);
      }
    }
    if(aTopic == 'http-on-modify-request'){
      try{
        var cookieSvc = Components.classes["@mozilla.org/cookieService;1"]
          .getService(Components.interfaces.nsICookieService);
        //var cookieString = cookieSvc.getCookieString(aChannel.URI, aChannel);
        var actualHeader = '';
        try{
            actualHeader = aChannel.getRequestHeader('Cookie');
        } catch (e){
            // meh
        }
        if(actualHeader){
            var cookieBuilder = new CookieBuilder(actualHeader, aChannel); 
            var built = cookieBuilder.buildCookies();
            if(actualHeader!=built){
                aChannel.setRequestHeader('Cookie',built,false);
            }
        }
      }
      catch(e){
        console.log(e);
      }
   }
},

  removeFromListener: function() {
    var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
    observerService.removeObserver(this, "http-on-modify-request");
    observerService.removeObserver(this, "http-on-examine-response");
  },
  
  addToListener: function() {
    // Register new request and response listener
    // Should be a new version of  Mozilla/Phoenix (after september 15, 2003)
    var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
    observerService.addObserver(this, "http-on-modify-request",   false);
    observerService.addObserver(this, "http-on-examine-response", false);
  }
};
 
exports.main = function(options, callbacks) {
    listener = new Listener();
    flagStore = new FlagStore();
    listener.addToListener();
};
 
exports.onUnload = function (reason) {
    if(listener){
        listener.removeFromListener();
    }
  console.log(reason);
};

