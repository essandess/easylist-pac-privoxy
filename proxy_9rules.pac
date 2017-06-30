// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
//
// http://www.gnu.org/licenses/lgpl.txt
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// If you normally use a proxy, replace "DIRECT" below with
// "PROXY MACHINE:PORT"
// where MACHINE is the IP address or host name of your proxy
// server and PORT is the port number of your proxy server.
//
// Influenced in part by code from King of the PAC from http://securemecca.com/pac.html

// Define the blackhole proxy for blocked adware and trackware

var normal = "DIRECT";
// var blackhole_ip_port = "127.0.0.1:80";  // test code
// var blackhole_ip_port = "8.8.8.8:53";    // GOOG DNS blackhole; do not use: causes long waits on some sites
var blackhole_ip_port = "127.0.0.1:80";    // deployment code; use the same server as proxy.pac if possible
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com

// Too many rules (>~ 10k) bog down the browser; make reasonable exclusions here:

// EasyList rules:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet
// https://opnsrce.github.io/javascript-performance-tip-precompile-your-regular-expressions
// https://adblockplus.org/blog/investigating-filter-matching-algorithms
// 
// Strategies to convert EasyList rules to Javascript tests:
// 
// In general:
// 1. Preference for performance over 1:1 EasyList functionality
// 2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
// 3. Exact matches: use Object hashing (very fast); use efficient NDA RegExp's for all else
// 4. Divide and conquer specific cases to avoid large RegExp's
// 5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
// 6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin
// 
// scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings
// 
// EasyList rules:
// 
// || domain anchor
// 
// ||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
// ||host is wildcard e.g. ||a.* ? then RegExp.test(host)
// 
// ||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
// ||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]
// 
// ||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
// ||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)
// 
// url parts e.g. a.b^c&d|
// 
// All cases RegExp.test(url)
// Except: |http://a.b. Treat these as domain anchors after stripping the scheme
// 
// regex e.g. /r/
// 
// All cases RegExp.test(url)
// 
// @@ exceptions
// 
// Flag as "good" versus "bad" default
// 
// Variable name conventions (example that defines the rule):
// 
// bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
// bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
// 
// 9 rules:
var good_da_host_JSON = { "apple.com": null,
"init.itunes.apple.com": null,
"init-cdn.itunes-apple.com.akadns.net": null,
"itunes.apple.com.edgekey.net": null,
"icloud.com": null,
"setup.icloud.com": null,
"p32-escrowproxy.icloud.com": null,
"p32-escrowproxy.fe.apple-dns.net": null,
"keyvalueservice.icloud.com": null };
var good_da_host_exact_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules as an efficient NFA RegExp:
var good_da_host_RegExp = /^$/;
var good_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules:
var good_da_hostpath_JSON = { "aliyun.com/nocaptcha/analyze.jsonp": null,
"analytics.atomiconline.com/services/jquery.js": null,
"anthem.com/includes/foresee/foresee-trigger.js": null,
"atdmt.com/ds/yusptsprtspr": null,
"atpworldtour.com/assets/js/util/googleAnalytics.js": null,
"att.com/webtrends/scripts/dcs_tag.js": null,
"autoscout24.net/unifiedtracking/ivw.js": null,
"barclays.co.uk/touchclarity/mbox.js": null,
"behanceserved.com/stats/stats.js": null };
var good_da_hostpath_exact_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var good_da_hostpath_RegExp = /^(?:beacon\.guim\.co\.uk\/accept\-beacon|bountysource\.com\/badge\/tracker|ncbi\.nlm\.nih\.gov\/stat|ourworld\.com\/ow\/evercookie_|skypicker\.com\/places\/BCN|tc\.bankofamerica\.com\/c|24ur\.com\/adserver\/adall\.|bthomehub\.home\/images\/adv_|burbankleader\.com\/hive\/images\/adv_)/i;
var good_da_hostpath_regex_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var good_da_RegExp = /^(?:adblockanalytics\.com\/ads\.js$|flashx\.tv\/js\/jquery\.min\.js$|flashx\.tv\/js\/light\.min\.js$|speedtest\.net\/javascript\/speedtest\-main\.js\?v=|ads\.nyootv\.com\:8080\/crossdomain\.xml|ads\.pandora\.tv\/netinsight\/text\/pandora_global\/channel\/icf@|ads\.sudpresse\.be\/adview\.php\?what=zone\:|bing\.net\/images\/thumbnail\.aspx\?q=|completemarkets\.com\/pictureHandler\.ashx\?adid=)/i;
var good_da_regex_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules:
var good_da_host_exceptions_JSON = { "iad.apple.com": null,
"bingads.microsoft.com": null,
"azure.bingads.trafficmanager.net": null,
"choice.microsoft.com": null,
"choice.microsoft.com.nsatc.net": null,
"corpext.msitadfs.glbdns2.microsoft.com": null,
"corp.sts.microsoft.com": null,
"df.telemetry.microsoft.com": null,
"diagnostics.support.microsoft.com": null };
var good_da_host_exceptions_exact_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules:
var bad_da_host_JSON = { "meetrics.netbb-": null,
"0tracker.com": null,
"149.13.65.144": null,
"195.10.245.55": null,
"1freecounter.com": null,
"212.227.100.108": null,
"24counter.com": null,
"2cnt.net": null,
"2o7.net": null };
var bad_da_host_exact_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\1|collector\-(?=([\s\S]*?\.elb\.amazonaws\.com))\2|collector\-(?=([\s\S]*?\.tvsquared\.com))\3|datacollect(?=([\s\S]*?\.abtasty\.com))\4|metro\-trending\-(?=([\s\S]*?\.amazonaws\.com))\5|siteintercept(?=([\s\S]*?\.qualtrics\.com))\6|vtnlog\-(?=([\s\S]*?\.elb\.amazonaws\.com))\7|logger\-(?=([\s\S]*?\.dailymotion\.com))\8|metric(?=([\s\S]*?\.rediff\.com))\9)/i;
var bad_da_host_regex_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules:
var bad_da_hostpath_JSON = { "google-analytics.com/analytics.js": null,
"google-analytics.com/cx/api.js": null,
"google-analytics.com/ga_exp.js": null,
"google-analytics.com/internal/analytics.js": null,
"google-analytics.com/plugins": null,
"google-analytics.com/siteopt.js": null,
"googletagmanager.com/gtm.js": null,
"quantserve.com/api": null,
"quantserve.com/pixel": null };
var bad_da_hostpath_exact_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:google\-analytics\.com\/collect|google\-analytics\.com\/gtm\/js|google\-analytics\.com\/internal\/collect[^\w.%-]|google\-analytics\.com\/r\/collect[^\w.%-]|5min\.com\/flashcookie\/StorageCookieSWF_|9fine\.ru\/js\/counter\.|akamai\.net\/chartbeat\.|amazonaws\.com\/analytics\.|aol\.com\/ping)/i;
var bad_da_hostpath_regex_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:ivwextern\.|piwik\.|doubleclick\.net\/imp;|24option\.com\/\?oftc=|6waves\.com\/edm\.php\?uid=|ad\.atdmt\.com\/i\/go;|amazonaws\.com\/\?wsid=|anvato\.com\/anvatoloader\.swf\?analytics=|auctiva\.com\/Default\.aspx\?query)/i;
var bad_da_regex_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:&trackingserver=|\-AdTracking\.|\-analitycs\/fab\.|\-analitycs\/ga\.|\-analitycs\/metrica\.|\-analytics\-tagserver\-|\-analytics\/insight\.|\-asset\-tag\.|\-bluekai\.)/i;
var bad_url_parts_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules as an efficient NFA RegExp:
var good_url_RegExp = /^$/;
var good_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules as an efficient NFA RegExp:
var bad_url_RegExp = /^$/;
var bad_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// Add any good networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// LAN, loopback, Apple (direct and Akamai e.g. e4805.a.akamaiedge.net), Microsoft (updates and services)
var GoodNetworks_Array = [ "10.0.0.0,     255.0.0.0",
"172.16.0.0,        255.240.0.0",
"192.168.0.0,       255.255.0.0",
"127.0.0.0,         255.0.0.0",
"17.0.0.0,          255.0.0.0",
"23.2.8.68,         255.255.255.255",
"23.39.179.17,      255.255.255.255",
"23.2.145.78,       255.255.255.255",
"104.70.71.223,     255.255.255.255",
"104.73.77.224,     255.255.255.255",
"104.96.184.235,    255.255.255.255",
"104.96.188.194,    255.255.255.255",
"65.52.0.0,         255.255.252.0" ];

// Apple iAd, Microsoft telemetry
var GoodNetworks_Exceptions_Array = [ "17.172.28.11,     255.255.255.255",
"134.170.30.202,    255.255.255.255",
"137.116.81.24,     255.255.255.255",
"157.56.106.189,    255.255.255.255",
"184.86.53.99,      255.255.255.255",
"2.22.61.43,        255.255.255.255",
"2.22.61.66,        255.255.255.255",
"204.79.197.200,    255.255.255.255",
"23.218.212.69,     255.255.255.255",
"65.39.117.230,     255.255.255.255",
"65.52.108.33,      255.255.255.255",
"65.55.108.23,      255.255.255.255",
"64.4.54.254,       255.255.255.255" ];

// Akamai: 23.64.0.0/14, 23.0.0.0/12, 23.32.0.0/11, 104.64.0.0/10

// Add any bad networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// From securemecca.com: Adobe marketing cloud, 2o7, omtrdc, Sedo domain parking, flyingcroc, accretive
var BadNetworks_Array = [ "61.139.105.128,    255.255.255.192",
"63.140.35.160,  255.255.255.248",
"63.140.35.168,  255.255.255.252",
"63.140.35.172,  255.255.255.254",
"63.140.35.174,  255.255.255.255",
"66.150.161.32,  255.255.255.224",
"66.235.138.0,   255.255.254.0",
"66.235.141.0,   255.255.255.0",
"66.235.143.48,  255.255.255.254",
"66.235.143.64,  255.255.255.254",
"66.235.153.16,  255.255.255.240",
"66.235.153.32,  255.255.255.248",
"81.31.38.0,     255.255.255.128",
"82.98.86.0,     255.255.255.0",
"89.185.224.0,   255.255.224.0",
"207.66.128.0,   255.255.128.0" ];

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\w*+-]{2,15}):\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]+)(\\??[\\S]*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24}\\.?)", "i");
var slashend_RegExp = RegExp("\\/$", "i");

//////////////////////////////////////////////////
// Define the is_ipv4_address function and vars //
//////////////////////////////////////////////////

var ipv4_RegExp = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function is_ipv4_address(host)
{
    var ipv4_pentary = host.match(ipv4_RegExp);
    var is_valid_ipv4 = false;
    
    if (ipv4_pentary) {
        is_valid_ipv4 = true;
        for( i = 1; i <= 4; i++) {
            if (ipv4_pentary[i] >= 256) {
                is_valid_ipv4 = false;
            }
        }
    }
    return is_valid_ipv4;
}

// object hashes
// Note: original stackoverflow-based hasOwnProperty does not woth within iOS kernel 
var hasOwnProperty = function(obj, prop) {
    return obj.hasOwnProperty(prop);
}

/////////////////////
// Done Setting Up //
/////////////////////

// debug with Chrome at chrome://net-internals/#events
// alert("Debugging message.")

//////////////////////////////////
// Define the FindProxyFunction //
//////////////////////////////////

var use_pass_rules_parts_flag = true;  // use the pass rules for url parts, then apply the block rules
var alert_flag = false;                // use for short-circuit '&&' to print debugging statements
var debug_flag = false;               // use for short-circuit '&&' to print debugging statements

function FindProxyForURL(url, host)
{
    var host_is_ipv4 = is_ipv4_address(host);
    var host_ipv4_address;
    
    alert_flag && alert("url is: " + url);
    alert_flag && alert("host is: " + host);

    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";

    // Remove the scheme and extract the path for regex efficiency
    var url_noscheme = url.replace(schemepart_RegExp,"");
    var url_pathonly = url_noscheme.replace(hostpart_RegExp,"");
    var url_noquery = url_noscheme.replace(querypart_RegExp,"$1");
    // Remove the server name from the url and host if host is not an IPv4 address
    var url_noserver = !host_is_ipv4 ? url_noscheme.replace(domainpart_RegExp,"$1") : url_noscheme;
    var url_noservernoquery = !host_is_ipv4 ? url_noquery.replace(domainpart_RegExp,"$1") : url_noscheme;
    var host_noserver =  !host_is_ipv4 ? host.replace(domainpart_RegExp,"$1") : host;
    
    // Remove slashes from the EOL
    url_pathonly = url_pathonly != "/" ? url_pathonly.replace(slashend_RegExp,"") : url_pathonly;
    url_noquery = url_noquery.replace(slashend_RegExp,"");
    url_noserver = url_noserver.replace(slashend_RegExp,"");
    url_noservernoquery = url_noservernoquery.replace(slashend_RegExp,"");
    
    // Debugging results
    if (debug_flag && alert_flag) {
        alert("url_noscheme is: " + url_noscheme);
        alert("url_pathonly is: " + url_pathonly);
        alert("url_noquery is: " + url_noquery);
        alert("url_noserver is: " + url_noserver);
        alert("url_noservernoquery is: " + url_noservernoquery);
        alert("host_noserver is: " + host_noserver);
    }

    // Short circuit to blackhole for good_da_host_exceptions
    if ( hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
        alert_flag && alert("good_da_host_exceptions_JSON blackhole!");
        // Redefine url and host to avoid leaking information to the blackhole
        url = "http://127.0.0.1:80";
        host = "127.0.0.1";
        return blackhole;
    }

    ///////////////////////////////////////////////////////////////////////
    // Check to make sure we can get an IPv4 address from the given host //
    // name.  If we cannot do that then skip the Networks tests.         //
    ///////////////////////////////////////////////////////////////////////
    
    host_ipv4_address = host_is_ipv4 ? host : (isResolvable(host) ? dnsResolve(host) : false);

    if (host_ipv4_address) {
        alert_flag && alert("host ipv4 address is: " + host_ipv4_address);
        /////////////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the GoodNetworks_Array (with exceptions) //
        // we pass it because it is considered safe.                               //
        /////////////////////////////////////////////////////////////////////////////
    
        for (i in GoodNetworks_Exceptions_Array) {
            tmpNet = GoodNetworks_Exceptions_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole!");
                // Redefine url and host to avoid leaking information to the blackhole
                url = "http://127.0.0.1:80";
                host = "127.0.0.1";
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS!");
                return MyFindProxyForURL(url, host);
            }
        }
    
        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////
    
        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole!");
                // Redefine url and host to avoid leaking information to the blackhole
                url = "http://127.0.0.1:80";
                host = "127.0.0.1";
                return blackhole;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // HTTPS: https scheme can only use domain information                      //
    // unless PacHttpsUrlStrippingEnabled == false [Chrome] or                  //
    // network.proxy.autoconfig_url.include_path == true [firefox]              //
    // E.g. on macOS:                                                           //
    // defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false //
    // Check setting at page chrome://policy                                    //
    //////////////////////////////////////////////////////////////////////////////

    // Assume browser has disabled path access if scheme is https and path is '/'
    if ( scheme == "https" && url_pathonly == "/" ) {
    
        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host)))
            && !hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
                alert_flag && alert("HTTPS PASS!");
            return MyFindProxyForURL(url, host);
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
    
        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole!");
            // Redefine url and host to avoid leaking information to the blackhole
            url = "http://127.0.0.1:80";
            host = "127.0.0.1";
            return blackhole;
        }
    }

    ////////////////////////////////////////
    // HTTPS and HTTP: full path analysis //
    ////////////////////////////////////////
    
    if (scheme == "https" || scheme == "http") {
    
        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( !hasOwnProperty(good_da_host_exceptions_JSON,host)
            && ((good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
                (use_pass_rules_parts_flag &&
                    (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                    // test logic: only do the slower test if the host has a (non)suspect fqdn
                    (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                    (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                    (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                    (good_url_parts_flag && good_url_parts_RegExp.test(url_pathonly)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return MyFindProxyForURL(url, host);
        }
    
        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON,host_noserver): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON,host): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON,url_noquery): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(host_noserver): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(host): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(url_noservernoquery): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(url_noquery): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(url_noserver): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(url_noscheme): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(url_pathonly): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url_pathonly)));
            alert("bad_url_regex_RegExp.test(url): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }
    
        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url_pathonly)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole!");
            // Redefine url and host to avoid leaking information to the blackhole
            url = "http://127.0.0.1:80";
            host = "127.0.0.1";
            return blackhole;
        }
    }
    
    // default pass
    alert_flag && alert("Default PASS!");
    return MyFindProxyForURL(url, host);
}

// User-supplied FindProxyForURL()
function MyFindProxyForURL(url, host)
{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
   dnsDomainIs(host, ".local") ||
   (url.substring(0,3) == "ftp")
)
        return "DIRECT";
else
        return "DIRECT";
}
