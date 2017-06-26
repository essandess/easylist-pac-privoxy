#!/usr/bin/env python3
#coding: utf-8
__author__ = 'stsmith'

# easylist_pac: Convert Easylist Tracker and Adblocking rules to an efficient Proxy Auto Configuration file

# Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse as ap, datetime, functools as fnt, os, re, shutil, sys, time, warnings

# version dependent libraries
# https://docs.python.org/2/library/urllib.html
# https://docs.python.org/3.0/library/urllib.parse.html
if (sys.version_info > (3, 0)):
    import urllib.request
else:
    from urllib2 import urlopen
    import urlparse

# blackhole specification in arguments
# best choise is the LAN IP address of the http://hostname/proxy.pac web server, e.g. 192.168.0.2:80
parser = ap.ArgumentParser()
parser.add_argument('-b', '--blackhole', help="Blackhole IP:port", type=str, default='127.0.0.1:80')
parser.add_argument('-d', '--download_dir', help="Download directory", type=str, default='~/Downloads')
parser.add_argument('-p', '--proxy', help="Proxy host:port", type=str, default='')
parser.add_argument('-P', '--PAC_original', help="Original proxy.pac file", type=str, default='proxy.pac.orig')
parser.add_argument('-th', '--truncate_hash', help="Truncate hash object length to maximum number", type=int, default=9999)
parser.add_argument('-tr', '--truncate_regex', help="Truncate regex rules to maximum number", type=int, default=4999)
parser.add_argument('-@@', '--exceptions_ignore_flag', help="Ignore exception rules", action='store_true')
args = parser.parse_args()
blackhole_ip_port = args.blackhole
easylist_dir = os.path.expanduser(args.download_dir)
proxy_host_port = args.proxy
orig_pac_file = os.path.join(easylist_dir,args.PAC_original)
truncate_hash_max = args.truncate_hash
truncate_alternatives_max = args.truncate_regex
exceptions_ignore_flag = args.exceptions_ignore_flag

pac_proxy = 'PROXY {}'.format(proxy_host_port) if proxy_host_port else 'DIRECT'

# only download if newer
easylist_url = 'https://easylist.to/easylist/easylist.txt'
easyprivacy_url = 'https://easylist.to/easylist/easyprivacy.txt'

# Conversion to UTC
# resp = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': user_agent}))
last_modified_resp = lambda req: resp.headers.get_all("Last-Modified")[0]
last_modified_to_utc = lambda lm: time.mktime(datetime.datetime.strptime(lm,"%a, %d %b %Y %X GMT").timetuple())
file_to_utc = lambda f: time.mktime(datetime.datetime.utcfromtimestamp(os.path.getmtime(f)).timetuple())

user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
# Download and/or update the easlist.txt and easyprivacy.txt files
for url in [easylist_url, easyprivacy_url]:
    fname = os.path.basename(url)
    fname_full = os.path.join(easylist_dir,fname)
    file_utc = file_to_utc(fname_full) if os.path.isfile(os.path.join(easylist_dir,fname)) else 0.
    resp = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': user_agent}))
    url_utc = last_modified_to_utc(last_modified_resp(resp))
    if url_utc > file_utc:  # download the newer file
        with open(fname_full, 'wb') as out_file:
            shutil.copyfileobj(resp, out_file)

# define a default, user-supplied FindProxyForURL function
default_FindProxyForURL_function = '''\
function FindProxyForURL(url, host)
{{
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
        return "{}";
}}
'''.format(pac_proxy)

if os.path.isfile(orig_pac_file):
    with open(orig_pac_file, 'r') as fd:
        original_FindProxyForURL_function = fd.read()
else:
    original_FindProxyForURL_function = default_FindProxyForURL_function
# change the function name to MyFindProxyForURL
original_FindProxyForURL_function = re.sub(r'function[\s]+FindProxyForURL','function MyFindProxyForURL',original_FindProxyForURL_function)

#  proxy.pac preamble

proxy_pac_preamble = '''\
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
var blackhole_ip_port = "{}";    // deployment code; use the same server as proxy.pac if possible
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet
    
// Too many rules (>~ 10k) bog down the browser; make reasonable exclusions here:

'''.format(blackhole_ip_port)

proxy_pac_postamble = '''
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
"104.96.184.235,    255.255.255.255",
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
var schemepart_RegExp = RegExp("^([\\\\w*+-]{2,15}):\\\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\\\w-]+\\\\.)+[a-zA-Z0-9-]{2,24}\\\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\\\w-]+\\\\.)+[a-zA-Z0-9-]{2,24}\\\\.?[\\\\w~%.\\\\/^*-]+)(\\\\??[\\\\S]*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\\\w-]+\\\\.)*((?:[\\\\w-]+\\\\.)[a-zA-Z0-9-]{2,24}\\\\.?)", "i");
var slashend_RegExp = RegExp("\\\\/$", "i");

// da_hostonly_re = re.compile(r'^((?:[\w*-]+\.)+[a-zA-Z0-9*-]{1,24}\.?)(?:$|[/^?])$');
// da_hostpath_re = re.compile(r'^((?:[\w*-]+\.)+[a-zA-Z0-9*-]{1,24}\.?[\w~%./^*-]+?)\??$');

// object hashes
// https://stackoverflow.com/questions/135448/how-do-i-check-if-an-object-has-a-property-in-javascript
function hasOwnProperty(obj, prop) {
    var proto = obj.__proto__ || obj.constructor.prototype;
    return (prop in obj) &&
        (!(prop in proto) || proto[prop] !== obj[prop]);
}

if ( Object.prototype.hasOwnProperty ) {
    var hasOwnProperty = function(obj, prop) {
        return obj.hasOwnProperty(prop);
    }
}

// unique arrays
// https://stackoverflow.com/questions/11688692/most-elegant-way-to-create-a-list-of-unique-items-in-javascript
// function unique_nonempty(arr) {
//     var u = {}, a = [];
//     for(var i = 0, l = arr.length; i < l; ++i){
//         if(arr[i].length > 0 && !u.hasOwnProperty(arr[i])) {
//             a.push(arr[i]);
//             u[arr[i]] = 1;
//         }
//     }
//     return a;
// }

// convert EasyList wildcard '*', separator '^', and anchor '|' to regexp; ignore '?' globbing 
// http://blogs.perl.org/users/mauke/2017/05/converting-glob-patterns-to-efficient-regexes-in-perl-and-javascript.html

var domain_anchor_RegExp = RegExp("^\\\\|\\\\|");
// performance: use a simplified, less inclusive of subdomains, regex for domain anchors
// also assume that RexgExp("^https?//") stripped from url string beforehand
//var domain_anchor_replace = "^(?:[\\\\w\\-]+\\\\.)*?";
var domain_anchor_replace = "^";
var n_wildcard = 1;
function easylist2re(pat,offset) {
    function tr(pat) {                                                          
        return pat.replace(/[/.?+@^|]/g, function (m0, mp, ms) {  // url, regex, EasyList special chars
            // res = m0 === '?' ? '[\\s\\S]' : '\\\\' + m0;                   
            // https://adblockplus.org/filters#regexps, separator '^' == [^\\w.%-]
            var res = '\\\\' + m0;
            switch (m0) {
            case '^':
                res = '[^\\\\w-]';
                break;
            case '|':
                res = mp + m0.length === ms.length ? '$' : '^';
                break;
            default:
                res = '\\\\' + m0;  // escape special characters
            }
            return res;
        });
    }

    // EasyList domain anchor '||'
    var bos = '';
    if (domain_anchor_RegExp.test(pat)) {
        pat = pat.replace(domain_anchor_RegExp, "");  // strip "^||"
        bos = domain_anchor_replace;
    }

    // EasyList wildcards '*', separators '^', and start/end anchors '|'
    // define n_wildcard outside the function for concatenation of these patterns
    // var n_wildcard = 1;
    pat = bos + pat.replace(/\W[^*]*/g, function (m0, mp, ms) {
        if (m0.charAt(0) !== '*') {
            return tr(m0);
        }
        // var eos = mp + m0.length === ms.length ? '$' : '';
        var eos = '';
        return '(?=([\\\\s\\\\S]*?' + tr(m0.substr(1)) + eos + '))\\\\' + n_wildcard++;
    });
    return pat;
}

// inclusive example -- step through at regex101.com to decode
// var res = easylist2re('||' + 'a*'.repeat(2) + 'b.com/?q=1^ad_box_|')
// console.log(res);
// ^(?:https?:\\/\\/){0,1}(?:[\\w\\-]+\\.)*[^\\w\\-]?a(?=([\\s\\S]*?a))\\1(?=([\\s\\S]*?b\.com\\/\\?q=1[^\\w-]ad_box_$))\\2

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com

// || domain anchor

// ||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
// ||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
// ||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]

// The exact rule sets are defined by the *_JSON hashes

// ||host is wildcard e.g. ||a.* ? then RegExp.test(host)
// ||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]
// ||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)
// url parts e.g. a.b^c&d|

// Compile efficient NFA RegExp's

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_da_host_RegExp = new RegExp(domain_anchor_replace + "(?:" + good_da_host_regex_Array.map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_da_hostpath_RegExp = new RegExp(domain_anchor_replace + "(?:" + good_da_hostpath_regex_Array.map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_da_RegExp = new RegExp(domain_anchor_replace + "(?:" + good_da_regex_Array.map(easylist2re).join("|") + ")", "i");

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_da_host_RegExp = new RegExp(domain_anchor_replace + "(?:" + bad_da_host_regex_Array.map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_da_hostpath_RegExp = new RegExp(domain_anchor_replace + "(?:" + bad_da_hostpath_regex_Array.map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_da_RegExp = new RegExp(domain_anchor_replace + "(?:" + bad_da_regex_Array.map(easylist2re).join("|") + ")", "i");

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_url_parts_RegExp = new RegExp("(?:" + good_url_parts_Array.map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_url_parts_RegExp = new RegExp("(?:" + bad_url_parts_Array.map(easylist2re).join("|") + ")", "i");

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_url_regex_RegExp = new RegExp("(?:" + good_url_regex_Array.map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_url_regex_RegExp = new RegExp("(?:" + bad_url_regex_Array.map(easylist2re).join("|") + ")", "i");

// Post-processing: Dereference large strings (perhaps unnecessarily) to allow garbage collection
good_da_host_regex_Array = null;
good_da_hostpath_regex_Array = null;
good_da_regex_Array = null;
bad_da_host_regex_Array = null;
bad_da_hostpath_regex_Array = null;
bad_da_regex_Array = null;
good_url_parts_Array = null;
bad_url_parts_Array = null;
good_url_regex_Array = null;
bad_url_regex_Array = null;

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

    //////////////////////////////////////////////////////////////
    // SCHEME BLOCKS: schemes matched here here will be blocked //
    //////////////////////////////////////////////////////////////
    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";
    if ( scheme.length == 0 || bad_schemes_RegExp.test(scheme) ) {
        // Redefine url and host to avoid leaking information to the blackhole
        url = "http://127.0.0.1:80";
        host = "127.0.0.1";
        return blackhole;
    }

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
                return MyFindProxyForURL(url.toString(), host);
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
            return MyFindProxyForURL(url.toString(), host);
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
            return MyFindProxyForURL(url.toString(), host);
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
    return MyFindProxyForURL(url.toString(), host);
}

// User-supplied FindProxyForURL()
''' + original_FindProxyForURL_function

easylist_strategy = """\
EasyList rules:
https://adblockplus.org/filters
https://adblockplus.org/filter-cheatsheet
https://opnsrce.github.io/javascript-performance-tip-precompile-your-regular-expressions
https://adblockplus.org/blog/investigating-filter-matching-algorithms

Strategies to convert EasyList rules to Javascript tests:

In general:
1. Preference for performance over 1:1 EasyList functionality
2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
3. Exact matches: use Object hashing (very fast); use efficient NDA RegExp's for all else
4. Divide and conquer specific cases to avoid large RegExp's
5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin

scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings

EasyList rules:

|| domain anchor

||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
||host is wildcard e.g. ||a.* ? then RegExp.test(host)

||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]

||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)

url parts e.g. a.b^c&d|

All cases RegExp.test(url)
Except: |http://a.b. Treat these as domain anchors after stripping the scheme

regex e.g. /r/

All cases RegExp.test(url)

@@ exceptions

Flag as "good" versus "bad" default

Variable name conventions (example that defines the rule):

bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
"""

# list variables based on EasyList strategies above
# initial values prepended before EasyList rules
# pass updates and services from these domains
# handle organization-specific ad and tracking servers in later commit
good_da_host_exact = ['apple.com',
                      'init.itunes.apple.com',  # use nslookup to determine canonical names
                      'init-cdn.itunes-apple.com.akadns.net',
                      'itunes.apple.com.edgekey.net',
                      'icloud.com',
                      'setup.icloud.com',
                      'setup.fe.apple-dns.net',
                      'gsa.apple.com',
                      'gsa.apple.com.akadns.net',
                      'iadsdk.apple.com',
                      'iadsdk.apple.com.edgekey.net',
                      'lcdn-locator.apple.com',
                      'lcdn-locator.apple.com.akadns.net',
                      'lcdn-locator-usuqo.apple.com.akadns.net',
                      'cl1.apple.com',
                      'cl2.apple.com',
                      'cl3.apple.com',
                      'cl4.apple.com',
                      'cl5.apple.com',
                      'cl1-cdn.origin-apple.com.akadns.net',
                      'cl2-cdn.origin-apple.com.akadns.net',
                      'cl3-cdn.origin-apple.com.akadns.net',
                      'cl4-cdn.origin-apple.com.akadns.net',
                      'cl5-cdn.origin-apple.com.akadns.net',
                      'cl1.apple.com.edgekey.net',
                      'cl2.apple.com.edgekey.net',
                      'cl3.apple.com.edgekey.net',
                      'cl4.apple.com.edgekey.net',
                      'cl5.apple.com.edgekey.net',
                      'xp.apple.com',
                      'xp.itunes-apple.com.akadns.net',
                      'mt-ingestion-service-pv.itunes.apple.com',
                      'p32-sharedstreams.icloud.com',
                      'p32-sharedstreams.fe.apple-dns.net',
                      'p32-fmip.icloud.com',
                      'p32-fmip.fe.apple-dns.net',
                      'gsp-ssl.ls.apple.com',
                      'gsp-ssl.ls-apple.com.akadns.net',
                      'gsp-ssl.ls2-apple.com.akadns.net',
                      'gspe35-ssl.ls.apple.com',
                      'gspe35-ssl.ls-apple.com.akadns.net',
                      'gspe35-ssl.ls.apple.com.edgekey.net',
                      'gsp64-ssl.ls.apple.com',
                      'gsp64-ssl.ls-apple.com.akadns.net',
                      'mt-ingestion-service-st11.itunes.apple.com',
                      'mt-ingestion-service-st11.itunes-apple.com.akadns.net',
                      'apple-dns.net',
                      'microsoft.com', 'mozilla.com', 'mozilla.org']
good_da_host_regex = []
good_da_hostpath_exact = []
good_da_hostpath_regex = []
good_da_regex = []
bad_da_host_exact = []
bad_da_host_regex = []
bad_da_hostpath_exact = []
bad_da_hostpath_regex = []
bad_da_regex = []
good_url_parts = []
bad_url_parts = []
good_url_regex = []
bad_url_regex = []

# provide explicit expceptions to good hosts or domains, e.g. iad.apple.com
good_da_host_exceptions_exact = [ 'iad.apple.com',
                                  'bingads.microsoft.com',
                                  'azure.bingads.trafficmanager.net',
                                  'choice.microsoft.com',
                                  'choice.microsoft.com.nsatc.net',
                                  'corpext.msitadfs.glbdns2.microsoft.com',
                                  'corp.sts.microsoft.com',
                                  'df.telemetry.microsoft.com',
                                  'diagnostics.support.microsoft.com',
                                  'feedback.search.microsoft.com',
                                  'i1.services.social.microsoft.com',
                                  'i1.services.social.microsoft.com.nsatc.net',
                                  'redir.metaservices.microsoft.com',
                                  'reports.wes.df.telemetry.microsoft.com',
                                  'services.wes.df.telemetry.microsoft.com',
                                  'settings-sandbox.data.microsoft.com',
                                  'settings-win.data.microsoft.com',
                                  'sqm.df.telemetry.microsoft.com',
                                  'sqm.telemetry.microsoft.com',
                                  'sqm.telemetry.microsoft.com.nsatc.net',
                                  'statsfe1.ws.microsoft.com',
                                  'statsfe2.update.microsoft.com.akadns.net',
                                  'statsfe2.ws.microsoft.com',
                                  'survey.watson.microsoft.com',
                                  'telecommand.telemetry.microsoft.com',
                                  'telecommand.telemetry.microsoft.com.nsatc.net',
                                  'telemetry.urs.microsoft.com',
                                  'vortex.data.microsoft.com',
                                  'vortex-sandbox.data.microsoft.com',
                                  'vortex-win.data.microsoft.com',
                                  'cy2.vortex.data.microsoft.com.akadns.net',
                                  'watson.microsoft.com',
                                  'watson.ppe.telemetry.microsoft.com'
                                  'watson.telemetry.microsoft.com',
                                  'watson.telemetry.microsoft.com.nsatc.net',
                                  'wes.df.telemetry.microsoft.com',
                                  'win10.ipv6.microsoft.com',
                                  'www.bingads.microsoft.com',
                                  'survey.watson.microsoft.com' ]

# EasyList regular expressions

comment_re = re.compile(r'^!\s*')   # ! commment
configuration_re = re.compile(r'^\[[^]]*?\]')  # [Adblock Plus 2.0]
easylist_opts = r'~{0,1}\b(?:third-party|domain|script|image|stylesheet|object(?!-subrequest)|object\-subrequest|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|generichide|genericblock|other|sitekey|match-case|collapse|donottrack|popup|media|font)\b'
option_re = re.compile(r'^(.*?)(\$' + easylist_opts + r'.*?)$')
# regex's used to exclude options for specific cases
domain_option = r'(?:domain=)'  # discards rules specific to links from specific domains
alloption_exception_re = re.compile(easylist_opts)  # discard all options from rules
notdm3dimppupos_option_exception_re = re.compile(r'~{0,1}\b(?:script|stylesheet|object(?!-subrequest)|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|generichide|genericblock|other|sitekey|match-case|collapse|donottrack|media|font)\b')
not3dimppupos_option_exception_re = re.compile(r'~{0,1}\b(?:domain|script|stylesheet|object(?!-subrequest)|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|generichide|genericblock|other|sitekey|match-case|collapse|donottrack|media|font)\b')
domain_option_exception_re = re.compile(domain_option)  # discard from-domain specific rules
scriptdomain_option_exception_re = re.compile(r'(?:script|domain=)')  # discard from-domain specific rules
selector_re = re.compile(r'^(.*?)#\@{0,1}#*?.*?$') # #@##div [should be #+?, but old style still used]
regex_re = re.compile(r'^\@{0,2}\/(.*?)\/$')
wildcard_begend_re = re.compile(r'^(?:\**?([^*]*?)\*+?|\*+?([^*]*?)\**?)$')
wild_anch_sep_exc_re = re.compile(r'[*|^@]')
wild_sep_exc_noanch_re = re.compile(r'(?:[*^@]|\|[\s\S])')
anch_sep_exc_re = re.compile(r'[|^@]')
anch_exc_re = re.compile(r'[|@]')
exception_re = re.compile(r'^@@(.*?)$')
wildcard_re = re.compile(r'\*+?')
wildcard_regex = r'.*?'
regexp_symbol_re = re.compile(r'([?*.+@])')
httpempty_re = re.compile(r'^\|?https{0,1}://$')
pathend_re = re.compile(r'(?i)(?:(?:/|\|)$|\.(?:jsp?|php|xml|jpe?g|png|p?gif|img|swf|flv|(?:s|p)?html?|f?cgi|pl?|aspx|ashx|css|jsonp?|asp|search|cfm|ico|act|act(?:ion)?|spy|do|stm|cms|txt|imu|dll|io|smjs|xhr|ount|bin|py|dyn|gne|mvc|lv|nap|jam|nhn))')

domain_anch_re = re.compile(r'^\|\|(.+?)$')
domain_re = re.compile(r'(?:[\w\-]+\.)+[a-zA-Z0-9\-]{2,24}')
urlhost_re = re.compile(r'^(?:https?://){0,1}(?:[wW]{3}\d{0,3}[.]){0,1}' + r'({})'.format(domain_re.pattern))
# omit scheme from start of rule -- this will also be done in JS for efficiency
scheme_anchor_re = re.compile(r'^(\|?(?:[\w*+-]{1,15})?://)');  # e.g. '|http://' at start

# (Almost) fully-qualified domain name extraction (with EasyList wildcards)
# Example case: banner.3ddownloads.com^
da_hostonly_re = re.compile(r'^((?:[\w*-]+\.)+[a-zA-Z0-9*-]{1,24}\.?)(?:$|[/^?])$');
da_hostpath_re = re.compile(r'^((?:[\w*-]+\.)+[a-zA-Z0-9*-]{1,24}\.?[\w~%./^*-]+?)\??$');

# ignore any rules following comments with these strings, until the next non-ignorable comment
commentname_sections_ignore_re = r'(?:{})'.format('|'.join(re.sub(r'([.])','\\.',x) for x in '''\
gizmodo.in
shink.in
project-free-tv.li
vshare.eu
pencurimovie.ph
filmlinks4u.is
Spiegel.de
bento.de
German
French
Arabic
Armenian
Belarusian
Bulgarian
Chinese
Croatian
Czech
Danish
Dutch
Estonian
Finnish
Georgian
Greek
Hebrew
Hungarian
Icelandic
Indian
Indonesian
Italian
Japanese
Korean
Latvian
Lithuanian
Norwegian
Persian
Polish
Portuguese
Romanian
Russian
Serbian
Singaporean
Slovene
Slovak
Spanish
Swedish
Thai
Turkish
Ukranian
Ukrainian
Vietnamese
Gamestar.de
Focus.de
tvspielfilm.de
Prosieben
Wetter.com
Woxikon.de
Fanfiktion.de
boote-forum.de
comunio.de
planetsnow.de'''.split('\n')))

# regex to limit regex filters (bootstrapping in part from securemecca.com PAC regex keywords)
if False:
    badregex_regex_filters = ''  # Accept everything
else:
    badregex_regex_filters = '''\
cdn
cloud
banner
image
img
pop
game
free
financ
film
fast
farmville
fan
exp
share
cash
money
dollar
buck
dump
deal
daily
content
kick
down
file
video
score
partner
match
ifram
cam
widget
monk
rapid
platform
google
follow
shop
love
content
^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$
^([A-Za-z]{12}|[A-Za-z]{8}|[A-Za-z]{50})\.com$
smile
happy
traffic
dash
board
tube
torrent
down
creativ
host
affil
\\.(biz|ru|tv|stream|cricket|online|racing|party|trade|webcam|science|win|accountant|loan|faith|cricket|date)
^mob
join
data
your?
watch
survey
stealth
invisible
social
brand
site
script
xchang
merch
kli(k|p)
clic?k
zip
invest
0catch\\.com
24counter\\.com
2o7\\.net
302br\\.net
33across\\.com
360tag\\.com
3gl\\.net
51yes\\.com
abmr\\.net
acecounter\\.com
ad-gbn\\.com
ad6media\\.fr
adadvisor\\.net
adblade\\.com
adbull\\.com
adc-serv\\.net
adclick\\.lv
adclickmedia\\.com
addynamo\\.net
adengage\\.com
adextent\\.com
adfeedstrk\\.com
adform\\.net
adframesrc\\.com
adfusion\\.com
adgtracker\\.com
adhese\\.com
adinterax\\.com
adition\\.com
adjungle\\.com
adk2\\.com
adlooxtracking\\.com
adman\\.gr
admanage\\.com
admarketplace\\.net
admedia\\.com
admulti\\.com
adnxs\\.com
adobetag\\.com
adocean\\.pl
adparlor\\.com
adprotect\\.net
adreadytractions\\.com
adrent\\.net
adroll\\.com
adsafeprotected\\.com
adsbookie\\.com
adservinginternational\\.com
adskape\\.ru
adsonar\\.com
adspeed\\.com
adsrvr\\.org
adsymptotic\\.com
adtech\\.de
adtech\\.fr
adtechus\\.com
adtrk\\.biz
advance\\.net
advertstream\\.com
advertise\\.com
advertising\\.com
advertserve\\.com
adzerk\\.net
affinity\\.com
afftrack\\.com
afy11\\.net
agcdn\\.com
aggregateknowledge\\.com
agkn\\.com
aimediagroup\\.com
alexametrics\\.com
amazingcounters\\.com
amazon-adsystem\\.com
amgdgt\\.com
ampxchange\\.com
amung\\.us
analytics-egain\\.com
analytics\\.edgesuite\\.net
analytics\\.edgekey\\.net
analytics\\.go\\.com
anametrix\\.net
andomedia\\.com
angelfishstats\\.com
apicit\\.net
apmebf\\.com
arlime\\.com
assoc-amazon\\.com
atomex\\.net
atwola\\.com
audienceiq\\.com
avazutracking\\.net
acxiom-online\\.com
axf8\\.net
bbelements\\.com
behavioralengine\\.com
betrad\\.com
bidsystem\\.com
bidvertiser\\.com
bigmir\\.net
binlayer\\.com
bizible\\.com
bizographics\\.com
bkrtx\\.com
blockmetrics\\.com
blogads\\.com
blogtoplist\\.com
blueadvertise\\.com
bluekai\\.com
blueconic\\.net
bluecava\\.net
blueseek\\.com
bm23\\.com
bmmetrix\\.com
boomtrain\\.com
brandaffinity\\.net
brandreachsys\\.com
brat-online\\.ro
bravenet\\.com
brcdn\\.com
brightedge\\.com
btrll\\.com
btstatic\\.com
burt\\.io
buysellads\\.com
c\\.compete\\.com
c3metrics\\.com
c3tag\\.com
cam-content\\.com
cam4\\.com
carbonads\\.com
cc
ccbill\\.com
cc-dt\\.com
cedexis\\.com
chango\\.com
chartbeat\\.com
chartbeat\\.net
checkm8\\.com
cjb\\.net
clickable\\.net
clickability\\.com
clickbank\\.net
clickbooth\\.com
clickdensity\\.com
clickequations\\.net
clickintext\\.net
clickon\\.co\\.il
clickpathmedia\\.com
clickprotects\\.com
clicksagent\\.com
clickshield\\.net
clickshift\\.com
clicksor\\.com
clicksor\\.net
clicktale\\.net
clicktracks\\.com
clickzs\\.com
clickzzs\\.nl
clustrmaps\\.com
cmpnet\\.com
cn
cnzz\\.com
collect\\.igodigital\\.com
collective-media\\.net
collserve\\.com
comclick\\.com
company-target\\.com
comscore\\.com
conduit-banners\\.com
contextly\\.com
contextweb\\.com
convertexperiments\\.com
convertglobal\\.com
convertro\\.com
coremetrics\\.com
counter\\.hackers\\.lv
counter\\.rambler\\.ru
counter\\.yadro\\.ru
cpa\\.clicksure\\.com
cpxinteractive\\.com
cqcounter\\.com
craktraffic\\.com
crazyegg\\.com
creative-serving\\.com
criteo\\.com
criteo\\.net
crm-metrix\\.com
crowdscience\\.com
crsspxl\\.com
crwdcntrl\\.net
ctasnet\\.com
cxense\\.com
cxt\\.ms
dapper\\.net
dbbsrv\\.com
ddnsking\\.com
dedicatedmedia\\.com
deepmetrix\\.com
demandbase\\.com
demdex\\.net
digitaldesire\\.com
directadvert\\.ru
directrdr\\.com
directrev\\.com
directtrack\\.com
displaymarketplace\\.com
dl-rms\\.com
dmtracker\\.com
dmtry\\.com
domainsponsor\\.com
domdex\\.com
dotmetrics\\.net
dotomi\\.com
doublepimp\\.com
doubleverify\\.com
dsply\\.com
dt\\.mydas\\.mobi
dwin1\\.com
easy\\.lv
easyresearch\\.se
econda-monitor\\.de
ecustomeropinions\\.com
effectivemeasure\\.net
eloqua\\.com
emailretargeting\\.com
emediate\\.eu
en25\\.com
enecto\\.com
eproof\\.com
ero-advertising\\.com
esm1\\.net
esomniture\\.com
estara\\.com
estat\\.com
etargetnet\\.com
ethnio\\.com
etracker\\.de
euroclick\\.com
everestjs\\.net
everesttech\\.net
evergage\\.com
evolvemediametrics\\.com
evyy\\.net
exactag\\.com
exacttarget\\.com
exelator\\.com
exmasters\\.com
exoclick\\.com
extole\\.com
extreme-dm\\.com
eyeota\\.net
eyereturn\\.com
eyewonder\\.com
ezakus\\.net
ezboard\\.com
fastonlineusers\\.com
feedjit\\.com
feeldmc\\.com
finalid\\.com
flagcounter\\.com
flashtalking\\.com
fls\\.doubleclick\\.net
flxpxl\\.com
fmpub\\.net
footprintlive\\.com
formalyzer\\.com
freelogs\\.com
freesexparadise\\.com
frosmo\\.com
fwdservice\\.com
gaug\\.es
gemius\\.pl
geobytes\\.com
geoplugin\\.net
geovisite\\.com
getclicky\\.com
gigcount\\.com
glam\\.com
globalmailer\\.com
go-mpulse\\.net
go2jump\\.org
googleadservices\\.com
gosquared\\.com
gostats\\.com
gostats\\.ru
grapeshot\\.co\\.uk
gravity\\.com
gsimedia\\.net
gumgum\\.com
gwallet\\.com
heapanalytics\\.com
hiconversion\\.com
histats\\.com
hit\\.bg
hitslink\\.com
hitsprocessor\\.com
hittail\\.com
hopto\\.org
hotlog\\.ru
hs-analytics\\.net
hubspot\\.com
humanclick\\.com
hxtrack\\.com
hype-ads\\.com
hypeads\\.org
ib-ibi\\.com
ic-live\\.com
iclive\\.com
idtargeting\\.com
ilsemedia\\.nl
imiclk\\.com
imlive\\.com
impact-ad\\.jp
impresionesweb\\.com
impressiondesk\\.com
imrworldwide\\.com
indextools\\.com
industrybrains\\.com
infolinks\\.com
inpwrd\\.com
insightexpressai\\.com
inspectlet\\.com
intelliad\\.de
intellitxt\\.com
interia\\.pl
intermarkets\\.net
interpolls\\.com
intextad\\.net
investingchannel\\.com
invitemedia\\.com
inviziads\\.com
invoc\\.us
invodo\\.com
ip-api\\.com
ip-label\\.net
iperceptions\\.com
ipinfodb\\.com
ist-track\\.com
istrack\\.com
iwanttodeliver\\.com
jirafe\\.com
juicyads\\.com
jump-time\\.net
jumptap\\.com
jumptime\\.com
kameleoon\\.com
keywordmax\\.com
klikbonus\\.com
komoona\\.com
korrelate\\.net
krxd\\.net
l\\.addthiscdn\\.com
l2m\\.net
lduhtrp\\.net
leadforensics\\.com
leadformix\\.com
legolas-media\\.com
levexis\\.com
liadm\\.com
liftdna\\.com
lijit\\.com
linkbucks\\.com
linkpulse\\.com
linksmart\\.com
list\\.ru
listrakbi\\.com
liveperson\\.net
livepromotools\\.com
loggly\\.com
lognormal\\.net
lookery\\.com
lphbs\\.com
luckyorange\\.com
luxup\\.ru
m-pathy\\.com
magnify360\\.com
maploco\\.com
maps-4-u\\.com
marinsm\\.com
marketo\\.net
mathtag\\.com
matheranalytics\\.com
mdotlabs\\.com
measuremap\\.com
media6degrees\\.com
mediaforge\\.com
mediaforgews\\.com
mediatraffic\\.com
meetrics\\.net
mercent\\.com
met\\.vgwort\\.de
metalyzer\\.com
meteorsolutions\\.com
metric\\.gstatic\\.com
metrigo\\.com
misstrends\\.com
miva\\.com
mixpanel\\.com
mixpo\\.com
mkt51\\.net
mlstat\\.com
mmstat\\.com
moatads\\.com
mobify\\.com
monetate\\.net
mongoosemetrics\\.com
mookie1\\.com
motigo\\.com
motorpresse-statistik\\.de
mouseflow\\.com
mp\\.mydas\\.mobi
mplxtms\\.com
msads\\.net
mtree\\.com
mvilivestats\\.com
mvtracker\\.com
mxcdn\\.net
myaffiliateprogram\\.com
myomnistar\\.com
myroitracking\\.com
mysearch\\.com
mystat-in\\.net
mystats\\.nl
mythings\\.com
neodatagroup\\.com
netflame\\.cc
netlog\\.com
netmining\\.com
netmng\\.com
netseer\\.com
netshelter\\.net
newrelic\\.com
newsanalytics\\.com\\.au
newstogram\\.com
nexac\\.com
nextstat\\.com
nir\\.theregister\\.co\\.uk
nordicresearch\\.com
notlong\\.com
nrelate\\.com
nuggad\\.net
nxtck\\.com
o-oe\\.com
oewabox\\.at
offermatica\\.com
offermatica\\.intuit\\.com
ojolink\\.fr
ojrq\\.net
olark\\.com
omtrdc\\.net
onestat\\.com
online-metrix\\.net
opbandit\\.com
opentracker\\.net
openx\\.com
openx\\.net
openx\\.org
optimizely\\.com
optimost\\.com
orangeads\\.fr
outster\\.com
owneriq\\.net
p-td\\.com
pages05\\.net
paperg\\.com
pardot\\.com
parkingcrew\\.net
pay-click\\.ru
peer39\\.net
peerius\\.com
percentmobile\\.com
perfectaudience\\.com
pingdom\\.net
pixel\\.parsely\\.com
plugrush\\.com
plushlikegarnier\\.com
po\\.st
pochta\\.ru
pocitadlo\\.cz
pointroll\\.com
popadscdn\\.net
popunder\\.ru
ppctracking\\.net
prchecker\\.info
predictad\\.com
predictiveresponse\\.net
primosearch\\.com
prnx\\.net
pro-market\\.net
program3\\.com
proxad\\.net
proximic\\.com
pstats\\.com
publishflow\\.com
pubmatic\\.com
puhtml\\.com
puls\\.lv
pulse360\\.com
pulsemgr\\.com
pzkysq\\.pink
q1media\\.com
qbaka\\.net
qnsr\\.com
qualtrics\\.com
quantserve\\.com
qubitproducts\\.com
quebec-bin\\.com
quintelligence\\.com
rcm\\.amazon\\.com
r\\.msn\\.com
raasnet\\.com
reachjunction\\.com
readnotify\\.com
realclick\\.co\\.kr
realist\\.gen\\.tr
realtracker\\.com
rediff\\.com
redirecthere\\.com
redirectme\\.net
reinvigorate\\.net
reporo\\.net
res-x\\.com
research\\.de\\.com
research-int\\.se
revenuewire\\.net
revolvermaps\\.com
revsci\\.net
rfihub\\.com
rfihub\\.net
richmetrics\\.com
richrelevance\\.com
ringrevenue\\.com
rkdms\\.com
rlcdn\\.com
roia\\.biz
roispy\\.com
roitesting\\.com
roivista\\.com
rovion\\.com
rs6\\.net
rsvpgenius\\.com
ru
ru4\\.com
rubiconproject\\.com
runadtag\\.com
sail-horizon\\.com
sancdn\\.net
sayyac\\.com
sayyac\\.net
scanscout\\.com
scorecardresearch\\.com
scoutanalytics\\.net
searchignite\\.com
securetracking2\\.com
segment\\.com
segment\\.io
sellpoint\\.net
sendori\\.com
serving-sys\\.com
sexcounter\\.com
sharpspring\\.com
shinystat\\.com
shinystat\\.it
simplereach\\.com
simpli\\.fi
site50\\.net
siteapps\\.com
siteimprove\\.com
sitemeter\\.com
sitescout\\.com
sitestat\\.com
sitetagger\\.co\\.uk
sitetracker\\.com
skimlinks\\.com
skimresources\\.com
smartadserver\\.com
smartclick\\.net
snoobi\\.com
softonicads\\.com
sojern\\.com
sonobi\\.com
sophus3\\.com
soundsecureredir\\.com
specificclick\\.net
specificmedia\\.com
splittag\\.com
spongecell\\.com
spotxchange\\.com
spring-tns\\.net
springmetrics\\.com
spylog\\.com
spylog\\.ru
ssl-stats\\.wordpress\\.com
starmegane\\.info
stat24\\.com
statcounter\\.com
stathat\\.com
stats\\.fr
stats\\.magnify\\.net
stats\\.wordpress\\.com
steelhousemedia\\.com
stormiq\\.com
sub2tech\\.com
sumome\\.com
supercounters\\.com
superstats\\.com
supert\\.ag
sv2\\.biz
sytes\\.net
tagsrvcs\\.com
tailsweep\\.com
tailtarget\\.com
targetfuel\\.com
targetnet\\.com
telemetryverification\\.net
tellapart\\.com
tentaculos\\.net
thebrighttag\\.com
theprivateredirect\\.net
thesearchagency\\.net
tidaltv\\.com
tk
tnctrx\\.com
tns-cs\\.net
toboads\\.com
toolbar\\.com
toplist\\.cz
total-media\\.net
tradedoubler\\.com
tracemyip\\.org
track\\.clicksure\\.com
track\\.ning\\.com
trackalyzer\\.com
trackedlink\\.net
tracking\\.searchmarketing\\.com
tracking202\\.com
trafic-booster\\.biz
traffichaus\\.com
trafficjunky\\.net
travidia\\.com
tribalfusion\\.com
triplequadturbo\\.com
trk4\\.com
trkme\\.net
trovus\\.co\\.uk
truehits\\.in\\.th
truehits\\.net
trw12\\.com
tubemogul\\.com
turn\\.com
tvsquared\\.com
tynt\\.com
tyxo\\.bg
ugdturner\\.com
uimserv\\.net
umbel\\.com
undertone\\.com
unicast\\.com
unrulymedia\\.com
up\\.nytimes\\.com
usabilla\\.com
usabilitytools\\.com
usercash\\.com
userreport\\.com
users\\.51\\.la
valuead\\.com
veinteractive\\.com
ventivmedia\\.com
verticalscope\\.com
viglink\\.com
vindicosuite\\.com
vinsight\\.de
visiblemeasures\\.com
visistat\\.com
visitor-track\\.com
visualdna\\.com
visualdna-stats\\.com
visualwebsiteoptimizer\\.com
vizu\\.com
voicefive\\.com
voluumtrk\\.com
voodoo\\.com
w55c\\.net
way2traffic\\.com
web-stat\\.com
webcams\\.com
webeffective\\.keynote\\.com
webflowmetrics\\.com
webleads-tracker\\.com
weborama\\.fr
webspectator\\.com
webstats4u\\.com
webtrekk\\.net
webtrends\\.com
webtrendslive\\.com
webvoo\\.com
wemfbox\\.ch
whoson\\.com
wikia-beacon\\.com
wiredminds\\.de
woopra\\.com
wtp101\\.com
x-traceur\\.com
x0\\.nl
xblasterads1\\.com
xg4ken\\.com
xhit\\.com
xiti\\.com
xorg\\.pl
xplosion\\.de
xtendmedia\\.com
yesmessenger\\.com
yieldmanager\\.com
yieldmanager\\.net
yieldoptimizer\\.com
yousee\\.com
ypmadserver\\.com
yumenetworks\\.com
z5x\\.net
zanox\\.com
zapto\\.org
zdbb\\.net
zebestof\\.com
zedo\\.com
zemanta\\.com
zergnet\\.com
zqtk\\.net
rabnaar
adlogger
adbanner
adbanner
pagevisit
counter
adcheck
ad_?choice
addthis
adforge
banners
adobe_update
adobeflashplayer
adproducts?
adrevolver
ad-
ads
amazon-affiliate
logger
analytics?
track
assets
awempire
babes
baise
bbvanetoffice
behaviorads
bigtit
bing\\.com
bit\\.ly
blowjob
bondage
boobs
burningcamel
cardstatement
chartbeat
chicks
chloroform
click
cloudfront\\.net
cock
cumshot
dblclick
impression
doubleclick
surveycode
eluminate
ero-advertising
eroadvertising
eroti
event
ficken
flash-update
flash_update
flashplayer
fuck
gecock
adsense
googlead
gravity-beacon
hardcore
hentai
house_?ad
hugedomains\\.com
incest
iperceptions
java
jquery
jquery
keezmovies
keygen
lazyload-ad
lesbi
litas
livejasmin
loghuman
lolita
logic
godaddy
media
milf
naked
nasty
tpagetag
oasfile
okcupid
orgy
beacon
paypal
pissing
piwik
popunder
porn
proxysignature
pussy
quant
radio_?ad
remote-?desktop
stats?
sesso
sex
links?
slut
small-?ad
sms
fantasy
navad
tacoda
tecock
tits
transparent
trial
tripadvisor
utm
vecock
videoarab
voyeur
warez
webad
webiqonline
webtrek
zvents
3x
aba
adult
aggregate
knowledge
ally\\.com
allybank\\.com
amateur
americanexpress
anony
anti-vir
antispy
antivir
anz\\.co
aol\\.com
around
asian
avast\\.com
banese\\\.com
bankofamerica
bbva\\.es
bitch
blackapplehost
block
boob
bradesco\\.com
casalemedia
casino
cazino
cdc\\.gov
cdna\\.tremormedia\\.com
celeb
chase\\.com
chaseonline
cialis
cimbclicks
cisco
citibank
cloak
cool
danskebank
tremormedia
dhl
digid
discovercard
ebay
exponential
facebook
fdic
firewall
flash-player
flashplayer
freestats
gay
getpast
girls
glamour
brightcove
google\\.com
googlepages\\.com
googletagservices
garcinia
greencoffe
hidden
hide
hsbc
huge
invisible
irs\\.gov
itau\\.com
kampyle\\.com
kaspersky
kazaa
kontera
levitra
linkedin
lloydstsb
lust
macromedia
mastercard
mature
maximumslim
meter
microsoft\\.com
myspace
nacha\\.org
nude
oasc[(?:0|1|e)]
penis
pills
poker
popadscdn
privacy
prok[(?:c|s)]
prox
meebo
refunds?
heise\\.de
runescape
[^aeo]rx[^c]
s2d6\\.com
santander
[^i]scan[^dy]
secret
secure\.ally\.com
skype
slimbody
slimfast
ssa\\.gov
[^sy]suck
symantec
toolbar
traveladvertising
treasury\\.gov
triggertag
tsbbank
tsb\\.co\\.nz
tunnel
ubs\\.com
unblock
unibanco\\.com
unlock
usaa\\.com
usbank\\.com
ustreas\\.gov
ustreasury
verifiedbyvisa\\.com
viagra
vipreantivirus
visa\\.com
boldchat
wachovia
wellsfargo\\.com
westernunion
windowsupdate\\.com
xxx
yahoo
zeroredirect
zonealarm
activex
ad_?banner
ad_?iframe
ad_?label
ad_?legend
ad_?manager
adengage
adserver
adsyndication
advert
ajrotator
bannerads?
cmdatatagutils
competetracking
dynatracemonitor
filezilla
flash-plugin
flash-hq-plugin
flash-video-plugin
flashinstaller
footer-?ad
generate
google_?analytics
google_?page_?track
houseads?
install
install_?activex
mature
mtvi_?reporting
nude
omnidiggthis
openads
optimost
page-peel
pageear
performancingads?
pixeltracking
recordhit
redirectexittrack
revsci
afs_?ads
touchclarity
tracking_?frame
tradead
urlsplittrack
vtracker
yahoo-?ad
1pix\\.gif
1x1_trans\\.gif
listeners?
flashcookie
counters?
ad_?banner
ad_?counter
ad_?frame
ad_?iframe
ad_?rotation
ad_?tpl
adap\\.tv
adaptive
adaptvadplayer
ad_?code
adcalloverride
adchoices?
addyn
adfile
adheader
adhese
adimage
adimages
adindex
adinjector
adjs
adlinks\\.[(j|p)]
adloader
adlog
admanager
admantx
admarker
adobject
adpage
adpeeps
adproxy
adrelated
adrevenue
adrollpixel
adrum
freewheel
adsales
adsatt
adsbanner
adscript
adscroll
adsense
adserv
adsfac
adsonar
adsremote
adsrotate
adsrv
adssrv
adstream
adswrapper\.
adswrapper3
adtags?
adtech_
adtext
adtrack
adunit
adunits
advertisement
advertising
advert
adview
affiliates?
alexa\\.com
amatomu\\.com
amazonaws\\.com
analyticsextension
anal[^_oy]
miss-knowing
assets?
atdmt\\.com
autotag
avmws
aweber\\.com
baidu\\.com
bannerad
banners-stat
blekko\\.com
blogoas
bluekai
bottom_?ad
brandanalytics
brazzers\\.com
break\\.com
brightedge
britannica\\.com
bugsnag
buzznet\\.com
carbonads
cbc\\\.ca
cbox\\.ws
cbs1x1\\.gif
cdn\\.nmcdn\\.us
cdn5\\.js
cdnplanet\\.com
cdx\\.gif
cedexis
certona
cfformprotect
chartbeat
yandex\\.com
clear\\.gif
clickheat
clickjs
click_?stats
clickstream
clicktale
clicktale
clicktracking
cloudfront\\.net
cn-fe-ads
cn-fe-stats
cnevids\\.com
cnwk\\.1d
com\\/adx
com\\/i\\/i\\.gif
com\\/t\\.gif
com\\/v\\.gif
joomlawatch
common\\/ads
comscore
conversionruler
cookie-id
cookie\\.crumb
coradiant\\.js
coremetrics
counter\\.js
counter\\.php
criteo
cubead
curveball
dailymotion\\.com
dclk
dcs\\.gif
deep_?recover
demandbase
demdex\\.js
descpopup\\.js
disqus\\.com
doors\\/ads
dotclear\.[(g|j)]
dtmtag\.js
dw-world\\.de
dw\\.com
eas_tag
ecom\\/status
surveycode
digitalsurvey
elqcfg
elqimg
elqnow
emos2\\.js
emstrack
entry-stats
epimg\\.net
eros[^ei]
eu\\/ywa\\.js
eweek\\.com
exelate
extendedanalytics
fb-tracking
nyaa\\.eu
flash_?player
flash\\/ads
flashads
flashget
foresee
clear\\.png
fpcount
fsrscripts
fttrack
addons?
geoip
getads?
getbanner
getclicky
giganews\\.com
gigya\\.com
go2cloud\\.org
google\\.com\\/uds\\/stats
google_?ads?
google-analyticator
google_?caf
googletagmanager\\.com
googleusercontent\\.com
googlytics
gotmojo\\.com
gravity-beacon
grvcdn\\.com
gscounters
heatmap
hellobar\\.com
netflame\\.cc
hrblock\\.com
hs_?track
html\\.ng
huffingtonpost\\.com
iframe\\/ads?
providesupport\\.com
images\\/ad
imawebcookie
imdbads
img\\/ad
includes\\/ads?
indeed\\.com
installflashplay
intensedebate\\.com
internads
iperceptions
ixs1\\.net
jnana\\.tsa
jnana_[(1|9)]
js\\/(?:ads|dart|nielsen|oas|track|ywa)
adscripts?
kantarmedia
keen-tracker
keywee
kissmetrics
krux\\.js
link_?track
list-manage\\.com
livefyre\\.com
livezilla
loadads?
log_view
logging
lygo\\.com
mail\\.ru
medium\\.com
metrics?
mgnetwork\\.com
mobify
modules\\/ad
moneyball
mpel\\mpel
mpu-dm\\.html
msn\\.com
mwtag\\.js
mylife\\.com
nbcudigitaladops.com\/hosted\/housepix.gif
neonbctracker\\.js
net\\/_ads
net\\/pop
cetrk\\.com
news\\/(?:ber|ras|via)
nielsen
nircmd
mtr\\.js
oas-config
oas\\/oas
keynote\\.com
oiopub-direct
ooyala\\.com
opentag
openx_[^g]
openx\\/
opinionlab
optimost
org\\/pop
ostkcdn\\.com
page-ads
pagepeel
partenaires
pbstrackingplugin
perfectmarket\\.com
php-stats
myvisites
ping\\.gif
ping\\.html
piwik
pix\\.gif
pixall\\.min\\.js
pixel\\.gif
pixel\\.png
pixel-page\\.html
pixeltrack\\.php
twitter\\.com
ooyala\\.com
plus\\/ad
pop6\\.com
popunder
postprocad
pricegrabber\\.com
prnx_?track
ptv8\\.swf
pub\\/trictrac
pubads?
publicidad
pxa\\.min\\.js
quant\\.js
quantcast
quisma\\.com
ra_track
rcom-ads
rcom-wt-mlt
readme\\.exe
realmedia\\/ads
refreshads
reklama
related-ads
resxclsa
resxclsx
reuters\\.com
rg-rlog\\.php
rightad
ru\\/pop\\.js
rum\\/bacon\\.min\\.js
s-code[(4|5)]\\.js
s_code\\.js
s_code_ma\\.js
s\\/hbx\\.js
sailthru\\.js
salesforce\\.com
scanscout
scribol\\.com
scripts\\/ad
scripts\\/ga
scripts\\/xiti
sdctag\\.js
search\\.usa\\.gov
servead
session-hit
shell\\.exe
shinystat\\.cgi
shop\\.pe
shopify_stats
showad
silverpop
simplereach_counts
siteads
sitecatalyst
sitecrm
sitestat
skoom\\.de
skstats
smartad
smartname\\.com
spc_trans\\.gif
spc\\.php
spcjs\\.php
special-ads\\
sports\\.fr
__ssobj\\/core
stat\\.php
statcounter\\.js
static\\/ad
statistics\\.php
supercookie
survey_?monkey
swf\\/ad
swfbin\\/ad
swiftypecdn\\.com
tagcdn\\.com
taxonomy-ads
targeting
throttle
tealeaf\\.js
tealeafsdk\\.js
tealium\\.js
thirdparty
timeslog
tinypass\\.com
tncms\\/ads
top_?ad
topic_stats
touchcommerce\\.com
tout\\.com
trackevent
trackjs
trafic
trans_pixel
transparent
turner\\.com
turnsocial\\.com
tynt\\.js
typepad\\.com
ucoz\\.com
unica_[(n|o|t)]
update\\.exe
updateflashplayer\\.exe
upi\\.com
uploads\\/ad
us\\/[(c|s)]
userfly\\.js
utag\\.ga
utag\\.js
utag\\.loader
veapianalytics\\.js
vertical-stats
vfxdsys
vglnk\\.js
video-plugin
videodownloader
visit
voxmedia\\.com
vtrack\\.php
w3track\\.com
web_?ad
webiq
weblog
webtrek
webtrend
wget\\.exe
widgets
winstart\\.exe
winstart\\.zip
wired\\.com
woopra\\.js
slimstat
wpdigital\\.net
wrb\\.js
wsj\\.net
wtbase\\.js
wtcore\\.js
wtid\\.js
wtinit\\.js
wunderground\\.com
plugthis
xiti\.js
xgemius\\.js
xn_track
xtclick.
xtcore\\.[(j|p)]
xtrack\\.php
yahoo-beacon\\.js
yandex\\.ru
ybn_pixel
yimg\\.com
youtube\\.com
youtube-nocookie\\.com
ystat\\.js
ywxi\\.net
zaehlpixel\\.php
zag\\.gif
zaguk\\.gif
zdnet\\.com
ziffdavisenterprise\\.com
contextclicks
zwshell\\.exe
zwshellx\\.exe
zvents\\.com
crd_prm
adserver
cheapwatch
clicktalecdn
dating
doctor
finewatch
girl
hide
netspiderads
replicawatch
rx[^fls]
sex
superwatch
surf
swisswatch
ustreasury
watchreplica
ad-cdn
ad\\.
adcdn\\.
adimg\\.
adlog\\.
adnetwork\\.
ads\\.
ads-pd\\.
ads[0-9]\\.
adsys\\.
adv\\.
advertiser\\.
ally\\.com
bstats\\.
chase\\.com
content\\.mkt
crack[^l]
crmmetrix
alexa\\.com
dw-eu\\.com
ebay\\.com
fdic\\.gov
gdyn\\.
geoip\\.
geoiplookup\\.
gostats\\.
hard[(b|c|e|p|s)]
hot[^em]
id\\.google
irs\\.gov
nacha\\.org
oas\\.
openx\\.
ox-d\\.
pills
piwik\\.
pcworld\\.com
refund-services\\.irs
refunds\\.irs
reklama\\.
singlefeed\.com
sdc\\.
sedocnamemain\\.
secure\\.signup
ssdc\\.
stats\\.bbc\\.co\\.uk
synad\\.
synad2\\.
tit[^abhilmou]
traffic\\.outbrain\\.com
utm\\.
validclick\\.
visa\\.com
wtsdc\\.
ad-limits\\.js
ad-manager
ad_engine
adx\\.js
\\.bat
\\.bin
[^ck]anal[^_]
\\.com\/a\\.gif
\\.com\/p\\.gif
\\.com\\.au\\/ads
\\.cpl
[^bhmz]eros
\\.exe
\\.exe
\\.msi
\\.net\\/p\\.gif
\\.pac
\\.pdf
\\.pdf\\.exe
\\.rar
\\.scr
\\.sh
transparent1x1\\.gif
\\/travidia
__utm\\.js
whv2_001\\.js
xtcore\\.js
\\.zip
babe
beacon
gay
mature
nude
wachovia
sharethis\\.com
blogsontop\\.com
pantherssl\\.com
csdata1\\.com
cloudfront\\.net
domdex\\\.com
[^cs]hard
[^s]hot
log\\.go\\.com
stats\\.wp\\.com
[^i]crack
virgins\\.com
\\.xyz
cracks
yahoo\\.com
girl
girls
hide
pills
voxmedia\\.com
sex
shareasale\\.com
financialcontent\\.com'''

badregex_regex_filters_re = re.compile(r'(?:{})'.format('|'.join(badregex_regex_filters.split('\n'))))

# use or not use regular expression rules of any kind
def regex_ignore_test(line,opts=''):
    res = False  # don't ignore any rule
    # ignore wildcards and anchors
    # res = re_test(r'[*^]',line)
    return res

def re_test(regex,string):
    if isinstance(regex,str): regex = re.compile(regex)
    return bool(regex.search(string))

def easylist_append_rules(fd,ignore_huge_url_regex_rule_list=False):
    ignore_rules_flag = False
    for line in fd:
        line = line.rstrip()
        line_orig = line
        if False:
            debug_this_rule_string = '||arstechnica.com^*/|$object'
            if line.find(debug_this_rule_string) != -1:
                pass
        exception_flag = False  # block default; pass if True
        option_exception_re = not3dimppupos_option_exception_re  # ignore these options by default
        opts = ''  # default: no options in the rule
        # ignore these cases
        # comment case: ignore
        if re_test(comment_re,line):
            if re_test(commentname_sections_ignore_re, line):
                ignored_rules_comment_start = comment_re.sub('',line)
                if not ignore_rules_flag:
                    ignored_rules_count = 0
                    ignore_rules_flag = True
                    print('Ignore rules following comment ',end='',flush=True)
                print('"{}"… '.format(ignored_rules_comment_start),end='',flush=True)
            else:
                if ignore_rules_flag: print('\n {:d} rules ignored.'.format(ignored_rules_count),flush=True)
                ignored_rules_count = 0
                ignore_rules_flag = False
            continue
        if ignore_rules_flag:
            ignored_rules_count += 1
            continue
        # configuration case: ignore
        if re_test(configuration_re,line): continue
        # delete all easylist options **prior** to regex and selector cases
        # ignore domain limits for now
        if re_test(option_re,line):
            opts = option_re.sub('\\2', line)
            # domain-specific and other option exceptions: ignore
            # too many rules (>~ 10k) bog down the browser; make reasonable exclusions here
            line = option_re.sub('\\1', line)  # delete all the options and continue
        # block default or pass exception
        if re_test(exception_re,line):
            line = exception_re.sub('\\1', line)
            exception_flag = True
            option_exception_re = not3dimppupos_option_exception_re  # ignore these options within exceptions
            if exceptions_ignore_flag: continue
        # selector case: ignore
        if re_test(selector_re,line): continue
        # specific options: ignore
        if re_test(option_exception_re, opts): continue
        # blank url case: ignore
        if re_test(httpempty_re,line): continue
        # blank line case: ignore
        if not line: continue
        # treat each of the these cases separately, here and in Javascript
        # regex case
        if re_test(regex_re,line):
            if regex_ignore_test(line): continue
            line = regex_re.sub('\\1', line)
            if exception_flag: good_url_regex.append(line)
            else:
                if not re_test(badregex_regex_filters_re, line): continue  # limit bad regex's to those in the filter 
                bad_url_regex.append(line)
            continue
        # now that regex's are handled, delete unnecessary wildcards, e.g. /.../*
        line = wildcard_begend_re.sub('\\1', line)
        # domain anchors, || or '|http://a.b' -> domain anchor 'a.b' for regex efficiency in JS
        if re_test(domain_anch_re,line) or re_test(scheme_anchor_re,line):
            # strip off initial || or |scheme://
            if re_test(domain_anch_re,line): line = domain_anch_re.sub('\\1', line)
            elif re_test(scheme_anchor_re,line): line = scheme_anchor_re.sub("", line)
            # host subcase
            if re_test(da_hostonly_re,line):
                line = da_hostonly_re.sub('\\1', line)
                if not re_test(wild_anch_sep_exc_re,line):  # exact subsubcase
                    if not re_test(badregex_regex_filters_re, line):
                        if False: print(line)
                        continue  # limit bad regex's to those in the filter
                    if exception_flag: good_da_host_exact.append(line)
                    else: bad_da_host_exact.append(line)
                    continue
                else:  # regex subsubcase
                    if regex_ignore_test(line): continue
                    if exception_flag: good_da_host_regex.append(line)
                    else:
                        if not re_test(badregex_regex_filters_re, line): continue  # limit bad regex's to those in the filter 
                        bad_da_host_regex.append(line)
                    continue
            # hostpath subcase
            if re_test(da_hostpath_re,line):
                line = da_hostpath_re.sub('\\1', line)
                if not re_test(wild_sep_exc_noanch_re,line) and re_test(pathend_re,line):  # exact subsubcase
                    line = re.sub(r'(?:/|\|)$', '', line)  # strip EOL slashes (repeat in JS) and anchors
                    if not re_test(badregex_regex_filters_re, line):
                        if False: print(line)
                        continue  # limit bad regex's to those in the filter
                    if exception_flag: good_da_hostpath_exact.append(line)
                    else: bad_da_hostpath_exact.append(line)
                    continue
                else:  # regex subsubcase
                    if regex_ignore_test(line): continue
                    # ignore option rules for some regex rules
                    if True and re_test(alloption_exception_re,opts): continue
                    if exception_flag: good_da_hostpath_regex.append(line)
                    else:
                        if not re_test(badregex_regex_filters_re, line): continue  # limit bad regex's to those in the filter 
                        bad_da_hostpath_regex.append(line)
                    continue
            # hostpathquery default case
            if True:
                # if re_test(re.compile(r'^go\.'),line):
                #     pass
                if regex_ignore_test(line): continue
                if exception_flag: good_da_regex.append(line)
                else: bad_da_regex.append(line)
                continue
        # all other non-regex patterns
        if True:
            if regex_ignore_test(line): continue
            if not ignore_huge_url_regex_rule_list:
                if True and re_test(alloption_exception_re, opts): continue
                if exception_flag: good_url_parts.append(line)
                else:
                    if not re_test(badregex_regex_filters_re, line): continue  # limit bad regex's to those in the filter 
                    bad_url_parts.append(line)
                continue  # superfluous continue

for fname in ['~/Desktop/easyprivacy.txt', '~/Desktop/easylist.txt']:
    fd = open(os.path.expanduser(fname), 'r')
    # ignore the very large number of url part rules in easylist.txt
    easylist_append_rules(fd,True and fname == '~/Desktop/easylist.txt')
    fd.close()

# ordered uniqueness, https://stackoverflow.com/questions/12897374/get-unique-values-from-a-list-in-python
ordered_unique_nonempty = lambda listable: fnt.reduce(lambda l, x: l.append(x) or l if x not in l and bool(x) else l, listable, [])

good_da_host_exact = ordered_unique_nonempty(good_da_host_exact)
good_da_host_regex = ordered_unique_nonempty(good_da_host_regex)
good_da_hostpath_exact = ordered_unique_nonempty(good_da_hostpath_exact)
good_da_hostpath_regex = ordered_unique_nonempty(good_da_hostpath_regex)
good_da_regex = ordered_unique_nonempty(good_da_regex)
good_da_host_exceptions_exact = ordered_unique_nonempty(good_da_host_exceptions_exact)

bad_da_host_exact = ordered_unique_nonempty(bad_da_host_exact)
bad_da_host_regex = ordered_unique_nonempty(bad_da_host_regex)
bad_da_hostpath_exact = ordered_unique_nonempty(bad_da_hostpath_exact)
bad_da_hostpath_regex = ordered_unique_nonempty(bad_da_hostpath_regex)
bad_da_regex = ordered_unique_nonempty(bad_da_regex)

good_url_parts = ordered_unique_nonempty(good_url_parts)
bad_url_parts = ordered_unique_nonempty(bad_url_parts)
good_url_regex = ordered_unique_nonempty(good_url_regex)
bad_url_regex = ordered_unique_nonempty(bad_url_regex)

# Use to define js object hashes (much faster than string conversion)
def js_init_object(object_name):
    obj = globals()[object_name]
    if len(obj) > truncate_hash_max:
        warnings.warn("Truncating regex alternatives rule set '{}' from {:d} to {:d}.".format(object_name,len(obj),truncate_hash_max))
        obj = obj[:truncate_hash_max]
    return '''\

// {:d} rules:
var {}_JSON = {}{}{};
var {}_flag = {} > 0 ? true : false;  // save #rules, then delete this array after conversion to hash or RegExp
'''.format(len(obj),re.sub(r'_exact$','',object_name),'{ ',",\n".join('"{}": null'.format(x) for x in obj),' }',object_name,len(obj))

# Use to define '\n'-separated regex alternatives
def js_init_array(array_name):
    # Javascript uses '`' for here documents
    arr = globals()[array_name]

    if re_test(r'(?:_parts|_regex)$',array_name) and len(arr) > truncate_alternatives_max:
        warnings.warn("Truncating regex alternatives rule set '{}' from {:d} to {:d}.".format(array_name,len(arr),truncate_alternatives_max))
        arr = arr[:truncate_alternatives_max]
    return '''\

// {:d} rules:
var {}_Array = {}{}{};
var {}_flag = {} > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp
'''.format(len(arr),array_name,'[ ',",\n".join('"{}"'.format(x) for x in arr),' ]',array_name,len(arr))

proxy_pac = proxy_pac_preamble \
            + "\n".join(["// " + l for l in easylist_strategy.split("\n")]) \
            + js_init_object('good_da_host_exact') \
            + js_init_array('good_da_host_regex') \
            + js_init_object('good_da_hostpath_exact') \
            + js_init_array('good_da_hostpath_regex') \
            + js_init_array('good_da_regex') \
            + js_init_object('good_da_host_exceptions_exact') \
            + js_init_object('bad_da_host_exact') \
            + js_init_array('bad_da_host_regex') \
            + js_init_object('bad_da_hostpath_exact') \
            + js_init_array('bad_da_hostpath_regex') \
            + js_init_array('bad_da_regex') \
            + js_init_array('good_url_parts') \
            + js_init_array('bad_url_parts') \
            + js_init_array('good_url_regex') \
            + js_init_array('bad_url_regex') \
            + proxy_pac_postamble

for l in ['good_da_host_exact',
          'good_da_host_regex',
          'good_da_hostpath_exact',
          'good_da_hostpath_regex',
          'good_da_regex',
          'good_da_host_exceptions_exact',
          'bad_da_host_exact',
          'bad_da_host_regex',
          'bad_da_hostpath_exact',
          'bad_da_hostpath_regex',
          'bad_da_regex',
          'good_url_parts',
          'bad_url_parts',
          'good_url_regex',
          'bad_url_regex']:
    print("{}: {:d} rules".format(l,len(locals()[l])),flush=True)

with open(os.path.join(easylist_dir,'proxy.pac'),'w') as fd:
    fd.write(proxy_pac)
