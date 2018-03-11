// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Sun, 11 Mar 2018 12:44:38 GMT
// Created with command: easylist_pac.py
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
var proxy = "DIRECT";                  // e.g. 127.0.0.1:3128
// var blackhole_ip_port = "127.0.0.1:8119";  // ngnix-hosted blackhole
// var blackhole_ip_port = "8.8.8.8:53";      // GOOG DNS blackhole; do not use: no longer works with iOS 11—causes long waits on some sites
var blackhole_ip_port = "127.0.0.1:8119";    // on iOS a working blackhole requires return code 200;
// e.g. use the adblock2privoxy nginx server as a blackhole
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
// 3. Exact matches: use Object hashing (very fast); use efficient NFA RegExp's for all else
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
// 71 rules:
var good_da_host_JSON = { "apple.com": null,
"icloud.com": null,
"apple-dns.net": null,
"swcdn.apple.com": null,
"init.itunes.apple.com": null,
"init-cdn.itunes-apple.com.akadns.net": null,
"itunes.apple.com.edgekey.net": null,
"setup.icloud.com": null,
"p32-escrowproxy.icloud.com": null,
"p32-escrowproxy.fe.apple-dns.net": null,
"keyvalueservice.icloud.com": null,
"keyvalueservice.fe.apple-dns.net": null,
"p32-bookmarks.icloud.com": null,
"p32-bookmarks.fe.apple-dns.net": null,
"p32-ckdatabase.icloud.com": null,
"p32-ckdatabase.fe.apple-dns.net": null,
"configuration.apple.com": null,
"configuration.apple.com.edgekey.net": null,
"mesu.apple.com": null,
"mesu-cdn.apple.com.akadns.net": null,
"mesu.g.aaplimg.com": null,
"gspe1-ssl.ls.apple.com": null,
"gspe1-ssl.ls.apple.com.edgekey.net": null,
"api-glb-bos.smoot.apple.com": null,
"query.ess.apple.com": null,
"query-geo.ess-apple.com.akadns.net": null,
"query.ess-apple.com.akadns.net": null,
"setup.fe.apple-dns.net": null,
"gsa.apple.com": null,
"gsa.apple.com.akadns.net": null,
"icloud-content.com": null,
"usbos-edge.icloud-content.com": null,
"usbos.ce.apple-dns.net": null,
"lcdn-locator.apple.com": null,
"lcdn-locator.apple.com.akadns.net": null,
"lcdn-locator-usuqo.apple.com.akadns.net": null,
"cl1.apple.com": null,
"cl2.apple.com": null,
"cl3.apple.com": null,
"cl4.apple.com": null,
"cl5.apple.com": null,
"cl1-cdn.origin-apple.com.akadns.net": null,
"cl2-cdn.origin-apple.com.akadns.net": null,
"cl3-cdn.origin-apple.com.akadns.net": null,
"cl4-cdn.origin-apple.com.akadns.net": null,
"cl5-cdn.origin-apple.com.akadns.net": null,
"cl1.apple.com.edgekey.net": null,
"cl2.apple.com.edgekey.net": null,
"cl3.apple.com.edgekey.net": null,
"cl4.apple.com.edgekey.net": null,
"cl5.apple.com.edgekey.net": null,
"xp.apple.com": null,
"xp.itunes-apple.com.akadns.net": null,
"mt-ingestion-service-pv.itunes.apple.com": null,
"p32-sharedstreams.icloud.com": null,
"p32-sharedstreams.fe.apple-dns.net": null,
"p32-fmip.icloud.com": null,
"p32-fmip.fe.apple-dns.net": null,
"gsp-ssl.ls.apple.com": null,
"gsp-ssl.ls-apple.com.akadns.net": null,
"gsp-ssl.ls2-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com": null,
"gspe35-ssl.ls-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com.edgekey.net": null,
"gsp64-ssl.ls.apple.com": null,
"gsp64-ssl.ls-apple.com.akadns.net": null,
"mt-ingestion-service-st11.itunes.apple.com": null,
"mt-ingestion-service-st11.itunes-apple.com.akadns.net": null,
"microsoft.com": null,
"mozilla.com": null,
"mozilla.org": null };
var good_da_host_exact_flag = 71 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_host_RegExp = /^$/;
var good_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var good_da_hostpath_JSON = {  };
var good_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_hostpath_RegExp = /^$/;
var good_da_hostpath_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_RegExp = /^$/;
var good_da_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 39 rules:
var good_da_host_exceptions_JSON = { "iad.apple.com": null,
"iadsdk.apple.com": null,
"iadsdk.apple.com.edgekey.net": null,
"bingads.microsoft.com": null,
"azure.bingads.trafficmanager.net": null,
"choice.microsoft.com": null,
"choice.microsoft.com.nsatc.net": null,
"corpext.msitadfs.glbdns2.microsoft.com": null,
"corp.sts.microsoft.com": null,
"df.telemetry.microsoft.com": null,
"diagnostics.support.microsoft.com": null,
"feedback.search.microsoft.com": null,
"i1.services.social.microsoft.com": null,
"i1.services.social.microsoft.com.nsatc.net": null,
"redir.metaservices.microsoft.com": null,
"reports.wes.df.telemetry.microsoft.com": null,
"services.wes.df.telemetry.microsoft.com": null,
"settings-sandbox.data.microsoft.com": null,
"settings-win.data.microsoft.com": null,
"sqm.df.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com.nsatc.net": null,
"statsfe1.ws.microsoft.com": null,
"statsfe2.update.microsoft.com.akadns.net": null,
"statsfe2.ws.microsoft.com": null,
"survey.watson.microsoft.com": null,
"telecommand.telemetry.microsoft.com": null,
"telecommand.telemetry.microsoft.com.nsatc.net": null,
"telemetry.urs.microsoft.com": null,
"vortex.data.microsoft.com": null,
"vortex-sandbox.data.microsoft.com": null,
"vortex-win.data.microsoft.com": null,
"cy2.vortex.data.microsoft.com.akadns.net": null,
"watson.microsoft.com": null,
"watson.ppe.telemetry.microsoft.comwatson.telemetry.microsoft.com": null,
"watson.telemetry.microsoft.com.nsatc.net": null,
"wes.df.telemetry.microsoft.com": null,
"win10.ipv6.microsoft.com": null,
"www.bingads.microsoft.com": null };
var good_da_host_exceptions_exact_flag = 39 > 0 ? true : false;  // test for non-zero number of rules

// 236 rules:
var bad_da_host_JSON = { "jobthread.com": null,
"content.ad": null,
"nastydollars.com": null,
"adziff.com": null,
"ad.doubleclick.net": null,
"pagead2.googlesyndication.com": null,
"popads.net": null,
"2mdn.net": null,
"padsdel.com": null,
"serving-sys.com": null,
"adchemy-content.com": null,
"ltassrv.com.s3.amazonaws.com": null,
"adap.tv": null,
"admitad.com": null,
"contentspread.net": null,
"chartbeat.com": null,
"scorecardresearch.com": null,
"static.parsely.com": null,
"optimizely.com": null,
"nuggad.net": null,
"adnxs.com": null,
"addthis.com": null,
"smartadserver.com": null,
"teads.tv": null,
"clicktale.net": null,
"ip-adress.com": null,
"webtrekk.net": null,
"xing-share.com": null,
"movad.net": null,
"mxcdn.net": null,
"intelliad.de": null,
"stroeerdigitalmedia.de": null,
"rlcdn.com": null,
"krxd.net": null,
"gitcdn.pw": null,
"adverserve.net": null,
"adskeeper.co.uk": null,
"padstm.com": null,
"visualwebsiteoptimizer.com": null,
"hotjar.com": null,
"crwdcntrl.net": null,
"flashtalking.com": null,
"adsafeprotected.com": null,
"adult.xyz": null,
"dashad.io": null,
"adform.net": null,
"cpx.to": null,
"share.baidu.com": null,
"coinad.com": null,
"adition.com": null,
"propvideo.net": null,
"mediaplex.com": null,
"hpr.outbrain.com": null,
"cm.g.doubleclick.net": null,
"banners.cams.com": null,
"bluekai.com": null,
"ad.proxy.sh": null,
"openx.net": null,
"taboola.com": null,
"quantserve.com": null,
"adx.kat.ph": null,
"ipinyou.com.cn": null,
"complexmedianetwork.com": null,
"ad.userporn.com": null,
"adapd.com": null,
"firstclass-download.com": null,
"bongacams.com": null,
"advertising.com": null,
"adfox.yandex.ru": null,
"ad.rambler.ru": null,
"ebayobjects.com.au": null,
"adspayformymortgage.win": null,
"log.pinterest.com": null,
"log.outbrain.com": null,
"pixel.facebook.com": null,
"videoplaza.com": null,
"metrics.brightcove.com": null,
"addtoany.com": null,
"smallseotools.com": null,
"chartaca.com.s3.amazonaws.com": null,
"abbp1.website": null,
"dnn506yrbagrg.cloudfront.net": null,
"widget.crowdignite.com": null,
"tracking-rce.veeseo.com": null,
"heapanalytics.com": null,
"vrp.outbrain.com": null,
"vrt.outbrain.com": null,
"videoplaza.tv": null,
"abbp1.science": null,
"ero-advertising.com": null,
"3wr110.xyz": null,
"sharethis.com": null,
"rapidyl.net": null,
"shareaholic.com": null,
"exoclick.com": null,
"juicyads.com": null,
"htmlhubing.xyz": null,
"advertserve.com": null,
"adk2.co": null,
"adtrace.org": null,
"adcash.com": null,
"am10.ru": null,
"mobsterbird.info": null,
"explainidentifycoding.info": null,
"sharecash.org": null,
"hornymatches.com": null,
"adonweb.ru": null,
"onad.eu": null,
"adk2.com": null,
"xclicks.net": null,
"clicksor.com": null,
"prpops.com": null,
"hd-plugin.com": null,
"contentabc.com": null,
"propellerpops.com": null,
"popwin.net": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"downloadboutique.com": null,
"insta-cash.net": null,
"admedit.net": null,
"adexc.net": null,
"sexad.net": null,
"clicksor.net": null,
"widget.yavli.com": null,
"adbooth.com": null,
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"august15download.com": null,
"adbma.com": null,
"adk2x.com": null,
"ad131m.com": null,
"ad2387.com": null,
"adnium.com": null,
"adxite.com": null,
"bentdownload.com": null,
"adultadworld.com": null,
"admngronline.com": null,
"ad4game.com": null,
"adplxmd.com": null,
"adrunnr.com": null,
"adxprtz.com": null,
"adxpansion.com": null,
"ad-maven.com": null,
"venturead.com": null,
"xtendmedia.com": null,
"brandreachsys.com": null,
"adjuggler.net": null,
"ad6media.fr": null,
"clicktripz.com": null,
"youradexchange.com": null,
"c4tracking01.com": null,
"perfcreatives.com": null,
"media-servers.net": null,
"888media.net": null,
"livepromotools.com": null,
"click.scour.com": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"statsmobi.com": null,
"clicksvenue.com": null,
"terraclicks.com": null,
"clicksgear.com": null,
"onclickmax.com": null,
"poponclick.com": null,
"toroadvertisingmedia.com": null,
"clickfuse.com": null,
"clickmngr.com": null,
"pwrads.net": null,
"whoads.net": null,
"mediaseeding.com": null,
"pgmediaserve.com": null,
"waframedia5.com": null,
"wigetmedia.com": null,
"trafficholder.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"partners.yobt.tv": null,
"clickosmedia.com": null,
"traffictraffickers.com": null,
"smi2.ru": null,
"ads.yahoo.com": null,
"alternads.info": null,
"traktrafficflow.com": null,
"adcdnx.com": null,
"track.xtrasize.nl": null,
"hipersushiads.com": null,
"propellerads.com": null,
"epicgameads.com": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"affbuzzads.com": null,
"megapopads.com": null,
"newstarads.com": null,
"pointclicktrack.com": null,
"b.photobucket.com": null,
"down1oads.com": null,
"popmyads.com": null,
"filthads.com": null,
"1phads.com": null,
"onclickads.net": null,
"adscpm.net": null,
"360adstrack.com": null,
"adexchangetracker.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"adsmarket.com": null,
"imgrock.net": null,
"collector.contentexchange.me": null,
"getclicky.com": null,
"shareasale.com": null,
"pos.baidu.com": null,
"showcase.vpsboard.com": null,
"ad.mail.ru": null,
"doubleclick.net": null,
"pixel.ad": null,
"stats.bitgravity.com": null,
"advertiserurl.com": null,
"xxxmatch.com": null,
"adblade.com": null,
"creativecdn.com": null,
"trackvoluum.com": null,
"tsyndicate.com": null,
"hilltopads.net": null,
"tostega.ru": null,
"kissmetrics.com": null,
"lightson.vpsboard.com": null,
"histats.com": null,
"pubads.g.doubleclick.net": null,
"outbrain.com": null };
var bad_da_host_exact_flag = 236 > 0 ? true : false;  // test for non-zero number of rules
    
// 2 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:imgadult\.com(?=([\s\S]*?))\1|imgtaxi\.com(?=([\s\S]*?))\2)/i;
var bad_da_host_regex_flag = 2 > 0 ? true : false;  // test for non-zero number of rules

// 39 rules:
var bad_da_hostpath_JSON = { "depositfiles.com/stats.php": null,
"ad.atdmt.com/i/a.js": null,
"ad.atdmt.com/i/a.html": null,
"nydailynews.com/tracker.js": null,
"facebook.com/plugins/page.php": null,
"assets.pinterest.com/js/pinit.js": null,
"googletagmanager.com/gtm.js": null,
"elb.amazonaws.com/partner.gif": null,
"pornslash.com/images/a.gif": null,
"domaintools.com/tracker.php": null,
"baidu.com/js/log.js": null,
"imagesnake.com/includes/js/pops.js": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"streamcloud.eu/deliver.php": null,
"google-analytics.com/analytics.js": null,
"hulkshare.com/stats.php": null,
"linkconnector.com/traffic_record.php": null,
"videowood.tv/assets/js/popup.js": null,
"autoline-top.com/counter.php": null,
"imagebam.com/download_button.png": null,
"facebook.com/common/scribe_endpoint.php": null,
"cloudfront.net/analytics.js": null,
"movad.de/c.ount": null,
"plista.com/iframeShowItem.php": null,
"dpstatic.com/banner.png": null,
"turboimagehost.com/p1.js": null,
"thefile.me/apu.php": null,
"cloudfront.net/scripts/js3caf.js": null,
"elb.amazonaws.com/small.gif": null,
"cloudfront.net/log.js": null,
"myway.com/gca_iframe.html": null,
"hitleap.com/assets/banner.png": null,
"allmyvideos.net/player/ova-jw.swf": null,
"twitvid.com/api/tracking.php": null,
"newsarama.com/social.php": null,
"brightcove.com/1pix.gif": null,
"amazonaws.com/g.aspx": null,
"linkwithin.com/pixel.png": null,
"codecguide.com/stats.js": null };
var bad_da_hostpath_exact_flag = 39 > 0 ? true : false;  // test for non-zero number of rules
    
// 208 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:piano\-media\.com\/uid\/|bigxvideos\.com\/js\/pops2\.|pinterest\.com\/images\/|doubleclick\.net\/adx\/|pornfanplace\.com\/js\/pops\.|quantserve\.com\/pixel\/|adform\.net\/banners\/|doubleclick\.net\/adj\/|baidu\.com\/pixel|reddit\.com\/static\/|jobthread\.com\/t\/|amazonaws\.com\/analytics\.|adf\.ly\/_|adultfriendfinder\.com\/banners\/|freakshare\.com\/banner\/|platform\.twitter\.com\/js\/button\.|channel4\.com\/ad\/|nydailynews\.com\/img\/sponsor\/|veeseo\.com\/tracking\/|fwmrm\.net\/ad\/|oload\.tv\/log|baidu\.com\/ecom|streamango\.com\/log|tubecup\.com\/contents\/content_sources\/|openload\.co\/log|imageshack\.us\/ads\/|view\.atdmt\.com\/partner\/|google\-analytics\.com\/plugins\/|chaturbate\.com\/affiliates\/|cloudfront\.net\/track|secureupload\.eu\/banners\/|widgetserver\.com\/metrics\/|deadspin\.com\/sp\/|redtube\.com\/stats\/|domaintools\.com\/partners\/|visiblemeasures\.com\/log|adultfriendfinder\.com\/javascript\/|advfn\.com\/tf_|wtprn\.com\/sponsors\/|photobucket\.com\/track\/|doubleclick\.net\/ad\/|bigxvideos\.com\/js\/popu\.|exitintel\.com\/log\/|adultfriendfinder\.com\/go\/|twitter\.com\/javascripts\/|google\-analytics\.com\/gtm\/js|xvideos\-free\.com\/d\/|static\.plista\.com\/tiny\/|imagetwist\.com\/banner\/|slashgear\.com\/stats\/|pop6\.com\/banners\/|propelplus\.com\/track\/|yandex\.st\/share\/|topbucks\.com\/popunder\/|wupload\.com\/referral\/|mediaplex\.com\/ad\/js\/|cloudfront\.net\/twitter\/|sex\.com\/popunder\/|hstpnetwork\.com\/ads\/|video\-cdn\.abcnews\.com\/ad_|siberiantimes\.com\/counter\/|sawlive\.tv\/ad|pornoid\.com\/contents\/content_sources\/|doubleclick\.net\/pixel|yahoo\.com\/beacon\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|shareasale\.com\/image\/|xxxhdd\.com\/contents\/content_sources\/|gamestar\.de\/_misc\/tracking\/|hothardware\.com\/stats\/|appspot\.com\/stats|zawya\.com\/ads\/|facebook\.com\/tr\/|facebook\.com\/tr|videowood\.tv\/ads|pornalized\.com\/contents\/content_sources\/|amazonaws\.com\/fby\/|red\-tube\.com\/popunder\/|yahoo\.com\/track\/|addthis\.com\/live\/|adroll\.com\/pixel\/|addthiscdn\.com\/live\/|twitter\.com\/i\/jot|fulltiltpoker\.com\/affiliates\/|xxvideo\.us\/ad728x15|sextronix\.com\/images\/|soundcloud\.com\/event|spacash\.com\/popup\/|msn\.com\/tracker\/|daylogs\.com\/counter\/|cnn\.com\/ad\-|xhamster\.com\/ads\/|vodpod\.com\/stats\/|google\.com\/log|videoplaza\.tv\/proxy\/tracker[^\w.%-]|conduit\.com\/\/banners\/|cloudfront\.net\/facebook\/|chameleon\.ad\/banner\/|lovefilm\.com\/partners\/|wired\.com\/event|livedoor\.com\/counter\/|ad\.admitad\.com\/banner\/|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|soufun\.com\/stats\/|citygridmedia\.com\/ads\/|nytimes\.com\/ads\/|hosting24\.com\/images\/banners\/|shareaholic\.com\/analytics_|4tube\.com\/iframe\/|google\-analytics\.com\/collect|primevideo\.com\/uedata\/|girlfriendvideos\.com\/ad|static\.criteo\.net\/images[^\w.%-]|sparklit\.com\/counter\/|trustpilot\.com\/stats\/|amazon\.com\/clog\/|phncdn\.com\/iframe|ru4\.com\/click|keepvid\.com\/ads\/|virool\.com\/widgets\/|facebook\.com\/plugins\/follow|twitch\.tv\/track\/|github\.com\/_stats|powvideo\.net\/ban\/|static\.criteo\.net\/js\/duplo[^\w.%-]|firedrive\.com\/tools\/|kqzyfj\.com\/image\-|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|taboola\.com\/tb|rapidgator\.net\/images\/pics\/|imagecarry\.com\/down|theporncore\.com\/contents\/content_sources\/|liutilities\.com\/partners\/|3movs\.com\/contents\/content_sources\/|videoplaza\.com\/proxy\/distributor\/|amazonaws\.com\/publishflow\/|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|google\.com\/pagead|deadspin\.com[^\w.%-](?=([\s\S]*?\/trackers\.html))\1|nydailynews\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\2|facebook\.com[^\w.%-](?=([\s\S]*?\/tracking\.js))\3|youporn\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\4|bitgravity\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\5|clickfunnels\.com[^\w.%-](?=([\s\S]*?\/track))\6|porntube\.com[^\w.%-](?=([\s\S]*?\/track))\7|stuff\.co\.nz[^\w.%-](?=([\s\S]*?\/track\.min\.js))\8|cloudfront\.net(?=([\s\S]*?\/tracker\.js))\9|buzzfeed\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\10|typepad\.com[^\w.%-](?=([\s\S]*?\/stats))\11|oload\.tv[^\w.%-](?=([\s\S]*?\/_))\12|adf\.ly\/(?=([\s\S]*?\.php))\13|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/Analytics\-))\14|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adawe\-))\15|openload\.co[^\w.%-](?=([\s\S]*?\/_))\16|doubleclick\.net[^\w.%-](?=([\s\S]*?\/ad\/))\17|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adj\/))\18|google\.com[^\w.%-](?=([\s\S]*?\/fastbutton))\19|facebook\.com(?=([\s\S]*?\/plugins\/like\.php))\20|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/like\.php))\21|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/page\.php))\22|platform\.twitter\.com(?=([\s\S]*?\/widget\/))\23|platform\.twitter\.com(?=([\s\S]*?\/widgets\/))\24|hulkshare\.com[^\w.%-](?=([\s\S]*?\/adsmanager\.js))\25|taboola\.com[^\w.%-](?=([\s\S]*?\/log\/))\26|images\-amazon\.com\/images\/(?=([\s\S]*?\/banner\/))\27|allmyvideos\.net\/(?=([\s\S]*?%))\28|allmyvideos\.net\/(?=([\s\S]*?))\29|thevideo\.me\/(?=([\s\S]*?\.php))\30|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adaptvjw5\-))\31|yimg\.com[^\w.%-](?=([\s\S]*?\/sponsored\.js))\32|rackcdn\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\33|amazonaws\.com[^\w.%-](?=([\s\S]*?\/pageviews))\34|videogamesblogger\.com[^\w.%-](?=([\s\S]*?\/scripts\/takeover\.js))\35|liutilities\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\36|urlcash\.net\/random(?=([\s\S]*?\.php))\37|213\.174\.140\.76[^\w.%-](?=([\s\S]*?\/js\/msn\.js))\38|quantserve\.com[^\w.%-](?=([\s\S]*?\.swf))\39|media\-imdb\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\40|amazonaws\.com[^\w.%-](?=([\s\S]*?\/subscription\/))\41|blogsmithmedia\.com[^\w.%-](?=([\s\S]*?facebook))\42|imagetwist\.com\/(?=([\s\S]*?))\43|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-ad\.))\44|paypal\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\45|kitguru\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-Skin\.))\46|ifilm\.com\/website\/(?=([\s\S]*?_skin_))\47|thevideo\.me\/(?=([\s\S]*?_))\48|googleapis\.com[^\w.%-](?=([\s\S]*?\/gen_204))\49|i3investor\.com[^\w.%-](?=([\s\S]*?\/partner\/))\50|redtubefiles\.com[^\w.%-](?=([\s\S]*?\/banner\/))\51|meetlocals\.com[^\w.%-](?=([\s\S]*?popunder))\52|google\.com[^\w.%-](?=([\s\S]*?\/log))\53|cloudzer\.net[^\w.%-](?=([\s\S]*?\/banner\/))\54|widgetserver\.com[^\w.%-](?=([\s\S]*?\/image\.gif))\55|tumblr\.com[^\w.%-](?=([\s\S]*?\/sponsored_))\56|tumblr\.com[^\w.%-](?=([\s\S]*?_sponsored_))\57|redtube\.com[^\w.%-](?=([\s\S]*?\/banner\/))\58|facebook\.com(?=([\s\S]*?\/impression\.php))\59|yimg\.com[^\w.%-](?=([\s\S]*?\/ywa\.js))\60|static\.(?=([\s\S]*?\.criteo\.net\/images[^\w.%-]))\61|eweek\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\62|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/follow))\63|facebook\.com\/ajax\/(?=([\s\S]*?\/log\.php))\64|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/ltas\-))\65|naij\.com[^\w.%-](?=([\s\S]*?\/branding\/))\66|static\.(?=([\s\S]*?\.criteo\.net\/js\/duplo[^\w.%-]))\67|lfcimages\.com[^\w.%-](?=([\s\S]*?\/partner\-))\68)/i;
var bad_da_hostpath_regex_flag = 208 > 0 ? true : false;  // test for non-zero number of rules
    
// 17 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:porntube\.com\/ads$|ads\.|adv\.|affiliates\.|banner\.|quantserve\.com\/pixel;|erotikdeal\.com\/\?ref=|banners\.|bufferapp\.com\/wf\/open\?upn=|affiliate\.|cloudfront\.net\/\?a=|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\1|allmyvideos\.net\/(?=([\s\S]*?=))\2|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\3|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\4|thevideo\.me\/(?=([\s\S]*?\:))\5|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\6)/i;
var bad_da_regex_flag = 17 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 1099 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/img\/tumblr\-|\?getad=&|\.com\/ads\?|\/homepage\-ads\/|\/homepage\/ads\/|\/ad_pop\.php\?|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\/ad\-engine\.|\/ad_engine\?|\/imgad\.|\/imgad\?|\-web\-ad\-|\/web\-ad_|\/iframead\.|\/iframead\/|\/adplugin\.|\/adplugin_|\/contentad\/|\/contentad$|\/adcontent\/|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/webad\.|\/webad\?|_webad\.|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img\/ad_|\/img_ad\/|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\.com\/video\-ad\-|\/eu_cookies\.|_js\/ads\.js|\-ad\-iframe\.|\-ad\-iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|=adcenter&|\.cookie_law\.|\/cookie_law\/|\/static\/tracking\/|\-online\-advert\.|\/ad\.php$|\.com\/\?adv=|\/expandable_ad\.php|\/bottom\-ads\.|\/superads_|\.adriver\.|\/adriver\.|\/adriver_|\/online\-ad_|_online_ad\.|\/post\/ads\/|\/media\/ad\/|\/bg\/ads\/|\/web\-analytics\.|\/web_analytics\/|\/footer\-ads\/|\/adskin\/|\-top\-ads\.|\/top\-ads\.|\-show\-ads\.|\/show\-ads\.|\-text\-ads\.|_search\/ads\.js|\/ad\/logo\/|\/ad\?count=|\/ad_count\.|\/stream\-ad\.|\/mobile\-ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\/adv\-socialbar\-|\/dynamic\/ads\/|\/banner\/adv\/|\/banner\/adv_|\/special\-ads\/|\.co\/ads\/|\.cookienotice\.|\/cookienotice\.|\/ad132m\/|\/afs\/ads\/|\/facebookicon\.|\/ad\?sponsor=|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/showads\/|\/twittericon\.|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/mini\-ads\/|\/ads12\.|\/adsjs\.|\/player\/ads\.|\/player\/ads\/|\/modules\/ads\/|\/adsetup\.|\/adsetup_|\/ads\.cms|\/user\/ads\?|\.no\/ads\/|\/adsframe\.|\/adclick\.|\/i\/ads\/|\/lazy\-ads\-|\/remove\-ads\.|\/pc\/ads\.|\/external\/ads\/|\/ext\/ads\/|\/s_ad\.aspx\?|\/ads\/html\/|\/adbanners\/|\/blogad\.|\/td\-ads\-|\/custom\/ads|\/inc\/ads\/|\/default\/ads\/|\/xtclicks\.|\/xtclicks_|\/sidebar\-ads\/|\/adsdaq_|\/left\-ads\.|\/responsive\-ads\.|\/ads\/targeting\.|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\.online\/ads\/|\/online\/ads\/|\/house\-ads\/|\/delivery\.ads\.|\/ads\/async\/|\.net\/ad\/|&program=revshare&|\/popupads\.|\/adlog\.|\/image\/ads\/|\/image\/ads_|\/adsrv\.|\/adsrv\/|\/ads_reporting\/|\-peel\-ads\-|\/adsys\.|\.com\/js\/ads\/|\/ads\/click\?|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|\/sponsored_ad\.|\/sponsored_ad\/|\/plugins\/ads\-|\/plugins\/ads\/|\.link\/ads\/|\/ads\.htm|\/log\/ad\-|\/log_ad\?|\-sharebar\-|\/ads8\.|\/ads8\/|\/aff_ad\?|\/socialmedia_|\/adstop\.|\/adstop_|\.ads\.css|\/ads\.css|\/ads\.php|\/ads_php\/|\/partner\.ads\.|\.adpartner\.|\/adpartner\.|\?adpartner=|\/new\-ads\/|\/new\/ads\/|\/realmedia\/ads\/|&adcount=|\/adcount\.|\/ads\/square\-|\/ads\/square\.|\-adsonar\.|\/adsonar\.|\/video\-ad\-overlay\.|\/adClick\/|\/adClick\?|\/eu\-cookie\-|\/eu\-cookie\.|\/eu\-cookie\/|_eu_cookie_|\.ads9\.|\/ads9\.|\/ads9\/|=popunders&|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/bannerad\.|\/bannerad\/|_bannerad\.|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|\-adsystem\-|\/adsystem\.|\/adsystem\/|\/ads\/text\/|\/ads_text_|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\.ads3\-|\/ads3\.|\/ads3\/|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\/stats\/event\.js\?|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/blog\/ads\/|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\-img\/ads\/|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|\/adstat\.|\-social\-share\/|\-social\-share_|\/social\-share\-|\/social\-share\.|\/social\/share\-|\/social\/share_|\/social_share_|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\/google\/adv\.|&adserver=|\-adserver\-|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/social\-media\-banner\.|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\/head\-social\.|\/ad_preroll\-|\/admanager\.|\/admanager\/|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\/js\/tracking\.js|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\/js\/tracking\/|\/js\/tracking_|\/media\/ads\/|_media\/ads\/|\/static\/ads\/|_static\/ads\/|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|\/addthis_widget\.|\/wp\-content\/plugins\/automatic\-social\-locker\/|\/adwords\/|\/product\-ad\/|\-images\/ad\-|\/images\-ad\/|\/images\/ad\-|\/images\/ad\/|\/images_ad\/|_images\/ad\.|_images\/ad_|\/images\/gplus\-|\/adseo\/|&advertiserid=|\/ads4\/|\/videoad\.|_videoad\.|\/adworks\/|\/userad\/|\/admax\/|_WebAd[^\w.%-]|\-google\-ads\-|\-google\-ads\/|\/google\-ads\.|\/google\-ads\/|\/adman\/|\/adlink\?|\/adlink_|\/img\/gplus_|=advertiser\.|=advertiser\/|\?advertiser=|\/adsterra\/|\/images\/adver\-|\/ad\.css\?|\/googlead\-|\/googlead\.|_googlead\.|\/adimg\/|_smartads_|\/socialads\/|\/img\/twitter\-|\/img\/twitter\.|\/img\/twitter_|\/flashads\/|\/social\-media\.|\/social_media\/|\/cookies\-monster\.js|_mobile\/js\/ad\.|=adlabs&|\/click\.track\?|\/images\/facebook|\-twitter2\.|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\/wp\-images\/facebook\.png|\-adops\.|\/adops\/|\-adtrack\.|\/adtrack\/|\.net\/adx\.php\?|\.com\/ads\-|\.com\/ads\.|\.com\/ads_|\/com\/ads\/|\/adcash\-|\/chartbeat\.js|_chartbeat\.js|\/nuggad\.|\/nuggad\/|\/\?advideo\/|\?advideo_|\/embed\-log\.js|\-adspot\-|\/adspot\/|\/adspot_|&adnet=|\/adservice\-|\/adservice\/|\/adservice$|_ad\.png\?|\.com\/counter\?|\/adverserve\.|\/admaster\?|\?adx=|\/wp\-content\/plugins\/wp\-bannerize\/|\-google\-ad\.|\/google\-ad\-|\/google\-ad\?|\/google\/ad\?|\/google_ad\.|_google_ad\.|\/socialMedia\-|\/socialMedia\.|\.com\/\?ad=|\.com\/ad\?|\/adfox\/|\?adfox_|\.com\/js\/ad\.|\/campaign\/advertiser_|\/video\-ads\-management\.|\/analytics\/track\-|\/analytics\/track\.|\/analytics\/track\/|\/analytics\/track\?|\/analytics\/track$|\/getad\/|\/getad\?|\-social\-media\.|\/social_media_|_social\-media_|\/\?addyn$|\/video\-ads\-player\.|\/cookie\-law\.js|\/cookie_law\.js|_cookie_law\.js|\/assets\/js\/ad\.|&adurl=|\/_\/ads\/|\/img\-advert\-|\/wp\-content\/ads\/|\/amp\-ad\-|\/bin\/stats\?|\/masthead\/social\-|\/my\-ad\-injector\/|\-share\-button\.|\/share\-button\.|\/share\-button\?|\/share_button\.|\/share_button\?|\/share_button_|\/adition\.|\.com\/adz\/|\/show\-ad\.|\/show\.ad\?|\/show_ad\.|\/show_ad\?|\/follow\-us\-twitter\.|\/intelliad\.|\/clickability\-|\/clickability\/|\/clickability\?|_clickability\/|\/images\/ad2\/|\/adsmanager\/|\-socialmedia\-sprite\.|\-ad\-pixel\-|\-image\-ad\.|\/image\/ad\/|\/ad\/display\.php|\/adx\/iframe\.|\/adx_iframe_|\.com\/stats\.ashx\?|\/ero\-advertising\.|\/img\/facebook\-|\/img\/facebook\.|\/img\/facebook_|\/widget\-advert\.|\/iframes\/ad\/|\.sharebar\.js|\/admeta\.|=admeta&|\/leaderboard\-advert\.|\?affiliate=|\/ga_social_tracking_|\/advertisments\/|\/toonad\.|\/adiframe\.|\/adiframe\/|\/adiframe\?|\/adiframe_|\/pop_ad\.|_pop_ad\.|_pop_ad\/|\/adguru\.|\/ad_campaigns\/|\/utep_ad\.js|\/adv\-expand\/|\/adrolays\.|\/social\-traffic\-pop\/|\/adx\-exchange\.|\.tv\/log\?event|\.net\/ads\-|\.net\/ads\.|\.net\/ads\/|\.net\/ads\?|\.net\/ads_|\/cpx\-advert\/|\/ajax\/optimizely\-|\/cookie\-master\.js|\/js\/oas\-|\/js\/oas\.|\/ad\/img\/|\/ad_img\.|\/ad_img\/|\/advlink\.|\/site_under\.|\/adwizard\.|\/adwizard\/|\/adwizard_|\/pixel\/stream\/|\/google\/analytics\.js|\/adverthorisontalfullwidth\.|\.AdmPixelsCacheController\?|\/adaptvexchangevastvideo\.|\/ForumViewTopicContentAD\.|\/postprofilehorizontalad\.|=adreplacementWrapperReg\.|\/adClosefeedbackUpgrade\.|\/adzonecenteradhomepage\.|\/ForumViewTopicBottomAD\.|\/adtest\.|\/adtest\/|\/advertisementrotation\.|\/advertisingimageexte\/|\/AdvertisingIsPresent6\?|\/postprofileverticalad\.|\/adblockdetectorwithga\.|\/admanagementadvanced\.|\/advertisementmapping\.|\/initlayeredwelcomead\-|\/advertisementheader\.|\/advertisingcontent\/|\/advertisingwidgets\/|\/thirdpartyframedad\/|\.AdvertismentBottom\.|\/adfrequencycapping\.|\/adgearsegmentation\.|\/advertisementview\/|\/advertising300x250\.|\/advertverticallong\.|\/AdZonePlayerRight2\.|\/ShowInterstitialAd\.|\-web\-advert\-|_web\-advert\.|\/addeliverymodule\/|\/adinsertionplugin\.|\/AdPostInjectAsync\.|\/adrendererfactory\.|\/advertguruonline1\.|\/advertisementAPI\/|\/advertisingbutton\.|\/advertisingmanual\.|\/advertisingmodule\.|\/adzonebelowplayer\.|\/adzoneplayerright\.|\/jumpstartunpaidad\.|\?adtechplacementid=|\/adforgame160x600\.|\/adleaderboardtop\.|\/adpositionsizein\-|\/adreplace160x600\.|\/advertise125x125\.|\/advertisement160\.|\/advertiserwidget\.|\/advertisinglinks_|\/advFrameCollapse\.|\/requestmyspacead\.|\/supernorthroomad\.|\/adblockdetection\.|\/adBlockDetector\/|\/jsad\/|\/adbriteincleft2\.|\/adbriteincright\.|\/adchoicesfooter\.|\/adgalleryheader\.|\/adindicatortext\.|\/admatcherclient\.|\/adoverlayplugin\.|\/adreplace728x90\.|\/adtaggingsubsec\.|\/adtagtranslator\.|\/adultadworldpop_|\/advertisements2\.|\/advertisewithus_|\/adWiseShopPlus1\.|\/adwrapperiframe\.|\/contentmobilead\.|\/convertjsontoad\.|\/HompageStickyAd\.|\/mobilephonesad\/|\/sample300x250ad\.|\/tomorrowfocusAd\.|\/adblockDetector\.|\/adforgame728x90\.|\/adforgame728x90_|\/adinteraction\/|\/adaptvadplayer\.|\/adcalloverride\.|\/adfeedtestview\.|\/adframe120x240\.|\/adframewrapper\.|\/adiframeanchor\.|\/adlantisloader\.|\/adlargefooter2\.|\/adpanelcontent\.|\/adverfisement2\.|\/advertisement1\.|\/advertisement2\.|\/advertisement3\.|\/dynamicvideoad\?|\/premierebtnad\/|\/rotatingtextad\.|\/sample728x90ad\.|\/slideshowintad\?|\/adblockchecker\.|\/adblockdetect\.|\/adblockdetect\/|\/adchoicesicon\.|\/adframe728bot\.|\/adframebottom\.|\/adframecommon\.|\/adframemiddle\.|\/adinsertjuicy\.|\/adlargefooter\.|\/adleftsidebar\.|\/admanagement\/|\/adMarketplace\.|\/admentorserve\.|\/adotubeplugin\.|\/adPlaceholder\.|\/advaluewriter\.|\/adverfisement\.|\/advertising02\.|\/advertisment1\-|\/bottomsidead\/|\/getdigitalad\/|\/gigyatargetad\.|\/gutterspacead\.|\/leaderboardad\.|\/newrightcolad\.|\/promobuttonad\.|\/rawtubelivead\.|\/restorationad\-|=admodeliframe&|\/adblockkiller\.|\/advs\/|\/addpageview\/|\/admonitoring\.|&customSizeAd=|\-printhousead\-|\.advertmarket\.|\/AdBackground\.|\/adcampaigns\/|\/adcomponent\/|\/adcontroller\.|\/adfootcenter\.|\/adframe728b2\.|\/adifyoverlay\.|\/admeldscript\.|\/admentor302\/|\/admentorasp\/|\/adnetwork300\.|\/adnetwork468\.|\/AdNewsclip14\.|\/AdNewsclip15\.|\/adoptionicon\.|\/adrequisitor\-|\/adTagRequest\.|\/adtechHeader\.|\/adtechscript\.|\/advertisings\.|\/advertsquare\.|\/advertwebapp\.|\/advolatility\.|\/adzonebottom\.|\/adzonelegend\.|\/brightcovead\.|\/contextualad\.|\/custom11x5ad\.|\/horizontalAd\.|\/iframedartad\.|\/indexwaterad\.|\/jsVideoPopAd\.|\/PageBottomAD\.|\/skyscraperad\.|\/writelayerad\.|=dynamicwebad&|\-advertising2\-|\/advertising2\.|\/advtemplate\/|\/advtemplate_|\/adimppixel\/|\-adcompanion\.|\-adtechfront\.|\-advertise01\.|\-rightrailad\-|\/728x80topad\.|\/adchoices16\.|\/adchoicesv4\.|\/adcollector\.|\/adcontainer\?|\/addelivery\/|\/adfeedback\/|\/adfootright\.|\/adfoxLoader_|\/adframe728a\.|\/adframe728b\.|\/adfunctions\.|\/adgenerator\.|\/adgraphics\/|\/adhandlers2\.|\/adheadertxt\.|\/adhomepage2\.|\/adiframetop\.|\/admanagers\/|\/admetamatch\?|\/adpictures\/|\/adpolestar\/|\/adPositions\.|\/adproducts\/|\/adrequestvo\.|\/adrollpixel\.|\/adtopcenter\.|\/adtopmidsky\.|\/advcontents\.|\/advertises\/|\/advertlayer\.|\/advertright\.|\/advscripts\/|\/adzoneright\.|\/asyncadload\.|\/crossoverad\-|\/dynamiccsad\?|\/gexternalad\.|\/indexrealad\.|\/instreamad\/|\/internetad\/|\/lifeshowad\/|\/newtopmsgad\.|\/o2contentad\.|\/propellerad\.|\/showcasead\/|\/showflashad\.|\/SpotlightAd\-|_companionad\.|\.adplacement=|\/adplacement\.|\/adversting\/|\/adversting\?|\/vs\-track\.js|\-NewStockAd\-|\.adgearpubs\.|\.rolloverad\.|\/300by250ad\.|\/adbetween\/|\/adbotright\.|\/adboxtable\-|\/adbriteinc\.|\/adchoices2\.|\/adcontents_|\/AdElement\/|\/adexclude\/|\/adexternal\.|\/adfillers\/|\/adflashes\/|\/adfliction\-|\/adFooterBG\.|\/adfootleft\.|\/adformats\/|\/adframe120\.|\/adframe468\.|\/adframetop\.|\/adhandlers\-|\/adhomepage\.|\/adiframe18\.|\/adiframem1\.|\/adiframem2\.|\/adInfoInc\/|\/adlanding\/|\/admanager3\.|\/admanproxy\.|\/adorika300\.|\/adorika728\.|\/adoverride\.|\/adperfdemo\.|\/AdPreview\/|\/adprovider\.|\/adquality\/|\/adreplace\/|\/adrequests\.|\/adrevenue\/|\/adrightcol\.|\/adrotator2\.|\/adtextmpu2\.|\/adtopright\.|\/adv180x150\.|\/advertical\.|\/advertmsig\.|\/advertphp\/|\/advertpro\/|\/advertrail\.|\/advertstub\.|\/adviframe\/|\/advlink300\.|\/advrotator\.|\/advtarget\/|\/AdvWindow\/|\/adwidgets\/|\/adWorking\/|\/adwrapper\/|\/adxrotate\/|\/AdZoneAdXp\.|\/adzoneleft\.|\/baselinead\.|\/deliverad\/|\/DynamicAd\/|\/getvideoad\.|\/lifelockad\.|\/lightboxad[^\w.%-]|\/neudesicad\.|\/onplayerad\.|\/photo728ad\.|\/postprocad\.|\/pushdownAd\.|\/PVButtonAd\.|\/rotationad\.|\/sidelinead\.|\/slidetopad\.|\/tripplead\/|\?adlocation=|\?adunitname=|_preorderad\.|\-adrotation\.|\/adgallery2\.|\/adgallery2$|\/adgallery3\.|\/adgallery3$|\/adinjector\.|\/adinjector_|\/adpicture1\.|\/adpicture1$|\/adpicture2\.|\/adpicture2$|\/adrotation\.|\/externalad\.|_externalad\.|\/adcontrol\.|\/adcontrol\/|\/adinclude\.|\/adinclude\/|\/adkingpro\-|\/adkingpro\/|\/adoverlay\.|\/adoverlay\/|&adgroupid=|&adpageurl=|\-Ad300x250\.|\/125x125ad\.|\/300x250ad\.|\/ad125x125\.|\/ad160x600\.|\/ad1x1home\.|\/ad2border\.|\/ad2gather\.|\/ad300home\.|\/ad300x145\.|\/ad600x250\.|\/ad600x330\.|\/ad728home\.|\/adactions\.|\/adasset4\/|\/adbayimg\/|\/adblock26\.|\/adbotleft\.|\/adcentral\.|\/adchannel_|\/adclutter\.|\/adengage0\.|\/adengage1\.|\/adengage2\.|\/adengage3\.|\/adengage4\.|\/adengage5\.|\/adengage6\.|\/adexample\?|\/adfetcher\?|\/adfolder\/|\/adforums\/|\/adframes\/|\/adheading_|\/adiframe1\.|\/adiframe2\.|\/adiframe7\.|\/adiframe9\.|\/adinator\/|\/AdLanding\.|\/adLink728\.|\/adlock300\.|\/admarket\/|\/admeasure\.|\/admentor\/|\/adNdsoft\/|\/adonly468\.|\/adopspush\-|\/adoptions\.|\/adreclaim\-|\/adrelated\.|\/adrequest\.|\/adRequest\?|\/adruptive\.|\/adtopleft\.|\/adunittop$|\/advengine\.|\/advertize_|\/advertsky\.|\/adverttop\.|\/advfiles\/|\/adviewas3\.|\/advloader\.|\/advscript\.|\/advzones\/|\/adwriter2\.|\/adyard300\.|\/adzonetop\.|\/contentAd\.|\/contextad\.|\/delayedad\.|\/devicead\/|\/dynamicad\?|\/galleryad\.|\/getTextAD\.|\/GetVASTAd\?|\/invideoad\.|\/MonsterAd\-|\/overlayad\.|\/PageTopAD\.|\/pitattoad\.|\/prerollad\.|\/processad\.|\/proxxorad\.|\/showJsAd\/|\/siframead\.|\/slideinad\.|\/sliderAd\/|\/spiderad\/|\/testingad\.|\/tmobilead\.|\/unibluead\.|\/vert728ad\.|\/vplayerad\.|\/VXLayerAd\-|\/webmailad\.|\/welcomead\.|=DisplayAd&|\?adcentric=|\?adcontext=|\?adflashid=|\?adversion=|\?advsystem=|\/admonitor\-|\/admonitor\.|\/adrefresh\-|\/adrefresh\.|\/defaultad\.|\/defaultad\?|\/adbroker\.|\/adbroker\/|\/adconfig\.|\/adconfig\/|\/addefend\.|\/addefend\/|\/adfactor\/|\/adfactor_|\/adwidget\/|\/adwidget_|\/bottomad\.|\/bottomad\/|\/buttonad\/|_buttonad\.|&adclient=|\/adclient\-|\/adclient\.|\/adclient\/|\-Ad300x90\-|\-adcentre\.|\-adhelper\.|\/768x90ad\.|\/ad120x60\.|\/ad1place\.|\/ad290x60_|\/ad468x60\.|\/ad468x80\.|\/AD728cat\.|\/ad728rod\.|\/adarena\/|\/adasset\/|\/adblockl\.|\/adblockr\.|\/adborder\.)/i;
var bad_url_parts_flag = 1099 > 0 ? true : false;  // test for non-zero number of rules
    
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
"23.2.145.78,       255.255.255.255",
"23.39.179.17,      255.255.255.255",
"23.63.98.0,        255.255.254.0",
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
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]*)(\\??\\S*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24})\\.?", "i");

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

// EasyList filtering for FindProxyForURL(url, host)
function EasyListFindProxyForURL(url, host)
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
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
                return proxy;
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////

        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
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
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
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
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON," + host_noserver + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON," + host + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noservernoquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(" + host_noserver + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(" + host + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(" + url_noservernoquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(" + url_noquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(" + url_noserver + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(" + url_noscheme + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(" + url + "): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url)));
            alert("bad_url_regex_RegExp.test(" + url + "): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole: " + url + ", " + host);
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
    return proxy;
}

// User-supplied FindProxyForURL()
function FindProxyForURL(url, host)
{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
   dnsDomainIs(host, ".local") ||
   (url.substring(0,4) == "ftp:")
)
        return "DIRECT";
else
        return EasyListFindProxyForURL(url, host);
}   
