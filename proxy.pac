// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Mon, 11 Dec 2017 00:28:45 GMT
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

// 966 rules:
var bad_da_host_JSON = { "jobthread.com": null,
"content.ad": null,
"megabanners.cf": null,
"nastydollars.com": null,
"adziff.com": null,
"spade.twitch.tv": null,
"ad.doubleclick.net": null,
"pagead2.googlesyndication.com": null,
"popads.net": null,
"2mdn.net": null,
"serving-sys.com": null,
"padsdel.com": null,
"adchemy-content.com": null,
"adap.tv": null,
"admitad.com": null,
"ltassrv.com.s3.amazonaws.com": null,
"contentspread.net": null,
"scorecardresearch.com": null,
"chartbeat.com": null,
"static.parsely.com": null,
"adnxs.com": null,
"nuggad.net": null,
"optimizely.com": null,
"adform.net": null,
"dashad.io": null,
"smartadserver.com": null,
"clicktale.net": null,
"teads.tv": null,
"webtrekk.net": null,
"movad.net": null,
"xing-share.com": null,
"addthis.com": null,
"intelliad.de": null,
"gitcdn.pw": null,
"mxcdn.net": null,
"krxd.net": null,
"adverserve.net": null,
"ip-adress.com": null,
"rlcdn.com": null,
"adskeeper.co.uk": null,
"stroeerdigitalmedia.de": null,
"visualwebsiteoptimizer.com": null,
"adsafeprotected.com": null,
"hotjar.com": null,
"flashtalking.com": null,
"crwdcntrl.net": null,
"padstm.com": null,
"share.baidu.com": null,
"cpx.to": null,
"adition.com": null,
"mediaplex.com": null,
"propvideo.net": null,
"coinad.com": null,
"hpr.outbrain.com": null,
"cm.g.doubleclick.net": null,
"banners.cams.com": null,
"bluekai.com": null,
"openx.net": null,
"taboola.com": null,
"quantserve.com": null,
"adx.kat.ph": null,
"ipinyou.com.cn": null,
"clickfunnels.com": null,
"ad.userporn.com": null,
"adapd.com": null,
"complexmedianetwork.com": null,
"log.pinterest.com": null,
"ad.rambler.ru": null,
"advertising.com": null,
"firstclass-download.com": null,
"ebayobjects.com.au": null,
"bongacams.com": null,
"log.outbrain.com": null,
"pixel.facebook.com": null,
"metrics.brightcove.com": null,
"chartaca.com.s3.amazonaws.com": null,
"videoplaza.com": null,
"dnn506yrbagrg.cloudfront.net": null,
"tracking-rce.veeseo.com": null,
"adspayformymortgage.win": null,
"videoplaza.tv": null,
"3wr110.xyz": null,
"ero-advertising.com": null,
"abbp1.website": null,
"abbp1.science": null,
"adk2.co": null,
"widget.crowdignite.com": null,
"htmlhubing.xyz": null,
"juicyads.com": null,
"adonweb.ru": null,
"adtrace.org": null,
"advertserve.com": null,
"sharecash.org": null,
"onad.eu": null,
"adcash.com": null,
"mobsterbird.info": null,
"explainidentifycoding.info": null,
"exoclick.com": null,
"am10.ru": null,
"admedit.net": null,
"adk2.com": null,
"vrp.outbrain.com": null,
"vrt.outbrain.com": null,
"adexc.net": null,
"sexad.net": null,
"adbooth.com": null,
"hornymatches.com": null,
"heapanalytics.com": null,
"clicksor.com": null,
"b.photobucket.com": null,
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"xclicks.net": null,
"august15download.com": null,
"bentdownload.com": null,
"adultadworld.com": null,
"admngronline.com": null,
"clicksor.net": null,
"adxpansion.com": null,
"venturead.com": null,
"ad-maven.com": null,
"ad4game.com": null,
"adplxmd.com": null,
"adrunnr.com": null,
"ad131m.com": null,
"ad2387.com": null,
"adnium.com": null,
"adxite.com": null,
"adbma.com": null,
"adk2x.com": null,
"widget.yavli.com": null,
"prpops.com": null,
"popwin.net": null,
"rapidyl.net": null,
"hd-plugin.com": null,
"contentabc.com": null,
"insta-cash.net": null,
"propellerpops.com": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"downloadboutique.com": null,
"stats.bitgravity.com": null,
"popcash.net": null,
"brandreachsys.com": null,
"youradexchange.com": null,
"c4tracking01.com": null,
"adjuggler.net": null,
"admaster.com.cn": null,
"perfcreatives.com": null,
"xtendmedia.com": null,
"livepromotools.com": null,
"ad6media.fr": null,
"media-servers.net": null,
"888media.net": null,
"clicktripz.com": null,
"click.scour.com": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"sharethis.com": null,
"clicksvenue.com": null,
"terraclicks.com": null,
"statsmobi.com": null,
"clicksgear.com": null,
"onclickmax.com": null,
"poponclick.com": null,
"clickfuse.com": null,
"clickmngr.com": null,
"toroadvertisingmedia.com": null,
"traffictraffickers.com": null,
"clickosmedia.com": null,
"mediaseeding.com": null,
"pgmediaserve.com": null,
"waframedia5.com": null,
"wigetmedia.com": null,
"pwrads.net": null,
"whoads.net": null,
"trafficholder.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"adcdnx.com": null,
"partners.yobt.tv": null,
"shareaholic.com": null,
"adfox.yandex.ru": null,
"track.xtrasize.nl": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"pointclicktrack.com": null,
"onclickads.net": null,
"360adstrack.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"adscpm.net": null,
"ads.yahoo.com": null,
"adsmarket.com": null,
"hipersushiads.com": null,
"propellerads.com": null,
"epicgameads.com": null,
"affbuzzads.com": null,
"megapopads.com": null,
"down1oads.com": null,
"popmyads.com": null,
"filthads.com": null,
"1phads.com": null,
"alternads.info": null,
"showcase.vpsboard.com": null,
"ad.mail.ru": null,
"basilic.netdna-cdn.com": null,
"doubleclick.net": null,
"imgrock.net": null,
"pos.baidu.com": null,
"collector.contentexchange.me": null,
"smi2.ru": null,
"xxxmatch.com": null,
"eclick.baidu.com": null,
"ct.pinterest.com": null,
"tostega.ru": null,
"pixel.ad": null,
"adhealers.com": null,
"adtgs.com": null,
"iwebanalyze.com": null,
"trackvoluum.com": null,
"fastclick.net": null,
"bestforexplmdb.com": null,
"hilltopads.net": null,
"flagads.net": null,
"lightson.vpsboard.com": null,
"getclicky.com": null,
"shareasale.com": null,
"adbetclickin.pink": null,
"adsjudo.com": null,
"pulseonclick.com": null,
"trafficbroker.com": null,
"trafficstars.com": null,
"33traffic.com": null,
"nextlandingads.com": null,
"adexchangecloud.com": null,
"adblade.com": null,
"adglare.org": null,
"bzclk.baidu.com": null,
"gsp1.baidu.com": null,
"kissmetrics.com": null,
"histats.com": null,
"creativecdn.com": null,
"pubads.g.doubleclick.net": null,
"vserv.bc.cdn.bitgravity.com": null,
"printfriendly.com": null,
"ad.reachlocal.com": null,
"topbinaryaffiliates.ck-cdn.com": null,
"hawkeye-data-production.sciencemag.org.s3-website-us-east-1.amazonaws.com": null,
"pixel.buzzfeed.com": null,
"adv.drtuber.com": null,
"fls-eu.amazon.com": null,
"microad.jp": null,
"pr-static.empflix.com": null,
"ad.smartclip.net": null,
"s11clickmoviedownloadercom.maynemyltf.netdna-cdn.com": null,
"tagcdn.com": null,
"addtoany.com": null,
"video-ad-stats.googlesyndication.com": null,
"perfectmarket.com": null,
"youroffers.win": null,
"xs.mochiads.com": null,
"plugin.ws": null,
"analytics.163.com": null,
"affiliatesmedia.sbobet.com": null,
"tracking.moneyam.com": null,
"cookiechoices.org": null,
"deliberatelyvirtuallyshared.xyz": null,
"cookielaw.org": null,
"ad5871bb0eeb.online": null,
"cookies.unidadeditorial.es": null,
"onlinereserchstatistics.online": null,
"widgets.fbshare.me": null,
"survey.io": null,
"webcams.com": null,
"cookies.fakt.pl": null,
"socialhoney.co": null,
"affiliate.burn-out.tv": null,
"ad.spielothek.so": null,
"pixiedust.buzzfeed.com": null,
"bonzai.ad": null,
"ingame.ad": null,
"spider.ad": null,
"affiliatehub.skybet.com": null,
"adcamel.pw": null,
"ams.addflow.ru": null,
"popunderjs.com": null,
"count.livetv.ru": null,
"affiliate.mediatemple.net": null,
"affiliate.godaddy.com": null,
"premium.naturalnews.tv": null,
"pixel.wp.com": null,
"adc.stream.moe": null,
"webcounter.ws": null,
"adhafera.xyz": null,
"advserver.xyz": null,
"skryptcookies.pl": null,
"affiliates-cdn.mozilla.org": null,
"share.yandex.ru": null,
"affiliate.mercola.com": null,
"affiliates.lynda.com": null,
"static.kinghost.com": null,
"whatismyip.win": null,
"affiliates.minglematch.com": null,
"affiliates.picaboocorp.com": null,
"affiliates.franchisegator.com": null,
"mansiontheologysoon.xyz": null,
"partner.video.syndication.msn.com": null,
"totemcash.com": null,
"backlogtop.xyz": null,
"affiliates.genealogybank.com": null,
"bannerexchange.com.au": null,
"affiliates.thrixxx.com": null,
"smartcookies.it": null,
"adlink.net": null,
"mycookies.it": null,
"fanconverter.wetpaint.me": null,
"gocp.stroeermediabrands.de": null,
"cookie.oup.com": null,
"facebooker.top": null,
"affiliate.iamplify.com": null,
"adnext.org": null,
"affiliate.resellerclub.com": null,
"adne.tv": null,
"clicktalecdn.sslcs.cdngc.net": null,
"cookietracker.cloudapp.net": null,
"profitshare.ro": null,
"bid.g.doubleclick.net": null,
"popunder.ru": null,
"affiliates.galapartners.co.uk": null,
"affiliates.mozy.com": null,
"affiliateprogram.keywordspy.com": null,
"affiliates.vpn.ht": null,
"toolbar.complex.com": null,
"affiliates.mgmmirage.com": null,
"affiliates.goodvibes.com": null,
"affiliates.swappernet.com": null,
"analytic.rocks": null,
"affiliates.treasureisland.com": null,
"affiliates.londonmarketing.com": null,
"adcfrthyo.tk": null,
"beacon.mtgx.tv": null,
"tracker.azet.sk": null,
"analytics.us.archive.org": null,
"affiliate.cx": null,
"analytics-static.ugc.bazaarvoice.com": null,
"cookiescript.info": null,
"affiliates.bookdepository.com": null,
"cache.worldfriends.tv": null,
"video.oms.eu": null,
"adlure.biz": null,
"ad.duga.jp": null,
"advatar.to": null,
"objects.tremormedia.com": null,
"ad.kissanime.io": null,
"volgograd-info.ru": null,
"advertone.ru": null,
"chinagrad.ru": null,
"advertur.ru": null,
"advombat.ru": null,
"advmaker.ru": null,
"ad.kisscartoon.io": null,
"adsmws.cloudapp.net": null,
"fls-fe.amazon.co.jp": null,
"respond-adserver.cloudapp.net": null,
"ad001.ru": null,
"adnext.fr": null,
"analytics.ifood.tv": null,
"liveyourdreamify.pw": null,
"analytics.ettoredelnegro.pro": null,
"s3-tracking.synthasite.net.s3.amazonaws.com": null,
"analytics.wildtangent.com": null,
"adclick.pk": null,
"cookies.forbes.pl": null,
"afimg.liveperson.com": null,
"adaction.se": null,
"webtrack.biz": null,
"cnstats.ru": null,
"track.bluecompany.cl": null,
"sharenice.org": null,
"fdxstats.xyz": null,
"blogads.com": null,
"promotools.biz": null,
"eventful.com": null,
"zanox-affiliate.de": null,
"knowlead.io": null,
"adexchange.io": null,
"adboost.it": null,
"cookies.reedbusiness.nl": null,
"track.atom-data.io": null,
"hm.baidu.com": null,
"optimost.com": null,
"gandrad.org": null,
"porn-ad.org": null,
"layer-ad.org": null,
"adigniter.org": null,
"find-ip-address.org": null,
"adman.gr": null,
"pixel.newscgp.com": null,
"buzzbox.buzzfeed.com": null,
"promo.cams.com": null,
"abeagle-public.buzzfeed.com": null,
"ad2adnetwork.biz": null,
"impact-ad.jp": null,
"analytics.carambatv.ru": null,
"adinte.jp": null,
"adnico.jp": null,
"ad-vice.biz": null,
"advg.jp": null,
"sportsbetaffiliates.com.au": null,
"tracking.vengovision.ru": null,
"cloudflare.solutions": null,
"admaster.net": null,
"blamads-assets.s3.amazonaws.com": null,
"post.rmbn.ru": null,
"pix.speedbit.com": null,
"adtotal.pl": null,
"tracking.oe24.at": null,
"analytics.solidbau.at": null,
"affiliates.homestead.com": null,
"tracking.kurier.at": null,
"1e0y.xyz": null,
"bw94.xyz": null,
"hdat.xyz": null,
"hhit.xyz": null,
"bh8yx.xyz": null,
"retag.xyz": null,
"1xijy.xyz": null,
"gotjs.xyz": null,
"verata.xyz": null,
"3jsbf5.xyz": null,
"56fh8x.xyz": null,
"acamar.xyz": null,
"achird.xyz": null,
"alamak.xyz": null,
"albali.xyz": null,
"pcruxm.xyz": null,
"analytics.proxer.me": null,
"havingo.xyz": null,
"acubens.xyz": null,
"aladfar.xyz": null,
"alaraph.xyz": null,
"albireo.xyz": null,
"or3f3xmk.xyz": null,
"alemoney.xyz": null,
"checkapi.xyz": null,
"mp3toavi.xyz": null,
"69wnz64h.xyz": null,
"ayabreya.xyz": null,
"dascasdw.xyz": null,
"ficusoid.xyz": null,
"gk25qeyc.xyz": null,
"lamiflor.xyz": null,
"panatran.xyz": null,
"peremoga.xyz": null,
"albaldah.xyz": null,
"kxqvnfcg.xyz": null,
"aleinvest.xyz": null,
"quicktask.xyz": null,
"dromorama.xyz": null,
"flac2flac.xyz": null,
"zapstorage.xyz": null,
"asermtawlfs.xyz": null,
"alltheladyz.xyz": null,
"mataharirama.xyz": null,
"clickpartoffon.xyz": null,
"cruftexcision.xyz": null,
"lostelephants.xyz": null,
"1bc169ca9feb0f6a.xyz": null,
"3472ccbc21c3f567.xyz": null,
"inspiringsweater.xyz": null,
"73d761ee7ff20979.xyz": null,
"80b6bbc92507f3fa.xyz": null,
"91d0df83b8560187.xyz": null,
"9b2594854efb1102.xyz": null,
"cd3b74f38059d637.xyz": null,
"honestlypopularvary.xyz": null,
"privilegebedroomlate.xyz": null,
"stabilityappointdaily.xyz": null,
"analytics.codigo.se": null,
"affiliates.myfax.com": null,
"textad.sexsearch.com": null,
"tracker.tiu.ru": null,
"analytics.archive.org": null,
"googleadservices.com": null,
"affiliate.com": null,
"analytics.urx.io": null,
"spylog.ru": null,
"track.revolvermarketing.ru": null,
"ifyoublockthisvideotoo.club": null,
"pixel.watch": null,
"advertica.ae": null,
"analytics.epi.es": null,
"mtrack.nl": null,
"addynamics.eu": null,
"link.link.ru": null,
"event.trove.com": null,
"fairad.co": null,
"adcarem.co": null,
"tracking.to": null,
"log.ren.tv": null,
"oas.skyscanner.net": null,
"adnet.ru": null,
"stats.g.doubleclick.net": null,
"gripdownload.co": null,
"lead.im": null,
"rxlex.faith": null,
"fnro4yu0.loan": null,
"uonj2o6i.loan": null,
"5tcgu99n.loan": null,
"cg1bz6tf.loan": null,
"duscb12r.loan": null,
"mc09j2u5.loan": null,
"ats4m6dr.loan": null,
"cb0xxe0f.loan": null,
"ms3wsmbg.loan": null,
"s997tc81.loan": null,
"kgrfw2mp.date": null,
"6mg38boa.date": null,
"dkf9g61v.date": null,
"dll5uyyj.date": null,
"fg18kvv7.date": null,
"hti9pqmy.date": null,
"n8jofwjp.date": null,
"xlw5e582.date": null,
"survey.g.doubleclick.net": null,
"k9anf8bc.webcam": null,
"ufyvdps3.webcam": null,
"a80zha8c.webcam": null,
"d0z4gwv7.webcam": null,
"wbkaidsc.webcam": null,
"26ohpieu.webcam": null,
"321hlnsb.webcam": null,
"hohv48oi.webcam": null,
"etracker.de": null,
"hitcount.dk": null,
"2ujo8ayw.racing": null,
"j8w4xqtu.racing": null,
"xfwkn8au.racing": null,
"y1xjgfhp.racing": null,
"busyd5s0.faith": null,
"ckdegfi5.faith": null,
"wmrdwhv3.faith": null,
"04xdqcfz.faith": null,
"xbt0izlb.faith": null,
"xmr6v4yg.faith": null,
"analytics.rechtslupe.org": null,
"73qbgex1.cricket": null,
"79ebttm6.cricket": null,
"8hykthze.cricket": null,
"j7gvaliq.cricket": null,
"lxpl6t0t.cricket": null,
"7w8qfy7a.cricket": null,
"97iigfvj.cricket": null,
"cd8iw9mh.cricket": null,
"rxrfb95v.cricket": null,
"x5k0pyxd.cricket": null,
"yhgai58i.cricket": null,
"adchannels.in": null,
"admaya.in": null,
"57cdb5e39630.racing": null,
"70b008710ae8.racing": null,
"e0e0e4195bb7.racing": null,
"748410ed2187.racing": null,
"77beee3f451e.racing": null,
"860dac995620.racing": null,
"e22c62690bd1.racing": null,
"f254b5a7fa4f.racing": null,
"utrack.hexun.com": null,
"1788f63a9a2e67d.date": null,
"2964385495e9278.date": null,
"3671b26803d01a2.date": null,
"66b9c396b3b06a7.date": null,
"98ccb39c305ef1a.date": null,
"cf6d25bb1333544.date": null,
"4d28ae0e559c1ba.webcam": null,
"de56aa68299cfdb.webcam": null,
"1083e30205ef1fb.webcam": null,
"253a2f5cf81dc99.webcam": null,
"56d967f32b31a07.webcam": null,
"a894e35b880ec38.webcam": null,
"b3695449509407d.webcam": null,
"d12bc830b49ad18.webcam": null,
"affiliate.productreview.com.au": null,
"tracker.streamroot.io": null,
"ozon.ru": null,
"metartmoney.met-art.com": null,
"ads.cc": null,
"fast.eager.io": null,
"adrotate.se": null,
"tracking.vid4u.org": null,
"track2.me": null,
"oascentral.hosted.ap.org": null,
"asd.projectfreetv.so": null,
"videos.oms.eu": null,
"adultsense.org": null,
"tracking.hostgator.com": null,
"track.codepen.io": null,
"track.mobicast.io": null,
"oas.luxweb.com": null,
"cnstats.cdev.eu": null,
"google-rank.org": null,
"yourlegacy.club": null,
"webads.co.nz": null,
"livejasmin.tv": null,
"3k4hppja.stream": null,
"4e9wpp17.stream": null,
"7y3bcefa.stream": null,
"9l7y8nel.stream": null,
"ab1eo0rx.stream": null,
"gkol15n1.stream": null,
"tde2wkyv.stream": null,
"476vi285.stream": null,
"kzkjewg7.stream": null,
"widget.wombo.gg": null,
"fungus.online": null,
"analytics.cmg.net": null,
"moneroocean.stream": null,
"genotba.online": null,
"analytics.wetpaint.me": null,
"ep7kpqn8.online": null,
"redstick.online": null,
"glaswall.online": null,
"markboil.online": null,
"fmstigat.online": null,
"adboost.com": null,
"dashgreen.online": null,
"deletemer.online": null,
"flytomars.online": null,
"pornworld.online": null,
"webtracker.jp": null,
"radiatorial.online": null,
"meetthegame.online": null,
"c50ba364a21f.online": null,
"037fd6ae9869.online": null,
"1b01c4e4aef9.online": null,
"60eaae1ac88a.online": null,
"cb13145bd83d.online": null,
"f88da2beba69.online": null,
"fc7fc652fed6.online": null,
"search.twitter.com": null,
"107e470d2ace7d8ecc2.stream": null,
"06a4da9b14a1e89c19b.stream": null,
"5eb91cb67450e702205.stream": null,
"a11a248de054b07d96f.stream": null,
"d7f25580a8da471f141.stream": null,
"adscale.de": null,
"owlanalytics.io": null,
"pixel.xmladfeed.com": null,
"track.qcri.org": null,
"interstitial.glsp.netdna-cdn.com": null,
"visit.homepagle.com": null,
"track.kandle.org": null,
"mobtop.ru": null,
"cloudset.xyz": null,
"j880iceh.party": null,
"39o9mcr2.party": null,
"4t7su0i3.party": null,
"9k5nhbht.party": null,
"ah77llcy.party": null,
"d2aizum1.party": null,
"ezmay9jo.party": null,
"rcersu5g.party": null,
"rhmed6po.party": null,
"lunametrics.wpengine.netdna-cdn.com": null,
"htl.bid": null,
"ad.cooks.com": null,
"ad.evozi.com": null,
"164f9d1bd2933.party": null,
"707e63f068175.party": null,
"b2ce5ba15afd9.party": null,
"2c66b5f66910a.party": null,
"c3caf79a8df36.party": null,
"d27c2fc111e8e.party": null,
"coinhive-proxy.party": null,
"analytics.iraiser.eu": null,
"tracking.novem.pl": null,
"ad.fnnews.com": null,
"banners.alt.com": null,
"ad.icasthq.com": null,
"ad.vidaroo.com": null,
"ad.jamster.com": null,
"ad.idgtn.net": null,
"ad.jamba.net": null,
"ihstats.cloudapp.net": null,
"affiliates.spark.net": null,
"adserve.ph": null,
"tracking.shoptogether.buy.com": null,
"twittericon.com": null,
"webads.nl": null,
"tracking.ustream.tv": null,
"tracker2.apollo-mail.net": null,
"stats.wp.com": null,
"ad.outsidehub.com": null,
"ad.reklamport.com": null,
"ad.lyricswire.com": null,
"ad.foxnetworks.com": null,
"deliv.lexpress.fr": null,
"ad.pickple.net": null,
"ad.directmirror.com": null,
"track.cafemomstatic.com": null,
"ad.mesomorphosis.com": null,
"manager.koocash.fr": null,
"croix.science": null,
"adcount.in": null,
"demande.science": null,
"6xfcmiy0.science": null,
"7t69dbtn.science": null,
"kge1ru01.science": null,
"x5qa0pxy.science": null,
"3592jwlr.science": null,
"8u01616i.science": null,
"c4p69ovw.science": null,
"dlfxyr7b.science": null,
"iocawy99.science": null,
"r91c6tvs.science": null,
"ry0brv6w.science": null,
"sdmf3f5b.science": null,
"sn5wcs89.science": null,
"u4x0ryw1.science": null,
"ad.iloveinterracial.com": null,
"topad.mobi": null,
"livestats.matrix.it": null,
"tracker.publico.pt": null,
"chronophotographie.science": null,
"tracking.mobile.de": null,
"cdn.trafficexchangelist.com": null,
"cookieinformation.com": null,
"affiliates.easydate.biz": null,
"freewheel.mtgx.tv": null,
"geobanner.alt.com": null,
"webtrekk.de": null,
"beacon-1.newrelic.com": null,
"affiliates.bookdepository.co.uk": null,
"explorer.sheknows.com": null,
"cookieassistant.com": null,
"deal.maabm.com": null,
"adwired.mobi": null,
"adpath.mobi": null,
"leadad.mobi": null,
"cookie-script.com": null,
"cookiereports.com": null,
"bshare.cn": null,
"campanja.com": null,
"widget.firefeeder.com": null,
"adclick.lv": null,
"access-analyze.org": null,
"awaps.yandex.ru": null,
"creatives.pichunter.com": null,
"monkeytracker.cz": null,
"stats.propublica.org": null,
"addnow.com": null,
"deals.buxr.net": null,
"demandmedia.s3.amazonaws.com": null,
"facebookofsex.com": null,
"pclick.internal.yahoo.com": null,
"affiliation.planethoster.info": null,
"analytics.tio.ch": null,
"webstat.se": null,
"scriptall.gq": null,
"ad.mediabong.net": null,
"adhome.biz": null,
"widgets.solaramerica.org": null,
"private.camz.": null,
"analytics.websolute.it": null,
"analytics.digitouch.it": null,
"cookiebot.com": null,
"ilapi.ebay.com": null,
"lapi.ebay.com": null,
"twitterforweb.com": null,
"log.idnes.cz": null,
"beacon.gu-web.net": null,
"beacon.squixa.net": null,
"beacon.gutefrage.net": null,
"logger.su": null,
"counter.theconversation.edu.au": null,
"adstest.zaman.com.tr": null,
"affili.st": null,
"media.studybreakmedia.com": null,
"sponsoredby.me": null,
"txjdgm53.win": null,
"7zqr1wpe.win": null,
"as1a6nl8.win": null,
"e3kgk5su.win": null,
"f5xzc55l.win": null,
"fxox4wvv.win": null,
"j4y01i3o.win": null,
"qzgoecv5.win": null,
"3fp43qvh.trade": null,
"6apoopbw.trade": null,
"mbbxbbtm.trade": null,
"p6t4vu6s.trade": null,
"80d43327c1673.win": null,
"1b08b39a3e524.win": null,
"8162bf1e58d95.win": null,
"94a564b26cf87.win": null,
"af56b5faa8d5c.win": null,
"cf09304f5f138.win": null,
"ea38c0b6bbb44.win": null,
"comscore.com": null,
"adku.co": null,
"tracking.ha.rueducommerce.fr": null,
"analytics.gvim.mobi": null,
"adnet.biz": null,
"relead.com": null,
"tracking.conversion-lab.it": null,
"tracking.conversionlab.it": null,
"3ef0cfe35714f932c.trade": null,
"647a4323fe432956c.trade": null,
"b80077a4be3ec4763.trade": null,
"9b0b3f3d9d9255035.trade": null,
"f08253c9a45a7c723.trade": null,
"cookieq.com": null,
"etology.com": null,
"analytics.ooyala.com": null,
"netcounter.de": null,
"affiliategateways.co": null,
"js.stroeermediabrands.de": null,
"ttdetect.staticimgfarm.com": null,
"cdn7.rocks": null,
"pg.buzzfeed.com": null,
"event-listener.air.tv": null,
"yupfiles.club": null,
"facebookicon.net": null,
"visitor-analytics.io": null,
"adslot.com": null,
"celebjihad.com": null,
"tracker.iltrovatore.it": null,
"adtelligence.de": null,
"static.tucsonsentinel.com": null,
"track.24heures.ch": null,
"analytics.belgacom.be": null,
"zoomanalytics.co": null,
"news-whistleout.s3.amazonaws.com": null,
"cellstats.mako.co.il": null,
"pro-advert.de": null,
"filamentapp.s3.amazonaws.com": null,
"bo-videos.s3.amazonaws.com": null,
"adpionier.de": null,
"logger.co.kr": null,
"letsgoshopping.tk": null,
"track.cedsdigital.it": null,
"adrank24.de": null,
"adsrv.us": null,
"track.veedio.it": null,
"trafficfuelpixel.s3-us-west-2.amazonaws.com": null,
"adheart.de": null,
"adtraxx.de": null,
"adprovi.de": null,
"paid4ad.de": null,
"ncdnprorogeraie.lol": null,
"cams.enjoy.be": null,
"ad.spreaker.com": null,
"gus.host": null,
"beacon.wikia-services.com": null,
"beacon.heliumnetwork.com": null,
"beacon.securestudies.com": null,
"vihtori-analytics.fi": null,
"beacon.errorception.com": null,
"gnezdo.ru": null,
"beacon.riskified.com": null,
"beacon.viewlift.com": null,
"adrise.de": null,
"trakksocial.googlecode.com": null,
"nativeads.com": null,
"beacon.nuskin.com": null,
"statistics.m0lxcdn.kukuplay.com": null,
"adzoe.de": null,
"bb-analytics.jp": null,
"cookie.gazeta.pl": null,
"adip.ly": null,
"webtracker.educationconnection.com": null,
"webtracker.apicasystem.com": null,
"stats.searchftps.org": null,
"etracker.com": null,
"arcadebannerexchange.org": null,
"sabin.free.fr": null,
"cloudcoins.co": null,
"analytics.carambo.la": null,
"usocial.pro": null,
"mms.deadspin.com": null,
"entrecard.s3.amazonaws.com": null,
"adbit.co": null,
"inpref.s3.amazonaws.com": null,
"wp-stat.s3.amazonaws.com": null,
"affiliate.dtiserv.com": null,
"bid.run": null,
"trackmkxoffers.se": null,
"analoganalytics.com": null,
"immassets.s3.amazonaws.com": null,
"gfaf-banners.s3.amazonaws.com": null,
"bitx.tv": null,
"laim.tv": null,
"affiliationjs.s3.amazonaws.com": null,
"twitter-badges.s3.amazonaws.com": null,
"magnify360-cdn.s3.amazonaws.com": null,
"tree-pixel-log.s3.amazonaws.com": null,
"engine.gamerati.net": null,
"stat.media": null,
"trace.events": null,
"epowernetworktrackerimages.s3.amazonaws.com": null,
"garss.tv": null,
"ijncw.tv": null,
"affec.tv": null,
"e2yth.tv": null,
"ov8pc.tv": null,
"stat.bilibili.tv": null,
"webstat.kuwo.cn": null,
"advertisingvalue.info": null,
"extend.tv": null,
"clientlog.portal.office.com": null,
"tra.pmdstatic.net": null,
"abtracker.us": null,
"rotaban.ru": null,
"zaehler.tv": null,
"a04296f070c0146f314d-0dcad72565cb350972beb3666a86f246.r50.cf5.rackcdn.com": null,
"viedeo2k.tv": null,
"toptracker.ru": null,
"bat.adforum.com": null,
"bitfalcon.tv": null,
"webstats.com": null,
"stats1.tune.pk": null,
"nativeroll.tv": null,
"depilflash.tv": null,
"directchat.tv": null,
"img.servint.net": null,
"tracker.calameo.com": null,
"webstat.no": null,
"webvisor.ru": null,
"tracking.beilagen-prospekte.de": null,
"tracking.hannoversche.de": null,
"tracking.promiflash.de": null,
"tracking.mvsuite.de": null,
"tracking.netbank.de": null,
"affiliationcash.com": null,
"googleads.g.doubleclick.net": null,
"yupfiles.org": null,
"tracking.plinga.de": null,
"tracking.ladies.de": null,
"tracking.sport1.de": null,
"tracking.tchibo.de": null,
"shinystat.it": null,
"tracking.srv2.de": null,
"fls-eu.amazon.es": null,
"tracking.hrs.de": null,
"adgoi.mobi": null,
"humanclick.com": null,
"analytics.newscred.com": null,
"ad.crichd.in": null,
"adclear.net": null,
"adrich.cash": null,
"analytics.rtbf.be": null,
"clkads.com": null,
"stats.qmerce.com": null,
"tracking.fanbridge.com": null,
"analytics.skyscanner.net": null,
"reportinglogger.my.rightster.com": null,
"profile.bharatmatrimony.com": null,
"adsame.com": null,
"outbrain.com": null };
var bad_da_host_exact_flag = 966 > 0 ? true : false;  // test for non-zero number of rules
    
// 1 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:rcm(?=([\s\S]*?\.amazon\.))\1)/i;
var bad_da_host_regex_flag = 1 > 0 ? true : false;  // test for non-zero number of rules

// 382 rules:
var bad_da_hostpath_JSON = { "nydailynews.com/tracker.js": null,
"ad.atdmt.com/i/a.js": null,
"ad.atdmt.com/i/a.html": null,
"depositfiles.com/stats.php": null,
"facebook.com/plugins/page.php": null,
"assets.pinterest.com/js/pinit.js": null,
"googletagmanager.com/gtm.js": null,
"pornslash.com/images/a.gif": null,
"elb.amazonaws.com/partner.gif": null,
"baidu.com/js/log.js": null,
"domaintools.com/tracker.php": null,
"imagesnake.com/includes/js/pops.js": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"streamcloud.eu/deliver.php": null,
"google-analytics.com/analytics.js": null,
"hulkshare.com/stats.php": null,
"linkconnector.com/traffic_record.php": null,
"autoline-top.com/counter.php": null,
"facebook.com/common/scribe_endpoint.php": null,
"videowood.tv/assets/js/popup.js": null,
"movad.de/c.ount": null,
"plista.com/iframeShowItem.php": null,
"thefile.me/apu.php": null,
"eageweb.com/stats.php": null,
"imagebam.com/download_button.png": null,
"myway.com/gca_iframe.html": null,
"hitleap.com/assets/banner.png": null,
"twitvid.com/api/tracking.php": null,
"cloudfront.net/analytics.js": null,
"turboimagehost.com/p1.js": null,
"newsarama.com/social.php": null,
"allmyvideos.net/player/ova-jw.swf": null,
"cloudfront.net/scripts/js3caf.js": null,
"elb.amazonaws.com/small.gif": null,
"cloudfront.net/log.js": null,
"linkwithin.com/pixel.png": null,
"brightcove.com/1pix.gif": null,
"allafrica.com/img/static/s_trans_nc.gif": null,
"codecguide.com/stats.js": null,
"shink.in/js/script.js": null,
"googletagservices.com/dcm/dcmads.js": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"amazonaws.com/g.aspx": null,
"redtube.com/js/track.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"adimgs.t2b.click/assets/js/ttbir.js": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"sanoma.nl/media/static/images/icon_zienl.png": null,
"zylom.com/pixel.jsp": null,
"google-analytics.com/siteopt.js": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"eastmoney.com/counter.js": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"phpbb.com/theme/images/hosting/hostmonster-downloads.gif": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"pimpandhost.com/static/html/wide_iframe.html": null,
"weibo.com/staticjs/weiboshare.html": null,
"military.com/data/popup/new_education_popunder.htm": null,
"btkitty.org/static/images/880X60.gif": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"sexvideogif.com/msn.js": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"baymirror.com/static/img/bar.gif": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"cdnplanet.com/static/rum/rum.js": null,
"toucharcade.com/wp-content/themes/skin_zero/images/skin_assets/main_skin.jpg": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"tubeplus.me/resources/js/codec.js": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"attorrents.com/static/images/download3.png": null,
"piano-media.com/bucket/novosense.swf": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"breakingburner.com/stats.html": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"ultimatewindowssecurity.com/securitylog/encyclopedia/images/allpartners.swf": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"viglink.com/images/pixel.gif": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"fncstatic.com/static/all/js/geo.js": null,
"assets.tumblr.com/assets/html/iframe/teaser.html": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"images.military.com/pixel.gif": null,
"assets.tumblr.com/assets/html/iframe/o.html": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"video44.net/gogo/yume-h.swf": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"ulogin.ru/js/stats.js": null,
"mailjet.com/statics/js/widget.modal.js": null,
"store.yahoo.net/lib/directron/icons-test02.jpg": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"btkitty.com/static/images/880X60.gif": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"pimpandhost.com/static/html/iframe.html": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"expressen.se/static/scripts/s_code.js": null,
"yourbittorrent.com/downloadnow.png": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"sexier.com/services/adsredirect.ashx": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"shareit.com/affiliate.html": null,
"yourbittorrent.com/images/lumovies.js": null,
"google-analytics.com/cx/api.js": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"myanimelist.net/static/logging.html": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"gstatic.com/gadf/ga_dyn.js": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"dailyfinance.com/tmfstatic/vs.gif": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"ino.com/img/sites/mkt/click.gif": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"google-analytics.com/internal/analytics.js": null,
"belfasttelegraph.co.uk/editorial/web/survey/recruit-div-img.js": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"autorrents.com/static/images/download2.png": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"imgdino.com/gsmpop.js": null,
"watchuseek.com/media/clerc-final.jpg": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"cur.lv/bootstrap/js/bootstrapx-clickover.js": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"watchuseek.com/media/wus-image.jpg": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"unblockedpiratebay.com/static/img/bar.gif": null,
"merchantcircle.com/static/track.js": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"vwdealerdigital.com/cdn/sd.js": null,
"google-analytics.com/ga_exp.js": null,
"lexus.com/lexus-share/js/tracking_omn/s_code.js": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"picturevip.com/imagehost/top_banners.html": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"statig.com.br/pub/setCookie.js": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"cardstore.com/affiliate.jsp": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"amazonaws.com/ad_w_intersitial.html": null,
"dump8.com/js/stat.php": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"kleisauke.nl/static/img/bar.gif": null,
"js.static.m1905.cn/pingd.js": null,
"india.com/ads/jw/ova-jw.swf": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"mycams.com/freechat.php": null,
"hdfree.tv/ad.html": null,
"youwatch.org/vod-str.html": null,
"rlsbb.com/wp-content/uploads/smoke.jpg": null,
"cdn.cdncomputer.com/js/main.js": null,
"sharesix.com/a/images/watch-bnr.gif": null,
"razor.tv/site/servlet/tracker.jsp": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"dl4all.com/data4.files/dpopupwindow.js": null,
"netzero.net/account/event.do": null,
"ecustomeropinions.com/survey/nojs.php": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"skyrock.net/img/pix.gif": null,
"kuiken.co/static/w.js": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"celebstoner.com/assets/images/img/top/420VapeJuice960x90V3.gif": null,
"kitguru.net/wp-content/wrap.jpg": null,
"scotts.com/smg/js/omni/customTracking.js": null,
"pimpandhost.com/images/pah-download.gif": null,
"atom-data.io/session/latest/track.html": null,
"rlsbb.com/wp-content/uploads/izilol.gif": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"jayisgames.com/maxcdn_160x250.png": null,
"cdnmaster.com/sitemaster/sm360.js": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"yavideo.tv/ajaxlog.txt": null,
"vipi.tv/ad.php": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"qbn.com/media/static/js/ga.js": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"letswatchsomething.com/images/filestreet_banner.jpg": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"24.com//flashplayer/ova-jw.swf": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"xbutter.com/js/pop-er.js": null,
"englishgrammar.org/images/30off-coupon.png": null,
"monkeyquest.com/monkeyquest/static/js/ga.js": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"watchseries.eu/images/download.png": null,
"hulu.com/google_conversion_video_view_tracking.html": null,
"fileom.com/img/downloadnow.png": null,
"cbc.ca/video/bigbox.html": null,
"playgirl.com/pg/media/prolong_ad.png": null,
"cash9.org/assets/img/banner2.gif": null,
"limetorrents.cc/static/images/download.png": null,
"d27s92d8z1yatv.cloudfront.net/js/jquery.jw.analitycs.js": null,
"cloudzilla.to/cam/wpop.php": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"streamplay.to/images/videoplayer.png": null,
"onsugar.com/static/ck.php": null,
"v.blog.sohu.com/dostat.do": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"youserials.com/i/banner_pos.jpg": null,
"hunstoncanoeclub.co.uk/media/system/js/modal.js": null,
"newstatesman.com/js/NewStatesmanSDC.js": null,
"friday-ad.co.uk/banner.js": null,
"pinterest.com/v1/urls/count.json": null,
"twitvid.com/mediaplayer/players/tracker.swf": null,
"watchseries.eu/js/csspopup.js": null,
"wagital.com/Wagital-Ads.html": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"fujifilm.com/js/shared/analyzer.js": null,
"gamecopyworld.com/games/i/if6.gif": null,
"ch131.so/images/2etio.gif": null,
"herold.at/images/stathbd.gif": null,
"torrent.cd/images/main_big_msoft.jpg": null,
"rapidvideo.org/images/pl_box_rapid.jpg": null,
"forbesimg.com/assets/js/forbes/fast_pixel.js": null,
"1whois.org/static/popup.js": null,
"pornshare.biz/2.js": null,
"sofascore.com/geoip.js": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"secureupload.eu/gfx/SecureUpload_Banner.png": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"watchuseek.com/flashwatchwus.swf": null,
"imagepix.org/Images/imageput.jpg": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"nabble.com/static/analytics.js": null,
"pubarticles.com/add_hits_by_user_click.php": null,
"beyond.com/common/track/trackgeneral.asp": null,
"imgur.com/albumview.gif": null,
"imgur.com/imageview.gif": null,
"imgur.com/lumbar.gif": null,
"apis.google.com/js/platform.js": null,
"boobieblog.com/submityourbitchbanner3.jpg": null,
"s-msn.com/br/gbl/js/2/report.js": null,
"lightboxcdn.com/static/identity.html": null,
"sportingbet.com.au/sbacontent/puntersparadise.html": null,
"spynews.ro/templates/default/img/face.png": null,
"enigmagroup.org/clients/privatetunnels.swf": null,
"literatureandlatte.com/gfx/buynowaffiliate.jpg": null,
"ultimatewindowssecurity.com/images/patchzone-resource-80x490.jpg": null,
"watchseries.eu/images/affiliate_buzz.gif": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"vbs.tv/tracker.html": null,
"watchfree.to/topright.php": null,
"blog.co.uk/script/blogs/afc.js": null,
"edvantage.com.sg/site/servlet/tracker.jsp": null,
"paper.li/javascripts/analytics.js": null,
"intel.com/sites/wap/global/wap.js": null,
"viralogy.com/javascript/viralogy_tracker.js": null,
"hwbot.org/banner.img": null,
"vixy.net/fb-traffic-pop.js": null,
"oscars.org/scripts/wt_include1.js": null,
"oscars.org/scripts/wt_include2.js": null,
"filmlinks4u.net/twatch/jslogger.php": null,
"static.hltv.org//images/gofastmar.jpg": null,
"top.baidu.com/js/nsclick.js": null,
"static.hltv.org//images/csgofasttakeover.jpg": null,
"torrent.cd/images/big_use.gif": null,
"makeagif.com/parts/fiframe.php": null,
"radio-canada.ca/lib/TrueSight/markerFile.gif": null,
"medorgs.ru/js/counterlog_img.js": null,
"ablacrack.com/popup-pvd.js": null,
"elgg.org/images/hostupon_banner.gif": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"trutv.com/includes/mods/iframes/mgid-blog.php": null,
"serialzz.us/ad.js": null,
"mywot.net/files/wotcert/vipre.png": null,
"flashi.tv/histats.php": null,
"eurotrucksimulator2.com/images/logo_blog.png": null,
"cloudfront.net/track.html": null,
"onegameplace.com/iframe.php": null,
"xcams.com/livecams/pub_collante/script.php": null,
"primewire.in/additional_content.php": null,
"washingtonpost.com/rw/sites/twpweb/js/init/init.track-header-1.0.0.js": null,
"bc.vc/adbcvc.html": null,
"uramov.info/wav/wavideo.html": null,
"flyordie.com/games/online/ca.html": null,
"bonbonme.com/js/rightbanner.js": null,
"magicaffiliateplugin.com/img/mga-125x125.gif": null,
"t3.com/js/trackers.js": null,
"thevideo.me/mba/cds.js": null,
"droidnetwork.net/img/dt-atv160.jpg": null,
"comdirect.de/ccf/img/ecrm2.gif": null,
"playomat.de/sfye_noscript.php": null,
"bit.no.com/assets/images/bity.png": null,
"assets.pinterest.com/pidget.html": null,
"developpez.com/public/js/track.js": null,
"godaddy.com/pageevents.aspx": null,
"d-h.st/assets/img/download1.png": null,
"egg.com/rum/data.gif": null,
"propakistani.pk/wp-content/themes/propakistani/images/776.jpg": null,
"static.hltv.org//images/gofastbg.png": null,
"exchangerates.org.uk/images-NEW/tor.gif": null,
"sourceforge.net/images/mlopen_post.html": null,
"nesn.com/img/nesn-nation/header-dunkin.jpg": null,
"kickass.cd/analytics.js": null,
"nyteknik.se/ver02/javascript/2012_s_code_global.js": null,
"reason.org/UserFiles/web-fin1.gif": null,
"imgadult.com/altiframe.php": null,
"videolan.org/images/events/animated_packliberte.gif": null,
"mailmax.co.nz/login/open.php": null,
"bets4free.co.uk/content/5481b452d9ce40.09507031.jpg": null,
"js.adv.dadapro.net/collector.js/prcy.js": null,
"odnaknopka.ru/stat.js": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"imgbabes.com/ero-foo.html": null,
"wiilovemario.com/images/fc-twin-play-nes-snes-cartridges.png": null,
"script.idgentertainment.de/gt.js": null,
"scriptcopy.com/tpl/phplb/search.jpg": null,
"24video.net/din_new6.php": null,
"niggasbelike.com/wp-content/themes/zeecorporate/images/b.jpg": null,
"shortnews.de/iframes/view_news.cfm": null,
"dict.cc/img/fbplus1.png": null,
"mercuryinsurance.com/static/js/s_code.js": null,
"server4.pro/images/banner.jpg": null,
"yahoo.com/ysmload.html": null,
"ibrod.tv/ib.php": null,
"downloadian.com/assets/banner.jpg": null,
"5star-shareware.com/scripts/5starads.js": null,
"nih.gov/share/scripts/survey.js": null,
"search.triadcars.news-record.com/autos/widgets/featuredautos.php": null,
"messianictimes.com/images/Israel%20Today%20Logo.png": null,
"seesaawiki.jp/img/rainman.gif": null,
"boobieblog.com/TilaTequilaBackdoorBanner2.jpg": null,
"blacklistednews.com/images/July31stPRO.PNG": null,
"o.aolcdn.com/js/mg1.js": null,
"nowehoryzonty.pl/js/cookies.js": null,
"infochoice.com.au/Handler/WidgetV2Handler.ashx": null,
"limetorrentlinkmix.com/rd18/dop.js": null,
"godisageek.com/amazon.png": null };
var bad_da_hostpath_exact_flag = 382 > 0 ? true : false;  // test for non-zero number of rules
    
// 1101 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:bigxvideos\.com\/js\/pops2\.|piano\-media\.com\/uid\/|doubleclick\.net\/adx\/|pinterest\.com\/images\/|pornfanplace\.com\/js\/pops\.|quantserve\.com\/pixel\/|jobthread\.com\/t\/|doubleclick\.net\/adj\/|nydailynews\.com\/img\/sponsor\/|adf\.ly\/_|adultfriendfinder\.com\/banners\/|channel4\.com\/ad\/|platform\.twitter\.com\/js\/button\.|fwmrm\.net\/ad\/|baidu\.com\/ecom|amazonaws\.com\/analytics\.|freakshare\.com\/banner\/|veeseo\.com\/tracking\/|imageshack\.us\/ads\/|google\-analytics\.com\/plugins\/|tubecup\.com\/contents\/content_sources\/|secureupload\.eu\/banners\/|view\.atdmt\.com\/partner\/|widgetserver\.com\/metrics\/|domaintools\.com\/partners\/|deadspin\.com\/sp\/|adultfriendfinder\.com\/javascript\/|chaturbate\.com\/affiliates\/|redtube\.com\/stats\/|oload\.tv\/log|wtprn\.com\/sponsors\/|openload\.co\/log|streamango\.com\/log|bigxvideos\.com\/js\/popu\.|advfn\.com\/tf_|cloudfront\.net\/track|adultfriendfinder\.com\/go\/|photobucket\.com\/track\/|doubleclick\.net\/ad\/|visiblemeasures\.com\/log|xvideos\-free\.com\/d\/|google\-analytics\.com\/gtm\/js|slashgear\.com\/stats\/|hstpnetwork\.com\/ads\/|topbucks\.com\/popunder\/|video\-cdn\.abcnews\.com\/ad_|propelplus\.com\/track\/|twitter\.com\/javascripts\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|cloudfront\.net\/twitter\/|wupload\.com\/referral\/|pop6\.com\/banners\/|sex\.com\/popunder\/|exitintel\.com\/log\/|imagetwist\.com\/banner\/|yahoo\.com\/beacon\/|pornoid\.com\/contents\/content_sources\/|siberiantimes\.com\/counter\/|sawlive\.tv\/ad|doubleclick\.net\/pixel|mediaplex\.com\/ad\/js\/|static\.plista\.com\/tiny\/|gamestar\.de\/_misc\/tracking\/|facebook\.com\/tr\/|facebook\.com\/tr|shareasale\.com\/image\/|adroll\.com\/pixel\/|hothardware\.com\/stats\/|xxxhdd\.com\/contents\/content_sources\/|twitter\.com\/i\/jot|xxvideo\.us\/ad728x15|appspot\.com\/stats|addthis\.com\/live\/|videowood\.tv\/ads|zawya\.com\/ads\/|addthiscdn\.com\/live\/|ru4\.com\/click|yandex\.st\/share\/|yahoo\.com\/track\/|pornalized\.com\/contents\/content_sources\/|chaturbate\.com\/creative\/|google\-analytics\.com\/collect|sextronix\.com\/images\/|daylogs\.com\/counter\/|github\.com\/_stats|amazonaws\.com\/fby\/|vodpod\.com\/stats\/|msn\.com\/tracker\/|xhamster\.com\/ads\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|reddit\.com\/static\/|nytimes\.com\/ads\/|lovefilm\.com\/partners\/|spacash\.com\/popup\/|girlfriendvideos\.com\/ad|citygridmedia\.com\/ads\/|red\-tube\.com\/popunder\/|chameleon\.ad\/banner\/|shareaholic\.com\/analytics_|livedoor\.com\/counter\/|conduit\.com\/\/banners\/|trustpilot\.com\/stats\/|ad\.admitad\.com\/banner\/|primevideo\.com\/uedata\/|videos\.com\/click|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|static\.criteo\.net\/images[^\w.%-]|virool\.com\/widgets\/|hosting24\.com\/images\/banners\/|4tube\.com\/iframe\/|sparklit\.com\/counter\/|phncdn\.com\/iframe|keepvid\.com\/ads\/|cloudfront\.net\/facebook\/|taboola\.com\/tb|facebook\.com\/plugins\/follow|cnn\.com\/ad\-|google\.com\/log|andyhoppe\.com\/count\/|theporncore\.com\/contents\/content_sources\/|3movs\.com\/contents\/content_sources\/|firedrive\.com\/tools\/|kqzyfj\.com\/image\-|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|soundcloud\.com\/event|static\.criteo\.net\/js\/duplo[^\w.%-]|yotv\.co\/ad\/|twitch\.tv\/track\/|videoplaza\.com\/proxy\/distributor\/|googleusercontent\.com\/tracker\/|engadget\.com\/click|soufun\.com\/stats\/|youtube\.com\/pagead\/|cnzz\.com\/stat\.|amazonaws\.com\/publishflow\/|recomendedsite\.com\/addon\/upixel\/|huffingtonpost\.com\/click|bridgetrack\.com\/site\/|drivearchive\.co\.uk\/images\/amazon\.|wired\.com\/event|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|rapidgator\.net\/images\/pics\/|dailymotion\.com\/track\-|dailymotion\.com\/track\/|skysa\.com\/tracker\/|akanoo\.com\/tracker\/|inphonic\.com\/tracking\/|nspmotion\.com\/tracking\/|urlcash\.org\/banners\/|ad\.admitad\.com\/fbanner\/|baidu\.com\/billboard\/pushlog\/|amazon\.com\/clog\/|liutilities\.com\/partners\/|hostgator\.com\/~affiliat\/cgi\-bin\/affiliates\/|filedownloader\.net\/design\/|doubleclick\.net\/pfadx\/ugo\.gv\.1up\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|carbiz\.in\/affiliates\-and\-partners\/|picsexhub\.com\/js\/pops2\.|mochiads\.com\/srv\/|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|ad\.mo\.doubleclick\.net\/dartproxy\/|betwaypartners\.com\/affiliate_media\/|brandcdn\.com\/pixel\/|pixazza\.com\/track\/|sysomos\.com\/track\/|luminate\.com\/track\/|picbucks\.com\/track\/|targetspot\.com\/track\/|turnsocial\.com\/track\/|clickandgo\.com\/booking\-form\-widget|fulltiltpoker\.com\/affiliates\/|youtube\-nocookie\.com\/device_204|ad\.doubleclick\.net\/ddm\/trackclk\/|hulkload\.com\/b\/|wishlistproducts\.com\/affiliatetools\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|amarotic\.com\/Banner\/|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|theolympian\.com\/static\/images\/weathersponsor\/|bluehost\-cdn\.com\/media\/partner\/images\/|livefyre\.com\/tracking\/|phncdn\.com\/images\/banners\/|dailymail\.co\.uk\/i\/pix\/ebay\/|reevoo\.com\/track\/|dailymotion\.com\/logger\/|pichunter\.com\/creatives\/|sitegiant\.my\/affiliate\/|doubleclick\.net\/adx\/wn\.nat\.|ncrypt\.in\/images\/a\/|toucharcade\.com\/wp\-content\/uploads\/skins\/|broadbandgenie\.co\.uk\/widget|ibtimes\.com\/banner\/|vindicosuite\.com\/tracking\/|sabah\.com\.tr\/Statistic\/|dealextreme\.com\/affiliate_upload\/|doubleclick\.net\/pfadx\/mc\.channelnewsasia\.com[^\w.%-]|h2porn\.com\/contents\/content_sources\/|browsershots\.org\/static\/images\/creative\/|media\-imdb\.com\/twilight\/|doubleclick\.net\/pfadx\/blp\.video\/midroll|video\.mediaset\.it\/polymediashowanalytics\/|gstatic\.com\/gen_204|cdn77\.org\/tags\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|doubleclick\.net\/pfadx\/nbcu\.nhl\.|doubleclick\.net\/pfadx\/nbcu\.nhl\/|addthis\.com\/at\/|sulia\.com\/papi\/sulia_partner\.js\/|doubleclick\.net\/pfadx\/tmz\.video\.wb\.dart\/|mixpanel\.com\/track|softpedia\-static\.com\/images\/aff\/|static\.multiplayuk\.com\/images\/w\/w\-|doubleclick\.net\/pfadx\/ndm\.tcm\/|doubleclick\.net\/pfadx\/bzj\.bizjournals\/|chefkoch\.de\/counter|doubleclick\.net\/pfadx\/gn\.movieweb\.com\/|vivatube\.com\/upload\/banners\/|express\.de\/analytics\/|doubleclick\.net\/pfadx\/miniclip\.midvideo\/|doubleclick\.net\/pfadx\/miniclip\.prevideo\/|doubleclick\.net\/pfadx\/ddm\.ksl\/|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|wonderlabs\.com\/affiliate_pro\/banners\/|thebull\.com\.au\/admin\/uploads\/banners\/|imagecarry\.com\/down|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|trove\.com\/identity\/public\/visitor\/|rdio\.com\/media\/images\/affiliate\/|ejpress\.org\/img\/banners\/|whitepages\.ae\/images\/UI\/WS\/|whitepages\.ae\/images\/UI\/SRA\/|whitepages\.ae\/images\/UI\/SRB\/|facebook\.com\/plugins\/subscribe|beacons\.vessel\-static\.com\/xff|blamcity\.com\/log\/|share\-online\.biz\/affiliate\/|inhumanity\.com\/cdn\/affiliates\/|sectools\.org\/shared\/images\/p\/|doubleclick\.net\/pfadx\/nbcu\.nbc\/|sextvx\.com\/static\/images\/tpd\-|autotrader\.co\.za\/partners\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|metromedia\.co\.za\/bannersys\/banners\/|bits\.wikimedia\.org\/geoiplookup|goldmoney\.com\/~\/media\/Images\/Banners\/|questionmarket\.com\/static\/|ultimate\-guitar\.com\/_img\/promo\/takeovers\/|adm\.fwmrm\.net\/p\/mtvn_live\/|nfl\.com\/assets\/images\/hp\-poweredby\-|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|bigrock\.in\/affiliate\/|channel4\.com\/assets\/programmes\/images\/originals\/|tsite\.jp\/static\/analytics\/|storage\.to\/affiliate\/|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|apple\.com\/itunesaffiliates\/|110\.45\.173\.103\/ad\/|doubleclick\.net\/xbbe\/creative\/vast|nmap\.org\/shared\/images\/p\/|seclists\.org\/shared\/images\/p\/|doubleclick\.net\/pfadx\/tmg\.telegraph\.|google\-analytics\.com\/internal\/collect[^\w.%-]|upsellit\.com\/custom\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|doubleclick\.net\/pfadx\/www\.tv3\.co\.nz|nydailynews\.com\/PCRichards\/|whozacunt\.com\/images\/banner_|rt\.com\/static\/img\/banners\/|facebook\.com\/method\/links\.getStats|theseblogs\.com\/visitScript\/|vindicosuite\.com\/track\/|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|cumulus\-cloud\.com\/trackers\/|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|ncrypt\.in\/images\/banner|epictv\.com\/sites\/default\/files\/290x400_|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|couptopia\.com\/affiliate\/|doubleclick\.net\/json|accuradio\.com\/static\/track\/|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|media\.domainking\.ng\/media\/|aerotime\.aero\/upload\/banner\/|rocktv\.co\/adds\/|worldradio\.ch\/site_media\/banners\/|sacbee\.com\/static\/dealsaver\/|googlesyndication\.com\/simgad\/|sourceforge\.net\/log\/|go\.com\/stat\/|ironsquid\.tv\/data\/uploads\/sponsors\/|static\.criteo\.com\/images[^\w.%-]|camwhores\.tv\/banners\/|obox\-design\.com\/affiliate\-banners\/|doubleclick\.net\/pfadx\/muzuoffsite\/|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|koreatimes\.co\.kr\/images\/bn\/|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|adyou\.me\/bug\/adcash|foxadd\.com\/addon\/upixel\/|jugglu\.com\/content\/widgets\/|getreading\.co\.uk\/static\/img\/bg_takeover_|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|dpbolvw\.net\/image\-|themis\-media\.com\/media\/global\/images\/cskins\/|handango\.com\/marketing\/affiliate\/|anrdoezrs\.net\/image\-|doubleclick\.net\/pfadx\/sugar\.poptv\/|condenastdigital\.com\/content|ad2links\.com\/js\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|doubleclick\.net\/pfadx\/CBS\.|coinmarketcap\.com\/static\/sponsored\/|any\.gs\/visitScript\/|socialstreamingplayer\.crystalmedianetworks\.com\/tracker\/|brettterpstra\.com\/wp\-content\/uploads\/|citeulike\.org\/static\/campaigns\/|yea\.xxx\/img\/creatives\/|nudography\.com\/photos\/banners\/|avira\.com\/site\/datatracking|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|doubleclick\.net\/pfadx\/ccr\.|media\.complex\.com\/videos\/prerolls\/|1320wils\.com\/assets\/images\/promo%20banner\/|pussycash\.com\/content\/banners\/|inquirer\.net\/wp\-content\/themes\/news\/images\/wallpaper_|ppc\-coach\.com\/jamaffiliates\/|theday\.com\/assets\/images\/sponsorlogos\/|knco\.com\/wp\-content\/uploads\/wpt\/|watchuseek\.com\/media\/1900x220_|djmag\.co\.uk\/sites\/default\/files\/takeover\/|amazonaws\.com\/btrb\-prd\-banners\/|xscores\.com\/livescore\/banners\/|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|vpnarea\.com\/affiliate\/|borrowlenses\.com\/affiliate\/|thereadystore\.com\/affiliate\/|doubleclick\.net\/adx\/wn\.loc\.|swagmp3\.com\/cdn\-cgi\/pe\/|russian\-dreams\.net\/static\/js\/|preisvergleich\.de\/setcookie\/|ad\.atdmt\.com\/m\/|develop\-online\.net\/static\/banners\/|t5\.ro\/static\/|punterlink\.co\.uk\/images\/storage\/siteban|doubleclick\.net\/pfadx\/csn\.|doubleclick\.net\/pfadx\/muzumain\/|babyblog\.ru\/pixel|vigilante\.pw\/img\/partners\/|uploading\.com\/static\/banners\/|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|voyeurhit\.com\/contents\/content_sources\/|dailymail\.co\.uk\/tracking\/|sharew\.org\/modalfiles\/|allmovieportal\.com\/dynbanner\.|sweed\.to\/affiliates\/|hqfooty\.tv\/ad|safarinow\.com\/affiliate\-zone\/|doubleclick\.net\/pfadx\/nfl\.|debtconsolidationcare\.com\/affiliate\/tracker\/|ad\.atdmt\.com\/s\/|ziffstatic\.com\/jst\/zdvtools\.|bitbond\.com\/affiliate\-program\/|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|justporno\.tv\/ad\/|mcvuk\.com\/static\/banners\/|dota\-trade\.com\/img\/branding_|facebook\.com\/friends\/requests\/log_impressions|chaturbate\.com\/sitestats\/openwindow\/|conde\.io\/beacon|nation\.sc\/images\/banners\/|getadblock\.com\/images\/adblock_banners\/|gaccny\.com\/uploads\/tx_bannermanagement\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|armenpress\.am\/static\/add\/|doubleclick\.net\/pfadx\/ng\.videoplayer\/|visa\.com\/logging\/logEvent|myiplayer\.eu\/ad|wikipedia\.org\/beacon\/|yyv\.co\/track\/|thelodownny\.com\/leslog\/ads\/|smn\-news\.com\/images\/banners\/|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|axandra\.com\/affiliates\/|zanox\-affiliate\.de\/ppv\/|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|bruteforceseo\.com\/affiliates\/|graduateinjapan\.com\/affiliates\/|popeoftheplayers\.eu\/ad|djmag\.com\/sites\/default\/files\/takeover\/|pcr\-online\.biz\/static\/banners\/|tlavideo\.com\/affiliates\/|singlehop\.com\/affiliates\/|bruteforcesocialmedia\.com\/affiliates\/|twitter\.com\/account\/|metroweekly\.com\/tools\/blog_add_visitor\/|thenude\.eu\/affiliates\/|aftonbladet\.se\/blogportal\/view\/statistics|vator\.tv\/tracking\/|casti\.tv\/adds\/|putpat\.tv\/tracking|whatsnewonnetflix\.com\/assets\/blockless\-ad\-|videovalis\.tv\/tracking\/|ziffstatic\.com\/jst\/zdsticky\.|alooma\.io\/track\/|mfcdn\.net\/media\/game321\/|jebril\.com\/sites\/default\/files\/images\/top\-banners\/|live\-porn\.tv\/adds\/|go2cdn\.org\/brand\/|gameyum\.com\/_static\/popup\/|timesinternet\.in\/ad\/|proxysolutions\.net\/affiliates\/|iradio\.ie\/assets\/img\/backgrounds\/|redtube\.com\/trackimps|ooyala\.com\/3rdparty\/comscore_|goodgearguide\.com\.au\/files\/skins\/|arnnet\.com\.au\/files\/skins\/|appwork\.org\/hoster\/banner_|amazonaws\.com\/statics\.reedge\.com\/|jenningsforddirect\.co\.uk\/sitewide\/extras\/|yimg\.com\/nq\/ued\/assets\/flash\/wsclient_|onescreen\.net\/os\/static\/pixels\/|allanalpass\.com\/track\/|desert\.ru\/tracking\/|amazonaws\.com\/streetpulse\/ads\/|talkphotography\.co\.uk\/images\/externallogos\/banners\/|lumfile\.com\/lumimage\/ourbanner\/|sickipedia\.org\/static\/images\/banners\/|rbth\.ru\/widget\/|presscoders\.com\/wp\-content\/uploads\/misc\/aff\/|epimg\.net\/js\/vr\/vrs\.|doubleclick\.net\/adx\/tsg\.|amazon\.com\/gp\/yourstore\/recs\/|graboid\.com\/affiliates\/|mmosite\.com\/sponsor\/|calciomercato\.it\/img\/notizie\/social\/|ask\.com\/servlets\/ulog|shop\.sportsmole\.co\.uk\/pages\/deeplink\/|hdpornphotos\.com\/images\/banner_|totalcmd\.pl\/img\/nucom\.|totalcmd\.pl\/img\/olszak\.|amy\.gs\/track\/|dyo\.gs\/track\/|itweb\.co\.za\/logos\/|sponsor4cash\.de\/script\/|heraldnet\.com\/section\/iFrame_AutosInternetSpecials|hostdime\.com\/images\/affiliate\/|cloudfront\.net\/googleplus\/|tshirthell\.com\/img\/affiliate_section\/|oasap\.com\/images\/affiliate\/|jobs\-affiliates\.ws\/images\/|flashx\.tv\/banner\/|hardsextube\.com\/preroll\/getiton\/|foxtel\.com\.au\/cms\/fragments\/corp_analytics\/|coolsport\.tv\/adtadd\.|doubleclick\.net\/pfadx\/storm\.no\/|lowendbox\.com\/wp\-content\/themes\/leb\/banners\/|bluenile\.ca\/track\/|tehrantimes\.com\/banner\/|getsocial\.io\/widget\/|whistleout\.com\/Widgets\/|s3\.amazonaws\.com\/draftset\/banners\/|schurzdigital\.com\/deals\/widget\/|shinypics\.com\/blogbanner\/|facebook\.com\/audiencenetwork\/|ball2win\.com\/Affiliate\/|doubleclick\.net\/pfadx\/bet\.com\/|bbcchannels\.com\/workspace\/uploads\/|whatsthescore\.com\/logos\/icons\/bookmakers\/|tune\.pk\/plugins\/cb_tunepk\/ads\/|concealednation\.org\/sponsors\/|toolslib\.net\/assets\/img\/a_dvt\/|wykop\.pl\/dataprovider\/diggerwidget\/|getnzb\.com\/img\/partner\/banners\/|sciencecareers\.org\/widget\/|broadbandgenie\.co\.uk\/img\/talktalk\/|talkers\.com\/images\/banners\/|ypcdn\.com\/webyp\/javascripts\/client_side_analytics_|teesupport\.com\/wp\-content\/themes\/ts\-blog\/images\/cp\-|golem\.de\/staticrl\/scripts\/golem_cpx_|plugins\.longtailvideo\.com\/yourlytics|saabsunited\.com\/wp\-content\/uploads\/ban\-|freeporn\.to\/wpbanner\/|geometria\.tv\/banners\/|nigeriafootball\.com\/img\/affiliate_|pixel\.indieclicktv\.com\/annonymous\/|digitalsatellite\.tv\/banners\/|amazonaws\.com\/cdn\.megacpm\.com\/|vitalmtb\.com\/assets\/vital\.aba\-|friedrice\.la\/widget\/|doubleclick\.net\/adi\/|thenude\.eu\/media\/mxg\/|tonefuse\.s3\.amazonaws\.com\/clientjs\/|homoactive\.tv\/banner\/|oodle\.co\.uk\/event\/track\-first\-view\/|allsend\.com\/public\/assets\/images\/|doubleclick\.net\/pfadx\/ssp\.kgtv\/|abplive\.in\/analytics\/|flipkart\.com\/ajaxlog\/visitIdlog|amazonaws\.com\/photos\.offers\.analoganalytics\.com\/|fairfaxregional\.com\.au\/proxy\/commercial\-partner\-solar\/|ticketnetwork\.com\/images\/affiliates\/|porn2blog\.com\/wp\-content\/banners\/|syndication\.twimg\.com\/widgets\/|huuto\.net\/js\/analytic\/|doubleclick\.net\/adx\/CBS\.|slacker\.com\/beacon\/page\/|c\-date\.it\/tracking|googlesyndication\.com\/sadbundle\/|twitter\.com\/abacus|pwpwpoker\.com\/images\/banners\/|twitter\.com\/scribes\/|mtvnimages\.com\/images\/skins\/|ovpn\.to\/ovpn\.to\/banner\/|hancinema\.net\/images\/watch\-now|hottubeclips\.com\/stxt\/banners\/|moneywise\.co\.uk\/affiliate\/|regnow\.img\.digitalriver\.com\/vendor\/37587\/ud_box|totallylayouts\.com\/online\-users\-counter\/|thedomainstat\.com\/filemanager\/userfiles\/banners\/|fastcdn\.me\/js\/snpp\/|linkedin\.com\/img\/|slack\.com\/clog\/track\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|thrixxx\.com\/affiliates\/|standard\.net\/sites\/default\/files\/images\/wallpapers\/|americanfreepress\.net\/assets\/images\/Banner_|schwalbe\.co\.uk\/_webedit\/cached\-images\/174\-37\-38\-0\-0\-37\-38|observer\.com\.na\/images\/banners\/|mightydeals\.s3\.amazonaws\.com\/md_adv\/|sexphoto\.xxx\/sites\/|guru99\.com\/images\/adblocker\/|mtvnservices\.com\/metrics\/|yandex\.ru\/cycounter|akamai\.net\/chartbeat\.|rexcams\.com\/misc\/iframes_new\/|eccie\.net\/buploads\/|multiupload\.nl\/popunder\/|tourradar\.com\/def\/partner|speedtest\.net\/flash\/59rvvrpc\-|speedtest\.net\/flash\/60speedify|glam\.com\/gad\/|nijobfinder\.co\.uk\/affiliates\/|desperateseller\.co\.uk\/affiliates\/|amazonaws\.com\/searchdiscovery\-satellite\-production\/|vipstatic\.com\/mars\/|coolsport\.tv\/lshadd\.|bitreactor\.to\/sponsor\/|ehow\.com\/services\/jslogging\/log\/|irv2\.com\/images\/sponsors\/|early\-birds\.fr\/tracker\/|bwwstatic\.com\/socialtop|cbc\.ca\/g\/stats\/|daily\-mail\.co\.zm\/images\/banners\/|createtv\.com\/CreateProgram\.nsf\/vShowcaseFeaturedSideContentByLinkTitle\/|adm24\.de\/hp_counter\/|crimeaware\.co\.za\/files\-upload\/banner\/|ab\-in\-den\-urlaub\.de\/usertracking\/|fapdick\.com\/uploads\/fap_|fapdick\.com\/uploads\/1fap_|tvbrowser\.org\/logo_df_tvsponsor_|net\-parade\.it\/tracker\/|washingtonpost\.com\/wp\-srv\/javascript\/placeSiteMetrix\.|intercom\.io\/gtm_tracking\/|aravot\.am\/banner\/|kbcradio\.eu\/img\/banner\/|uploaded\.to\/img\/public\/|kaango\.com\/feCustomWidgetDisplay\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|xcritic\.com\/images\/rent\-|torrent\.cd\/images\/banner\-|eyetopics\.com\/content_images\/|ssshoesss\.ro\/banners\/|rough\-polished\.com\/upload\/bx\/|adsl2exchanges\.com\.au\/images\/spintel|anilinkz\.com\/img\/leftsponsors\.|anilinkz\.com\/img\/rightsponsors|static\.criteo\.net\/design[^\w.%-]|yimg\.com\/uq\/syndication\/|worldarchitecturenews\.com\/banner\/|putana\.cz\/banners\/|glamour\.cz\/banners\/|googletagservices\.com\/tag\/static\/|wp\.com\/wp\-content\/mu\-plugins\/post\-flair\/|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|galleries\.bz\/track\/|sitebooster\.com\/sb\/wix\/p|policeprofessional\.com\/files\/banners\-|theatm\.info\/images\/|yourdailypornstars\.com\/nothing\/|amazon\.com\/gp\/forum\/email\/tracking|carambo\.la\/analytics\/|wank\.to\/partner\/|babesandstars\.com\/images\/a\/|golem\.de\/staticrl\/scripts\/golem_cpxl_|download\.bitdefender\.com\/resources\/media\/|videos\.mediaite\.com\/decor\/live\/white_alpha_60\.|klfm967\.co\.uk\/resources\/creative\/|piratefm\.co\.uk\/resources\/creative\/|virtualhottie2\.com\/cash\/tools\/banners\/|c21media\.net\/wp\-content\/plugins\/sam\-images\/|projectfreetv\.ch\/adblock\/|bermudasun\.bm\/stats\/|sagoodnews\.co\.za\/templates\/ubuntu\-deals\/|filepost\.com\/static\/images\/bn\/|vigrax\.pl\/banner\/|chelsey\.co\.nz\/uploads\/Takeovers\/|camwhores\.tv\/contents\/other\/player\/|bettyconfidential\.com\/media\/fmads\/|vidzi\.tv\/mp4|free\-tv\-video\-online\.me\/episode\-buttom\-|flipkart\.com\/affiliateWidget\/|wiwo\.de\/analytics\/|videopediaworld\.com\/nuevo\/plugins\/midroll\.|playboy\.com\/libs\/analytics\/|mcjonline\.com\/filemanager\/userfiles\/banners\/|medizinauskunft\.de\/logger\/|fr\-online\.de\/analytics\/|draugiem\.lv\/lapas\/widgets\/|tagesspiegel\.de\/analytics\/|channelonline\.tv\/channelonline_advantage\/|berliner\-zeitung\.de\/analytics\/|yporn\.tv\/uploads\/flv_player\/midroll_images\/|schwalbe\.co\.uk\/_webedit\/cached\-images\/172\-37\-38\-0\-0\-37\-38|tampermonkey\.net\/bner\/|tvducky\.com\/imgs\/graboid\.|sis\.amazon\.com\/iu|eclipse\.org\/membership\/promo\/images\/|logotv\.com\/content\/skins\/|joblet\.jp\/javascripts\/|blip\.fm\/ad\/|comicbookresources\.com\/assets\/images\/skins\/|wowhead\.com\/uploads\/skins\/|f\-picture\.net\/Misc\/JumpClick|services\.webklipper\.com\/geoip\/|mbsvr\.net\/js\/tracker\/|streamtheworld\.com\/ondemand\/creative|dailyhome\.com\/leaderboard_banner|sxc\.hu\/img\/banner|annistonstar\.com\/leaderboard_banner|pushsquare\.com\/wp\-content\/themes\/pushsquare\/skins\/|wksu\.org\/graphics\/banners\/|staticlp\.com\/analytics\/|m6web\.fr\/statsd\/|otik\.de\/tracker\/|google\.com\/pagead|deadspin\.com[^\w.%-](?=([\s\S]*?\/trackers\.html))\1|nydailynews\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\2|bitgravity\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\3|facebook\.com[^\w.%-](?=([\s\S]*?\/tracking\.js))\4|youporn\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\5|clickfunnels\.com[^\w.%-](?=([\s\S]*?\/track))\6|stuff\.co\.nz[^\w.%-](?=([\s\S]*?\/track\.min\.js))\7|buzzfeed\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\8|porntube\.com[^\w.%-](?=([\s\S]*?\/track))\9|cloudfront\.net(?=([\s\S]*?\/tracker\.js))\10|gowatchit\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\11|goadv\.com[^\w.%-](?=([\s\S]*?\/track\.js))\12|partypoker\.com[^\w.%-](?=([\s\S]*?\/tracking\-))\13|9msn\.com\.au[^\w.%-](?=([\s\S]*?\/tracking\/))\14|livefyre\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\15|reevoo\.com[^\w.%-](?=([\s\S]*?\/track\/))\16|chip\.de[^\w.%-](?=([\s\S]*?_tracking\/))\17|staticwhich\.co\.uk\/assets\/(?=([\s\S]*?\/track\.js))\18|marketingpilgrim\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/trackur\.com\-))\19|dealer\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\20|dealer\.com[^\w.%-](?=([\s\S]*?\/tracker\/))\21|azurewebsites\.net[^\w.%-](?=([\s\S]*?\/mnr\-mediametrie\-tracking\-))\22|zdf\.de[^\w.%-](?=([\s\S]*?\/tracking))\23|neulion\.vo\.llnwd\.net[^\w.%-](?=([\s\S]*?\/track\.js))\24|ninemsn\.com\.au[^\w.%-](?=([\s\S]*?\.tracking\.udc\.))\25|ringostrack\.com[^\w.%-](?=([\s\S]*?\/amazon\-buy\.gif))\26|msn\.com[^\w.%-](?=([\s\S]*?\/track\.js))\27|hulu\.com\/watch\/(?=([\s\S]*?track\.url\-1\.com))\28|euroleague\.tv[^\w.%-](?=([\s\S]*?\/tracking\.js))\29|gazzettaobjects\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\30|volkswagen\-italia\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\31|fyre\.co[^\w.%-](?=([\s\S]*?\/tracking\/))\32|tracking\.(?=([\s\S]*?\/beacon\/))\33|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/tracking_RaptorheaderJS\.js))\34|lemde\.fr[^\w.%-](?=([\s\S]*?\/tracking\/))\35|barcelo\.com[^\w.%-](?=([\s\S]*?\/Tracking\.js))\36|youandyourwedding\.co\.uk[^\w.%-](?=([\s\S]*?\/socialtracking\/))\37|typepad\.com[^\w.%-](?=([\s\S]*?\/stats))\38|oload\.tv[^\w.%-](?=([\s\S]*?\/_))\39|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/Analytics\-))\40|adf\.ly\/(?=([\s\S]*?\.php))\41|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adawe\-))\42|openload\.co[^\w.%-](?=([\s\S]*?\/_))\43|doubleclick\.net[^\w.%-](?=([\s\S]*?\/ad\/))\44|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adj\/))\45|google\.com[^\w.%-](?=([\s\S]*?\/fastbutton))\46|facebook\.com(?=([\s\S]*?\/plugins\/like\.php))\47|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/like\.php))\48|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/page\.php))\49|amazonaws\.com[^\w.%-](?=([\s\S]*?\/ads\/))\50|platform\.twitter\.com(?=([\s\S]*?\/widgets\/))\51|hulkshare\.com[^\w.%-](?=([\s\S]*?\/adsmanager\.js))\52|platform\.twitter\.com(?=([\s\S]*?\/widget\/))\53|images\-amazon\.com\/images\/(?=([\s\S]*?\/banner\/))\54|thevideo\.me\/(?=([\s\S]*?\.php))\55|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adaptvjw5\-))\56|yimg\.com[^\w.%-](?=([\s\S]*?\/sponsored\.js))\57|taboola\.com[^\w.%-](?=([\s\S]*?\/log\/))\58|videogamesblogger\.com[^\w.%-](?=([\s\S]*?\/scripts\/takeover\.js))\59|allmyvideos\.net\/(?=([\s\S]*?%))\60|allmyvideos\.net\/(?=([\s\S]*?))\61|liutilities\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\62|urlcash\.net\/random(?=([\s\S]*?\.php))\63|rackcdn\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\64|amazonaws\.com[^\w.%-](?=([\s\S]*?\/pageviews))\65|quantserve\.com[^\w.%-](?=([\s\S]*?\.swf))\66|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-ad\.))\67|googleapis\.com[^\w.%-](?=([\s\S]*?\/gen_204))\68|thevideo\.me\/(?=([\s\S]*?_))\69|213\.174\.140\.76[^\w.%-](?=([\s\S]*?\/js\/msn\.js))\70|meetlocals\.com[^\w.%-](?=([\s\S]*?popunder))\71|i3investor\.com[^\w.%-](?=([\s\S]*?\/partner\/))\72|blogsmithmedia\.com[^\w.%-](?=([\s\S]*?facebook))\73|paypal\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\74|imagetwist\.com\/(?=([\s\S]*?))\75|ifilm\.com\/website\/(?=([\s\S]*?_skin_))\76|redtubefiles\.com[^\w.%-](?=([\s\S]*?\/banner\/))\77|thechive\.files\.wordpress\.com[^\w.%-](?=([\s\S]*?\-wallpaper\-))\78|tumblr\.com[^\w.%-](?=([\s\S]*?\/sponsored_))\79|tumblr\.com[^\w.%-](?=([\s\S]*?_sponsored_))\80|widgetserver\.com[^\w.%-](?=([\s\S]*?\/image\.gif))\81|facebook\.com(?=([\s\S]*?\/impression\.php))\82|eweek\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\83|media\-imdb\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\84|facebook\.com\/ajax\/(?=([\s\S]*?\/log\.php))\85|yimg\.com[^\w.%-](?=([\s\S]*?\/ywa\.js))\86|static\.(?=([\s\S]*?\.criteo\.net\/images[^\w.%-]))\87|naij\.com[^\w.%-](?=([\s\S]*?\/branding\/))\88|redtube\.com[^\w.%-](?=([\s\S]*?\/banner\/))\89|cloudzer\.net[^\w.%-](?=([\s\S]*?\/banner\/))\90|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/follow))\91|google\.com[^\w.%-](?=([\s\S]*?\/log))\92|getglue\.com[^\w.%-](?=([\s\S]*?\/count))\93|wp\.com[^\w.%-](?=([\s\S]*?\/linkwidgets\/slingshot_))\94|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/ltas\-))\95|ibtimes\.com[^\w.%-](?=([\s\S]*?\/sponsor_))\96|wordpress\.com[^\w.%-](?=([\s\S]*?\/twitter1\.png))\97|static\.(?=([\s\S]*?\.criteo\.net\/js\/duplo[^\w.%-]))\98|gravity\.com[^\w.%-](?=([\s\S]*?\/beacons\/))\99|imagefruit\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\100|yimg\.com[^\w.%-](?=([\s\S]*?\/flash\/promotions\/))\101|lfcimages\.com[^\w.%-](?=([\s\S]*?\/partner\-))\102|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/googlevideoadslibraryas3\.swf))\103|armorgames\.com[^\w.%-](?=([\s\S]*?\/banners\/))\104|gfi\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-BlogBanner))\105|avg\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\106|virginmedia\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\107|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-advert\-))\108|rapidlibrary\.com\/banner_(?=([\s\S]*?\.png))\109|widgetserver\.com[^\w.%-](?=([\s\S]*?\/quantcast\.swf))\110|wordpress\.com[^\w.%-](?=([\s\S]*?\/facebook\.png))\111|images\-amazon\.com\/images\/(?=([\s\S]*?\/ga\.js))\112|turner\.com[^\w.%-](?=([\s\S]*?\/ads\/))\113|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/FME\-Red\-CAP\.jpg))\114|adamvstheman\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/AVTM_banner\.jpg))\115|apis\.google\.com\/_\/apps\-static\/_\/js\/gapi\/(?=([\s\S]*?plusone\/))\116|newstatesman\.com\/sites\/all\/themes\/(?=([\s\S]*?_1280x2000\.))\117|financialsamurai\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sliced\-alternative\-10000\.jpg))\118|24hourwristbands\.com\/(?=([\s\S]*?\.googleadservices\.com\/))\119|pimpandhost\.com\/static\/i\/(?=([\s\S]*?\-pah\.jpg))\120|linkbird\.com\/static\/upload\/(?=([\s\S]*?\/banner\/))\121|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\.MUSIC\/))\122|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-Banner))\123|nichepursuits\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/long\-tail\-pro\-banner\.gif))\124|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\.gif))\125|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/DeadwoodStove\-PW\.gif))\126|copblock\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/covert\-handcuff\-key\-AD\-))\127|freebunker\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\128|yimg\.com\/cv\/(?=([\s\S]*?\/billboard\/))\129|flixster\.com[^\w.%-](?=([\s\S]*?\/analytics\.))\130|static\.pe\.studivz\.net[^\w.%-](?=([\s\S]*?\/library\.js))\131|walshfreedom\.com[^\w.%-](?=([\s\S]*?\/liberty\-luxury\.png))\132|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ibs\.orl\.news\/))\133|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/jihad\.jpg))\134|groupon\.com[^\w.%-](?=([\s\S]*?\/affiliate_widget\/))\135|opencurrency\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-aocs\-sidebar\-commodity\-bank\.png))\136|searchenginejournal\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\137|nufc\.com[^\w.%-](?=([\s\S]*?\/The%20Gate_NUFC\.com%20banner_%2016\.8\.13\.gif))\138|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PW\-Ad\.jpg))\139|pornsharing\.com\/App_Themes\/pornsharianew\/js\/adppornsharia(?=([\s\S]*?\.js))\140|pornsharing\.com\/App_Themes\/pornsharingnew\/js\/adppornsharia(?=([\s\S]*?\.js))\141|postaffiliatepro\.com[^\w.%-](?=([\s\S]*?\/banners\/))\142|player\.screenwavemedia\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\143|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\/banner))\144|allhiphop\.com\/site_resources\/ui\-images\/(?=([\s\S]*?\-conduit\-banner\.gif))\145|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Johnson\-Grow\-Lights\.gif))\146|bitcoinreviewer\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\-luckybit\.jpg))\147|static\.ow\.ly[^\w.%-](?=([\s\S]*?\/click\.gz\.js))\148|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/embed\.ytpwatch\.))\149|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.car\/))\150|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.dal\/))\151|tunein\.com\/account\/newiframe\/signup\/(?=([\s\S]*?conversionPopup))\152|gethigh\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/pass_a_drug_test_get_high_banner\.jpg))\153|drivereasy\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sidebar\-DriverEasy\-buy\.jpg))\154|video\.abc\.com[^\w.%-](?=([\s\S]*?\/promos\/))\155|imgflare\.com[^\w.%-](?=([\s\S]*?\/splash\.php))\156|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/app\.ytpwatch\.))\157|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/apmgoldmembership250x250\.jpg))\158|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/tsepulveda\-1\.jpg))\159|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MTV\-Viacom\/))\160|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNI\.COM\/))\161|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/click_to_buy\/))\162|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Judge\-Lenny\-001\.jpg))\163|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ccr\.newyork\.))\164|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\-CNBC\/))\165|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/American\-Resident\-Project\-Logo\-))\166|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x150\.png))\167|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/users\-online\-counter\/online\.js))\168|cbs\.com\/assets\/js\/(?=([\s\S]*?AdvCookie\.js))\169|mrc\.org[^\w.%-](?=([\s\S]*?\/Collusion_Banner300x250\.jpg))\170|ebaystatic\.com\/aw\/signin\/(?=([\s\S]*?_wallpaper_))\171|idg\.com\.au\/images\/(?=([\s\S]*?_promo))\172|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/theGunMagbanner\.png))\173|s\-assets\.tp\-cdn\.com\/widgets\/(?=([\s\S]*?\/vwid\/))\174(?=([\s\S]*?\.html))\175|zoover\.(?=([\s\S]*?\/shared\/bannerpages\/darttagsbanner\.aspx))\176|ebaystatic\.com\/aw\/pics\/signin\/(?=([\s\S]*?_signInSkin_))\177|static(?=([\s\S]*?\.linkedin\.com\/scds\/common\/))\178|facebook\.com[^\w.%-](?=([\s\S]*?\/plugins\/subscribe))\179|rghost\.ru\/download\/a\/(?=([\s\S]*?\/banner_download_))\180|preppersmallbiz\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PSB\-Support\.jpg))\181|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.sd\/))\182|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/domainpark\.cgi))\183|ragezone\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/HV\-banner\-300\-200\.jpg))\184|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.jpg))\185|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x250\.jpg))\186|afcdn\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\187|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/com\.ytpwatch\.))\188|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/women_guns192x50\.png))\189|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner\.))\190|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner_))\191|uflash\.tv[^\w.%-](?=([\s\S]*?\/affiliates\/))\192|activewin\.com[^\w.%-](?=([\s\S]*?\/blaze_static2\.gif))\193|images\-amazon\.com\/images\/(?=([\s\S]*?\/browser\-scripts\/da\-))\194|telegraphindia\.com[^\w.%-](?=([\s\S]*?\/banners\/))\195|australiantimes\.co\.uk\/wp\-content\/uploads\/(?=([\s\S]*?_google_pl\.jpg))\196|upload\.ee\/image\/(?=([\s\S]*?\/B_descarga_tipo12\.gif))\197|content\.ad\/Scripts\/widget(?=([\s\S]*?\.aspx))\198|upcat\.custvox\.org\/survey\/(?=([\s\S]*?\/countOpen\.gif))\199|tipico\.(?=([\s\S]*?\/affiliate\/))\200|grouponcdn\.com[^\w.%-](?=([\s\S]*?\/affiliate_widget\/))\201|techinsider\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-300x500\.))\202|l\.yimg\.com[^\w.%-](?=([\s\S]*?\/img\/badge\-))\203|kitguru\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-Skin\.))\204|cooksunited\.co\.uk\/counter(?=([\s\S]*?\.php))\205|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/gorillabanner728\.gif))\206|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\-social\.png))\207|i\.lsimg\.net[^\w.%-](?=([\s\S]*?\/sides_clickable\.))\208|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc1\.png))\209|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc2\.png))\210|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cloudbet_))\211|maciverse\.mangoco\.netdna\-cdn\.com[^\w.%-](?=([\s\S]*?banner))\212|bestvpn\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/mosttrustedname_260x300_))\213|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/THCB\-Validic\-jpg\-opt\.jpg))\214|nbcudigitaladops\.com\/hosted\/js\/(?=([\s\S]*?_com\.js))\215|heraldm\.com[^\w.%-](?=([\s\S]*?\/banner\/))\216|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/allserviceslogo\.gif))\217|xhcdn\.com[^\w.%-](?=([\s\S]*?\/ads_))\218|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/simgad\/))\219|celebstoner\.com\/assets\/images\/img\/sidebar\/(?=([\s\S]*?\/freedomleaf\.png))\220|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sensi2\.jpg))\221|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cannafo\.jpg))\222|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/WeedSeedShop\.jpg))\223|arntrnassets\.mediaspanonline\.com[^\w.%-](?=([\s\S]*?_HP_wings_))\224|twitter\.com\/(?=([\s\S]*?statuses\/user_timeline\/))\225|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dakine420\.png))\226|edgecastcdn\.net[^\w.%-](?=([\s\S]*?\.barstoolsports\.com\/wp\-content\/banners\/))\227|csdn\.net[^\w.%-](?=([\s\S]*?\/counter\.js))\228|cdmagurus\.com\/img\/(?=([\s\S]*?\.gif))\229|cannabisjobs\.us\/wp\-content\/uploads\/(?=([\s\S]*?\/OCWeedReview\.jpg))\230|foxandhoundsdaily\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-AD\.gif))\231|nzpages\.co\.nz[^\w.%-](?=([\s\S]*?\/banners\/))\232|profitconfidential\.com\/wp\-content\/themes\/PC\-child\-new\/images\/(?=([\s\S]*?_banners_))\233|llnwd\.net\/o28\/assets\/(?=([\s\S]*?\-sponsored\-))\234|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dynamic_banner_))\235|freedom\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\236|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_175x175\.jpg))\237|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_185x185\.jpg))\238|sourcefed\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/netflix4\.jpg))\239|originalweedrecipes\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-Medium\.jpg))\240|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/free_ross\.jpg))\241|phoronix\.com\/(?=([\s\S]*?\/twitter\.png))\242|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/scrogger\.gif))\243|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ABC\.com\/))\244|dnsstuff\.com\/dnsmedia\/images\/(?=([\s\S]*?_banner\.jpg))\245|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-180x350\.))\246|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180x350\.))\247|hwscdn\.com[^\w.%-](?=([\s\S]*?\/brands_analytics\.js))\248|sify\.com[^\w.%-](?=([\s\S]*?\/gads_))\249|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\/))\250|gmstatic\.net[^\w.%-](?=([\s\S]*?\/amazonbadge\.png))\251|irctctourism\.com\/ttrs\/railtourism\/Designs\/html\/images\/tourism_right_banners\/(?=([\s\S]*?DealsBanner_))\252|raysindex\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dolmansept2012flash\.swf))\253|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/videoReport\.php))\254|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/attemptAdReport\.php))\255|sfstatic\.com[^\w.%-](?=([\s\S]*?\/js\/fl\.js))\256|fncstatic\.com[^\w.%-](?=([\s\S]*?\/sponsored\-by\.gif))\257|justsomething\.co\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.))\258|lawprofessorblogs\.com\/responsive\-template\/(?=([\s\S]*?advert\.))\259|lfgcomic\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PageSkin_))\260|heyjackass\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x225_))\261|nextbigwhat\.com\/wp\-content\/uploads\/(?=([\s\S]*?ccavenue))\262|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/727x90))\263|aim\-ads\.com\/multimedia\-themonitor\-com\/wwwroot\/(?=([\s\S]*?_twitter_))\264|lego\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\265|srwww1\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\266|allmovie\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\267|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\268|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\269|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?_banner_))\270|tigerdirect\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\271|youku\.com[^\w.%-](?=([\s\S]*?\/click\.php))\272|survivaltop50\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Survival215x150Link\.png))\273|xrad\.io[^\w.%-](?=([\s\S]*?\/hotspots\/))\274|doubleclick\.net\/(?=([\s\S]*?\/pfadx\/lin\.))\275|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ESPN\/))\276|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.muzu\/))\277|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.BLIPTV\/))\278|doubleclick\.net\/pfadx\/(?=([\s\S]*?\/kidstv\/))\279|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/muzumain\/))\280|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MCNONLINE\/))\281|doubleclick\.net\/pfadx\/(?=([\s\S]*?CBSINTERACTIVE\/))\282|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.VIACOMINTERNATIONAL\/))\283|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.WALTDISNEYINTERNETGROU\/))\284|amazonaws\.com[^\w.%-](?=([\s\S]*?\/player_request_))\285(?=([\s\S]*?\/get_affiliate_))\286|digitaltveurope\.net\/wp\-content\/uploads\/(?=([\s\S]*?_wallpaper_))\287|capitolfax\.com\/wp\-content\/(?=([\s\S]*?ad\.))\288|pornsharia\.com[^\w.%-](?=([\s\S]*?\/adppornsharia\.js))\289|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/250x125\-))\290|hulkshare\.oncdn\.com[^\w.%-](?=([\s\S]*?\/removeads\.))\291|dailyblogtips\.com\/wp\-content\/uploads\/(?=([\s\S]*?\.gif))\292|joindota\.com\/wp\-content\/(?=([\s\S]*?\.png))\293|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180_350\.))\294|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/billpayhelp2\.png))\295|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cb_))\296|thejointblog\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-235x))\297|morefree\.net\/wp\-content\/uploads\/(?=([\s\S]*?\/mauritanie\.gif))\298|fncstatic\.com[^\w.%-](?=([\s\S]*?\/business\-exchange\.html))\299|citywirecontent\.co\.uk[^\w.%-](?=([\s\S]*?\/cw\.oas\.dx\.js))\300|mypbrand\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\301|watchuseek\.com\/media\/(?=([\s\S]*?_250x250))\302|cardsharing\.info\/wp\-content\/uploads\/(?=([\s\S]*?\/ALLS\.jpg))\303|thessdreview\.com[^\w.%-](?=([\s\S]*?\/owc\-full\-banner\.jpg))\304|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\305|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\306|dada\.net[^\w.%-](?=([\s\S]*?\/nedstat_sitestat\.js))\307|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/helix\.gif))\308|capitolfax\.com\/wp\-content\/(?=([\s\S]*?Ad_))\309|htcsource\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icons\.png))\310|zombiegamer\.co\.za\/wp\-content\/uploads\/(?=([\s\S]*?\-skin\-))\311|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/ccn\.png))\312|madamenoire\.com\/wp\-content\/(?=([\s\S]*?_Reskin\-))\313|mrskincdn\.com[^\w.%-](?=([\s\S]*?\/flash\/aff\/))\314|sillusions\.ws[^\w.%-](?=([\s\S]*?\/vpn\-banner\.gif))\315|tv3\.ie[^\w.%-](?=([\s\S]*?\/sponsor\.))\316|complexmedianetwork\.com[^\w.%-](?=([\s\S]*?\/toolbarlogo\.png))\317|pw\.org\/sites\/all\/(?=([\s\S]*?\/ga\.js))\318|eteknix\.com\/wp\-content\/uploads\/(?=([\s\S]*?Takeover))\319|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/visitor\-counter\/counter\.js))\320|punch\.cdn\.ng[^\w.%-](?=([\s\S]*?\/wp\-banners\/))\321|wired\.com\/images\/xrail\/(?=([\s\S]*?\/samsung_layar_))\322|hollyscoop\.com\/sites\/(?=([\s\S]*?\/skins\/))\323|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/7281\.gif))\324|apis\.google\.com\/(?=([\s\S]*?\/socialgraph\/))\325|homedesignlover\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/pin\.jpg))\326|kurtgeiger\.com[^\w.%-](?=([\s\S]*?\/linkshare\/))\327|beacons\.vessel\-static\.com[^\w.%-](?=([\s\S]*?\/pageView))\328|thehindu\.com\/multimedia\/(?=([\s\S]*?\/sivananda_sponsorch_))\329|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\/))\330|mofomedia\.nl\/pop\-(?=([\s\S]*?\.js))\331|upickem\.net[^\w.%-](?=([\s\S]*?\/affiliates\/))\332|thessdreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/930x64_))\333|uniblue\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\334|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/cmn_complextv\/))\335|themittani\.com\/sites\/(?=([\s\S]*?\-skin))\336|spiegel\.de[^\w.%-](?=([\s\S]*?\/statistic\/))\337|static\.plista\.com[^\w.%-](?=([\s\S]*?\/resized\/))\338|samoatimes\.co\.nz[^\w.%-](?=([\s\S]*?\/banner468x60\/))\339|mmoculture\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-background\-))\340|iimg\.in[^\w.%-](?=([\s\S]*?\/sponsor_))\341|pastime\.biz[^\w.%-](?=([\s\S]*?\/personalad))\342(?=([\s\S]*?\.jpg))\343|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-vertical\.))\344|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x400_))\345|newsonjapan\.com[^\w.%-](?=([\s\S]*?\/banner\/))\346|pbs\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\347|bitcoinist\.net\/wp\-content\/uploads\/(?=([\s\S]*?_250x250_))\348|nu2\.nu[^\w.%-](?=([\s\S]*?\/sponsor\/))\349|staticworld\.net\/images\/(?=([\s\S]*?_skin_))\350|seeclickfix\.com[^\w.%-](?=([\s\S]*?\/text_widgets_analytics\.html))\351|between\-legs\.com[^\w.%-](?=([\s\S]*?\/banners\/))\352|kvcr\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\353|star883\.org[^\w.%-](?=([\s\S]*?\/sponsors\.))\354|ganool\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/matrix303\.gif))\355|freecycle\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\356|ganool\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Javtoys300250\.\.gif))\357|nature\.com[^\w.%-](?=([\s\S]*?\/marker\-file\.nocache))\358|aolcdn\.com\/os\/music\/img\/(?=([\s\S]*?\-skin\.jpg))\359|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\.jpg))\360|tremormedia\.com[^\w.%-](?=([\s\S]*?\/tpacudeoplugin46\.swf))\361|seedr\.ru[^\w.%-](?=([\s\S]*?\/stats\/))\362|rapidfiledownload\.com[^\w.%-](?=([\s\S]*?\/btn\-input\-download\.png))\363|ypcdn\.com\/(?=([\s\S]*?\/webyp))\364|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/728_))\365|orlandosentinel2\.com[^\w.%-](?=([\s\S]*?\-sponsorship\-))\366|ap\.org[^\w.%-](?=([\s\S]*?\/webtrendsap_hosted\.js))\367|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adi\/))\368|allposters\.com[^\w.%-](?=([\s\S]*?\/banners\/))\369|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.sevenload\.com_))\370|nu2\.nu[^\w.%-](?=([\s\S]*?_banner\.))\371|kron\.com\/uploads\/(?=([\s\S]*?\-ad\-))\372|data\.ninemsn\.com\.au\/(?=([\s\S]*?GetAdCalls))\373|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ssp\.wews\/))\374|bitcoinist\.net\/wp\-content\/(?=([\s\S]*?\/630x80\-bitcoinist\.gif))\375|dreamscene\.org[^\w.%-](?=([\s\S]*?_Banner\.))\376|eteknix\.com\/wp\-content\/uploads\/(?=([\s\S]*?skin))\377|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/motorswidgetsv2\.swf))\378|xxxgames\.biz[^\w.%-](?=([\s\S]*?\/sponsors\/))\379|yimg\.com\/cv\/(?=([\s\S]*?\/config\-object\-html5billboardfloatexp\.js))\380|netbiscuits\.net[^\w.%-](?=([\s\S]*?\/analytics\/))\381|947\.co\.za[^\w.%-](?=([\s\S]*?\-branding\.))\382|nbr\.co\.nz[^\w.%-](?=([\s\S]*?\-WingBanner_))\383|atlantafalcons\.com\/wp\-content\/(?=([\s\S]*?\/metrics\.js))\384|malaysiabay\.org[^\w.%-](?=([\s\S]*?creatives\.php))\385|jdownloader\.org[^\w.%-](?=([\s\S]*?\/smbanner\.png))\386|guns\.ru[^\w.%-](?=([\s\S]*?\/banners\/))\387|interseek\.si[^\w.%-](?=([\s\S]*?\/visit\.js))\388|bassmaster\.com[^\w.%-](?=([\s\S]*?\/premier_sponsor_logo\/))\389|wipfilms\.net[^\w.%-](?=([\s\S]*?\/amazon\.png))\390|coinbase\.com\/assets\/application\-(?=([\s\S]*?\.js))\391|mantra\.com\.au[^\w.%-](?=([\s\S]*?\/campaigns\/))\392|tmz\.vo\.llnwd\.net[^\w.%-](?=([\s\S]*?\/images\/))\393(?=([\s\S]*?skin))\394|javascript\-coder\.com[^\w.%-](?=([\s\S]*?\/form\-submit\-larger\.jpg))\395|galatta\.com[^\w.%-](?=([\s\S]*?\/banners\/))\396|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?\/side_strip\.))\397|nymag\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\398|armorgames\.com[^\w.%-](?=([\s\S]*?\/siteskin\.css))\399|yandex\.(?=([\s\S]*?\/hitcount\/))\400|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?\/singapore_auto\.))\401|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/pulsar\.js))\402|geocities\.yahoo\.(?=([\s\S]*?\/js\/sq\.))\403|1043thefan\.com[^\w.%-](?=([\s\S]*?_Sponsors\/))\404|race\-dezert\.com[^\w.%-](?=([\s\S]*?\/sponsor\-))\405|serials\.ws[^\w.%-](?=([\s\S]*?\/logo\.gif))\406|afloat\.ie[^\w.%-](?=([\s\S]*?\/banners\/))\407|skypeassets\.com[^\w.%-](?=([\s\S]*?\/inclient\/))\408|apis\.google\.com[^\w.%-](?=([\s\S]*?\/widget\/render\/person))\409|mmorpg\.com\/images\/(?=([\s\S]*?_hots_r0\.jpg))\410|waterford\-today\.ie[^\w.%-](?=([\s\S]*?\/banners\/))\411|manutd\.com[^\w.%-](?=([\s\S]*?\/Sponsors\/))\412|bizrate\.com[^\w.%-](?=([\s\S]*?\/survey_))\413|vertical\-n\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\414|verticalnetwork\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\415|saboom\.com\.pccdn\.com[^\w.%-](?=([\s\S]*?\/banner\/))\416|wrmf\.com\/upload\/(?=([\s\S]*?_Webskin_))\417|channel4\.com\/bips\/(?=([\s\S]*?\/brand\/))\418|wrko\.com\/sites\/wrko\.com\/files\/poll\/(?=([\s\S]*?_285x95\.jpg))\419|static\.(?=([\s\S]*?\.criteo\.net\/design[^\w.%-]))\420|zahodi\-ka\.ru[^\w.%-](?=([\s\S]*?\/schet\.cgi))\421|vondroid\.com\/site\-img\/(?=([\s\S]*?\-adv\-ex\-))\422|amazon\.com[^\w.%-](?=([\s\S]*?\/getaanad))\423|bitcoinist\.net\/wp\-content\/(?=([\s\S]*?\/inst\.png))\424|wipfilms\.net[^\w.%-](?=([\s\S]*?\/instant\-video\.png))\425|livestation\.com[^\w.%-](?=([\s\S]*?\/akamaimediaanalytics\.swf))\426|kongregate\.com\/images\/help_devs_(?=([\s\S]*?\.png))\427|poststar\.com[^\w.%-](?=([\s\S]*?\/ad_))\428|cloudfront\.net(?=([\s\S]*?\/sp\.js))\429|foxsoccer2go\.com\/namedImage\/(?=([\s\S]*?\/backgroundSkin\.jpg))\430|gmstatic\.net[^\w.%-](?=([\s\S]*?\/itunesbadge\.png))\431|4fuckr\.com\/static\/(?=([\s\S]*?\-banner\.))\432|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/ClientSideMetricsAUIJavascript))\433(?=([\s\S]*?\.js))\434|rethinkbar\.azurewebsites\.net[^\w.%-](?=([\s\S]*?\/ieflyout\.js))\435|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/adnumana350x250\-1\.jpg))\436|signup\.advance\.net[^\w.%-](?=([\s\S]*?affiliate))\437|blogspot\.com[^\w.%-](?=([\s\S]*?\/twitter\.png))\438|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/herbies\-1\.gif))\439|twitter\.com[^\w.%-](?=([\s\S]*?\/log\.json))\440|deccanchronicle\.com[^\w.%-](?=([\s\S]*?\-searchquad\-300100\.swf))\441|google\.(?=([\s\S]*?\/api\/sclk))\442|kexp\.org[^\w.%-](?=([\s\S]*?\/sponsoredby\.))\443|guns\.ru[^\w.%-](?=([\s\S]*?\/banner\/))\444|google\.(?=([\s\S]*?\/logxhraction))\445)/i;
var bad_da_hostpath_regex_flag = 1101 > 0 ? true : false;  // test for non-zero number of rules
    
// 73 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:ads\.|adv\.|porntube\.com\/ads$|erotikdeal\.com\/\?ref=|quantserve\.com\/pixel;|bufferapp\.com\/wf\/open\?upn=|banner\.|banners\.|synad\.|affiliate\.|affiliates\.|api\-read\.facebook\.com\/restserver\.php\?api_key=|cloudfront\.net\/\?a=|graph\.facebook\.com\/fql\?q=SELECT|static\.plista\.com\/jsmodule\/flash$|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|oddschecker\.com\/clickout\.htm\?type=takeover\-|movies\.askjolene\.com\/c64\?clickid=|35\.184\.137\.181[^\w.%-]popup,third\-party|sweed\.to\/\?pid=|gawker\.com\/\?op=hyperion_useragent_data|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|inn\.co\.il\/Controls\/HPJS\.ashx\?act=log|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|babylon\.com\/welcome\/index\.html\?affID=|mail\.yahoo\.com\/neo\/mbimg\?av\/curveball\/ds\/|sheknows\.com\/api\/module\?id=follow_social|streamtheworld\.com\/ondemand\/ars\?type=preroll|ooyala\.com\/authorized\?analytics|totalporn\.com\/videos\/tracking\/\?url=|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\1|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\2|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\3|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\4|allmyvideos\.net\/(?=([\s\S]*?=))\5|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\6|thevideo\.me\/(?=([\s\S]*?\:))\7|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\8|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\9|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\10|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\11|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\12|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\13|widgets\.itunes\.apple\.com[^\w.%-](?=([\s\S]*?&affiliate_id=))\14|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\15|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\16(?=([\s\S]*?&s=))\17(?=([\s\S]*?&h=))\18|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\19|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\20(?=([\s\S]*?=))\21|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\22|lijit\.com\/blog_wijits\?(?=([\s\S]*?=trakr&))\23|facebook\.com\/restserver\.php\?(?=([\s\S]*?\.getStats&))\24|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\25|tipico\.(?=([\s\S]*?\?affiliateId=))\26|doubleclick\.net\/pfadx\/(?=([\s\S]*?adcat=))\27|twitter\.com\/i\/cards\/tfw\/(?=([\s\S]*?\?advertiser_name=))\28|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\29|torrentz\.eu\/search(?=([\s\S]*?=))\30|static\.hd\-trailers\.net\/js\/javascript_(?=([\s\S]*?\.js$))\31|assoc\-amazon\.(?=([\s\S]*?[^\w.%-]e\/ir\?t=))\32|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\33|facebook\.com\/connect\/connect\.php\?(?=([\s\S]*?width))\34(?=([\s\S]*?&height))\35|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\36|plarium\.com\/play\/(?=([\s\S]*?adCampaign=))\37|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\38|yahoo\.(?=([\s\S]*?\/serv\?s=))\39|r\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/rtd\?ptid))\40|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\41|yimg\.com[^\w.%-](?=([\s\S]*?\/l\?ig=))\42|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\43|farm\.plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\44|oas\.(?=([\s\S]*?@))\45|downloadprovider\.me\/en\/search\/(?=([\s\S]*?\?aff\.id=))\46(?=([\s\S]*?&iframe=))\47)/i;
var bad_da_regex_flag = 73 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 1999 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adserver\.|\/homepage\-ads\/|\/homepage\/ads\/|\.com\/ads\?|\/ad_pop\.php\?|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\/ad\-engine\.|\/ad_engine\?|\-leaderboard\-ad\-|\/leaderboard_ad\/|\-web\-ad\-|\/web\-ad_|\/imgad\.|\/imgad\?|\/iframead\.|\/iframead\/|\/adplugin\.|\/adplugin_|\/contentad\/|\/contentad$|\/adcontent\/|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/webad\.|\/webad\?|_webad\.|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img\/ad_|\/img_ad\/|\.com\/video\-ad\-|\?getad=&|_js\/ads\.js|\-ad\-iframe\.|\-ad\-iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\-online\-advert\.|\.com\/\?adv=|\/online\-ad_|_online_ad\.|\.adriver\.|\/adriver\.|\/adriver_|\/bottom\-ads\.|\/ad\.php$|\/post\/ads\/|\/media\/ad\/|\/expandable_ad\.php|\/bg\/ads\/|\/footer\-ads\/|=adcenter&|\/adskin\/|\/adv\-socialbar\-|\-top\-ads\.|\/top\-ads\.|\.com\/js\/ads\/|\-show\-ads\.|\/show\-ads\.|_search\/ads\.js|\-text\-ads\.|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\/ad\/logo\/|\/special\-ads\/|\/ad132m\/|\/dynamic\/ads\/|\/afs\/ads\/|\/ad\?count=|\/ad_count\.|\/banner\/adv\/|\/banner\/adv_|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/remove\-ads\.|\/lazy\-ads\-|\/ads\.cms|\.co\/ads\/|\/mini\-ads\/|\/user\/ads\?|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/external\/ads\/|\/player\/ads\.|\/player\/ads\/|\/adclick\.|\.no\/ads\/|\/modules\/ads\/|\/ext\/ads\/|\/i\/ads\/|\/showads\/|\/ad\?sponsor=|\/ads\/html\/|\/td\-ads\-|\/adsys\.|\/adsys\/|\/ads12\.|\/adsjs\.|\/custom\/ads|\/default\/ads\/|\/adsetup\.|\/adsetup_|\/adsframe\.|\/adbanners\/|\/blogad\.|\/facebookicon\.|\/inc\/ads\/|\/responsive\-ads\.|\/twittericon\.|\/sidebar\-ads\/|\/left\-ads\.|\/ads\/targeting\.|\/ads\/async\/|\/delivery\.ads\.|\/adsdaq_|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\/house\-ads\/|\.online\/ads\/|\/online\/ads\/|\-peel\-ads\-|&program=revshare&|\/adlog\.|\/ads_reporting\/|\.net\/ad\/|\/image\/ads\/|\/image\/ads_|\/adsrv\.|\/adsrv\/|\.link\/ads\/|\/popupads\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|\/ads\.htm|\/plugins\/ads\-|\/plugins\/ads\/|\/sponsored_ad\.|\/sponsored_ad\/|\/log\/ad\-|\/log_ad\?|\.ads\.css|\/ads\.css|\/ads8\.|\/ads8\/|\/adstop\.|\/adstop_|\/ads\.php|\/ads_php\/|\/new\-ads\/|\/new\/ads\/|\/ads\/square\-|\/ads\/square\.|&adcount=|\/adcount\.|\.adpartner\.|\/adpartner\.|\?adpartner=|\-adsonar\.|\/adsonar\.|\/eu_cookies\.|\/video\-ad\-overlay\.|\/realmedia\/ads\/|=popunders&|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|\/bannerad\.|\/bannerad\/|_bannerad\.|\.ads9\.|\/ads9\.|\/ads9\/|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/adClick\/|\/adClick\?|\/ads\/text\/|\/ads_text_|\.cookie_law\.|\/cookie_law\/|\-adsystem\-|\/adsystem\.|\/adsystem\/|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\.ads3\-|\/ads3\.|\/ads3\/|\/blog\/ads\/|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\/static\/tracking\/|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\-img\/ads\/|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\/assets\/js\/ad\.|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\/google\/adv\.|\/adstat\.|\/img\/tumblr\-|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|&adserver=|\-adserver\-|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/head\-social\.|\/superads_|\/adwords\/|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\/web\-analytics\.|\/web_analytics\/|\/static\/ads\/|_static\/ads\/|\/addthis_widget\.|\/media\/ads\/|_media\/ads\/|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|&advertiserid=|\/adworks\/|\/admanager\.|\/admanager\/|\/userad\/|\/admax\/|\/wp\-images\/facebook\.png|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|\/adseo\/|\/images\/facebook|\-sharebar\-|\/js\/tracking\.js|\/ads4\/|\/adlink\?|\/adlink_|=advertiser\.|=advertiser\/|\?advertiser=|\/images\/adver\-|\/adman\/|\.cookienotice\.|\/cookienotice\.|\-images\/ad\-|\/images\-ad\/|\/images\/ad\-|\/images\/ad\/|\/images_ad\/|_images\/ad\.|_images\/ad_|\/js\/tracking\/|\/js\/tracking_|\.com\/js\/ad\.|\/ad\.css\?|\/videoad\.|_videoad\.|\/product\-ad\/|\/adimg\/|_smartads_|\/socialads\/|\/flashads\/|\/eu\-cookie\-|\/eu\-cookie\.|\/eu\-cookie\/|_eu_cookie_|=adlabs&|\/xtclicks\.|\/xtclicks_|\/images\/gplus\-|\/adfactory\-|\/adfactory_|\-adops\.|\/adops\/|\.net\/adx\.php\?|\-google\-ads\-|\-google\-ads\/|\/google\-ads\.|\/google\-ads\/|\-adtrack\.|\/adtrack\/|\-twitter2\.|\/social\-media\-banner\.|\/googlead\-|\/googlead\.|_googlead\.|\/img\/gplus_|\/\?advideo\/|\?advideo_|\/chartbeat\.js|_chartbeat\.js|\-adspot\-|\/adspot\/|\/adspot_|\/adcash\-|\/embed\-log\.js|\-social\-share\/|\-social\-share_|\/social\-share\-|\/social\/share\-|\/social\/share_|\/social_share_|&adnet=|\/campaign\/advertiser_|\/ad_preroll\-|\/nuggad\.|\/nuggad\/|\?adx=|\.com\/ads\-|\.com\/ads\.|\.com\/ads_|\/com\/ads\/|\/socialMedia\-|\/socialMedia\.|\/admaster\?|\/adverserve\.|\.com\/\?ad=|\.com\/ad\?|_ad\.png\?|\/analytics\/track\-|\/analytics\/track\.|\/analytics\/track\/|\/analytics\/track\?|\/analytics\/track$|\-google\-ad\.|\/google\-ad\-|\/google\-ad\?|\/google\/ad\?|\/google_ad\.|_google_ad\.|\.com\/counter\?|\/video\-ads\-management\.|\/social\-media\.|\/social_media\/|\-share\-button\.|\/share\-button\.|\/share\-button\?|\/share_button\.|\/share_button\?|\/share_button_|\/video\-ads\-player\.|\/masthead\/social\-|\/\?addyn$|&adurl=|\.com\/adz\/|\/amp\-ad\-|\/my\-ad\-injector\/|\/wp\-content\/plugins\/wp\-bannerize\/|\/_\/ads\/|\/adition\.|\/clickability\-|\/clickability\/|\/clickability\?|_clickability\/|\/img\-advert\-|\/wp\-content\/ads\/|\/adx\/iframe\.|\/adx_iframe_|\/follow\-us\-twitter\.|\/intelliad\.|\/show\-ad\.|\/show\.ad\?|\/show_ad\.|\/show_ad\?|\/adx\-exchange\.|\/wp\-content\/plugins\/automatic\-social\-locker\/|\/images\/ad2\/|\-ad\-pixel\-|\/ero\-advertising\.|\.com\/stats\.ashx\?|\-image\-ad\.|\/image\/ad\/|\/advlink\.|\/adsmanager\/|\/cookies\-monster\.js|\/ad\/display\.php|\/iframes\/ad\/|\/widget\-advert\.|\/admeta\.|=admeta&|\/leaderboard\-advert\.|\/ga_social_tracking_|\?AdUrl=|\/advertisments\/|\/toonad\.|\/adiframe\.|\/adiframe\/|\/adiframe\?|\/adiframe_|\/adv\-expand\/|\/adguru\.|\/pop_ad\.|_pop_ad\.|_pop_ad\/|\-social\-media\.|\/social_media_|_social\-media_|\.net\/ads\-|\.net\/ads\.|\.net\/ads\/|\.net\/ads\?|\.net\/ads_|\/cookie\-law\.js|\/cookie_law\.js|_cookie_law\.js|\/adrolays\.|\/cpx\-advert\/|\/social\-traffic\-pop\/|\/adwizard\.|\/adwizard\/|\/adwizard_|\/adverthorisontalfullwidth\.|\.AdmPixelsCacheController\?|\/adaptvexchangevastvideo\.|\/ForumViewTopicContentAD\.|\/postprofilehorizontalad\.|=adreplacementWrapperReg\.|\/adzonecenteradhomepage\.|\/ForumViewTopicBottomAD\.|\/advertisementrotation\.|\/advertisingimageexte\/|\/AdvertisingIsPresent6\?|\/postprofileverticalad\.|\/adblockdetectorwithga\.|\/admanagementadvanced\.|\/advertisementmapping\.|\/initlayeredwelcomead\-|\/advertisementheader\.|\/advertisingcontent\/|\/advertisingwidgets\/|\/thirdpartyframedad\/|\.AdvertismentBottom\.|\/adfrequencycapping\.|\/adgearsegmentation\.|\/advertisementview\/|\/advertising300x250\.|\/advertverticallong\.|\/AdZonePlayerRight2\.|\/ShowInterstitialAd\.|\/addeliverymodule\/|\/adinsertionplugin\.|\/AdPostInjectAsync\.|\/adrendererfactory\.|\/advertguruonline1\.|\/advertisementAPI\/|\/advertisingbutton\.|\/advertisingmanual\.|\/advertisingmodule\.|\/adzonebelowplayer\.|\/adzoneplayerright\.|\/jumpstartunpaidad\.|\?adtechplacementid=|\/adforgame160x600\.|\/adleaderboardtop\.|\/adpositionsizein\-|\/adreplace160x600\.|\/advertise125x125\.|\/advertisement160\.|\/advertiserwidget\.|\/advertisinglinks_|\/advFrameCollapse\.|\/requestmyspacead\.|\/supernorthroomad\.|\/adblockdetection\.|\/adBlockDetector\/|\/adbriteincleft2\.|\/adbriteincright\.|\/adchoicesfooter\.|\/adgalleryheader\.|\/adindicatortext\.|\/admatcherclient\.|\/adoverlayplugin\.|\/adreplace728x90\.|\/adtaggingsubsec\.|\/adtagtranslator\.|\/adultadworldpop_|\/advertisements2\.|\/advertisewithus_|\/adWiseShopPlus1\.|\/adwrapperiframe\.|\/contentmobilead\.|\/convertjsontoad\.|\/HompageStickyAd\.|\/mobilephonesad\/|\/sample300x250ad\.|\/tomorrowfocusAd\.|\/adblockDetector\.|\/adforgame728x90\.|\/adforgame728x90_|\/adinteraction\/|\/adaptvadplayer\.|\/adcalloverride\.|\/adfeedtestview\.|\/adframe120x240\.|\/adframewrapper\.|\/adiframeanchor\.|\/adlantisloader\.|\/adlargefooter2\.|\/adpanelcontent\.|\/adverfisement2\.|\/advertisement1\.|\/advertisement2\.|\/advertisement3\.|\/dynamicvideoad\?|\/premierebtnad\/|\/rotatingtextad\.|\/sample728x90ad\.|\/slideshowintad\?|\/adblockchecker\.|\/adchoicesicon\.|\/adframe728bot\.|\/adframebottom\.|\/adframecommon\.|\/adframemiddle\.|\/adinsertjuicy\.|\/adlargefooter\.|\/adleftsidebar\.|\/admanagement\/|\/adMarketplace\.|\/admentorserve\.|\/adotubeplugin\.|\/adPlaceholder\.|\/advaluewriter\.|\/adverfisement\.|\/advertising02\.|\/advertisment1\-|\/bottomsidead\/|\/getdigitalad\/|\/gigyatargetad\.|\/gutterspacead\.|\/leaderboardad\.|\/newrightcolad\.|\/promobuttonad\.|\/rawtubelivead\.|\/restorationad\-|=admodeliframe&|\/adblockdetect\.|\/adblockkiller\.|\/addpageview\/|\/admonitoring\.|&customSizeAd=|\-printhousead\-|\.advertmarket\.|\/AdBackground\.|\/adcampaigns\/|\/adcomponent\/|\/adcontroller\.|\/adfootcenter\.|\/adframe728b2\.|\/adifyoverlay\.|\/admeldscript\.|\/admentor302\/|\/admentorasp\/|\/adnetwork300\.|\/adnetwork468\.|\/AdNewsclip14\.|\/AdNewsclip15\.|\/adoptionicon\.|\/adrequisitor\-|\/adTagRequest\.|\/adtechHeader\.|\/adtechscript\.|\/advertisings\.|\/advertsquare\.|\/advertwebapp\.|\/advolatility\.|\/adzonebottom\.|\/adzonelegend\.|\/brightcovead\.|\/contextualad\.|\/custom11x5ad\.|\/horizontalAd\.|\/iframedartad\.|\/indexwaterad\.|\/jsVideoPopAd\.|\/PageBottomAD\.|\/skyscraperad\.|\/writelayerad\.|=dynamicwebad&|\-advertising2\-|\/advertising2\.|\/advtemplate\/|\/advtemplate_|\/adimppixel\/|\-adcompanion\.|\-adtechfront\.|\-advertise01\.|\-rightrailad\-|\/728x80topad\.|\/adchoices16\.|\/adchoicesv4\.|\/adcollector\.|\/adcontainer\?|\/addelivery\/|\/adfeedback\/|\/adfootright\.|\/adfoxLoader_|\/adframe728a\.|\/adframe728b\.|\/adfunctions\.|\/adgenerator\.|\/adgraphics\/|\/adhandlers2\.|\/adheadertxt\.|\/adhomepage2\.|\/adiframetop\.|\/admanagers\/|\/admetamatch\?|\/adpictures\/|\/adpolestar\/|\/adPositions\.|\/adproducts\/|\/adrequestvo\.|\/adrollpixel\.|\/adtopcenter\.|\/adtopmidsky\.|\/advcontents\.|\/advertises\/|\/advertlayer\.|\/advertright\.|\/advscripts\/|\/adzoneright\.|\/asyncadload\.|\/crossoverad\-|\/dynamiccsad\?|\/gexternalad\.|\/indexrealad\.|\/instreamad\/|\/internetad\/|\/lifeshowad\/|\/newtopmsgad\.|\/o2contentad\.|\/propellerad\.|\/showcasead\/|\/showflashad\.|\/SpotlightAd\-|_companionad\.|\.adplacement=|\/adplacement\.|\/adversting\/|\/adversting\?|\-NewStockAd\-|\.adgearpubs\.|\.rolloverad\.|\/300by250ad\.|\/adbetween\/|\/adbotright\.|\/adboxtable\-|\/adbriteinc\.|\/adchoices2\.|\/adcontents_|\/AdElement\/|\/adexclude\/|\/adexternal\.|\/adfillers\/|\/adflashes\/|\/adfliction\-|\/adFooterBG\.|\/adfootleft\.|\/adformats\/|\/adframe120\.|\/adframe468\.|\/adframetop\.|\/adhandlers\-|\/adhomepage\.|\/adiframe18\.|\/adiframem1\.|\/adiframem2\.|\/adInfoInc\/|\/adlanding\/|\/admanager3\.|\/admanproxy\.|\/adorika300\.|\/adorika728\.|\/adoverride\.|\/adperfdemo\.|\/AdPreview\/|\/adprovider\.|\/adquality\/|\/adreplace\/|\/adrequests\.|\/adrevenue\/|\/adrightcol\.|\/adrotator2\.|\/adtextmpu2\.|\/adtopright\.|\/adv180x150\.|\/advertical\.|\/advertmsig\.|\/advertphp\/|\/advertpro\/|\/advertrail\.|\/advertstub\.|\/adviframe\/|\/advlink300\.|\/advrotator\.|\/advtarget\/|\/AdvWindow\/|\/adwidgets\/|\/adWorking\/|\/adwrapper\/|\/adxrotate\/|\/AdZoneAdXp\.|\/adzoneleft\.|\/baselinead\.|\/deliverad\/|\/DynamicAd\/|\/getvideoad\.|\/lifelockad\.|\/lightboxad[^\w.%-]|\/neudesicad\.|\/onplayerad\.|\/photo728ad\.|\/postprocad\.|\/pushdownAd\.|\/PVButtonAd\.|\/rotationad\.|\/sidelinead\.|\/slidetopad\.|\/tripplead\/|\?adlocation=|\?adunitname=|_preorderad\.|\-adrotation\.|\/adgallery2\.|\/adgallery2$|\/adgallery3\.|\/adgallery3$|\/adinjector\.|\/adinjector_|\/adpicture1\.|\/adpicture1$|\/adpicture2\.|\/adpicture2$|\/adrotation\.|\/externalad\.|_externalad\.|\/adcontrol\.|\/adcontrol\/|\/adinclude\.|\/adinclude\/|\/adkingpro\-|\/adkingpro\/|\/adoverlay\.|\/adoverlay\/|&adgroupid=|&adpageurl=|\-Ad300x250\.|\/125x125ad\.|\/300x250ad\.|\/ad125x125\.|\/ad160x600\.|\/ad1x1home\.|\/ad2border\.|\/ad2gather\.|\/ad300home\.|\/ad300x145\.|\/ad600x250\.|\/ad600x330\.|\/ad728home\.|\/adactions\.|\/adasset4\/|\/adbayimg\/|\/adblock26\.|\/adbotleft\.|\/adcentral\.|\/adchannel_|\/adclutter\.|\/adengage0\.|\/adengage1\.|\/adengage2\.|\/adengage3\.|\/adengage4\.|\/adengage5\.|\/adengage6\.|\/adexample\?|\/adfetcher\?|\/adfolder\/|\/adforums\/|\/adframes\/|\/adheading_|\/adiframe1\.|\/adiframe2\.|\/adiframe7\.|\/adiframe9\.|\/adinator\/|\/AdLanding\.|\/adLink728\.|\/adlock300\.|\/admarket\/|\/admeasure\.|\/admentor\/|\/adNdsoft\/|\/adonly468\.|\/adopspush\-|\/adoptions\.|\/adreclaim\-|\/adrelated\.|\/adrequest\.|\/adRequest\?|\/adruptive\.|\/adtopleft\.|\/adunittop$|\/advengine\.|\/advertize_|\/advertsky\.|\/adverttop\.|\/advfiles\/|\/adviewas3\.|\/advloader\.|\/advscript\.|\/advzones\/|\/adwriter2\.|\/adyard300\.|\/adzonetop\.|\/contentAd\.|\/contextad\.|\/delayedad\.|\/devicead\/|\/dynamicad\?|\/galleryad\.|\/getTextAD\.|\/GetVASTAd\?|\/invideoad\.|\/MonsterAd\-|\/overlayad\.|\/PageTopAD\.|\/pitattoad\.|\/prerollad\.|\/processad\.|\/proxxorad\.|\/showJsAd\/|\/siframead\.|\/slideinad\.|\/sliderAd\/|\/spiderad\/|\/testingad\.|\/tmobilead\.|\/unibluead\.|\/vert728ad\.|\/vplayerad\.|\/VXLayerAd\-|\/webmailad\.|\/welcomead\.|=DisplayAd&|\?adcentric=|\?adcontext=|\?adflashid=|\?adversion=|\?advsystem=|\/admonitor\-|\/admonitor\.|\/adrefresh\-|\/adrefresh\.|\/defaultad\.|\/defaultad\?|\/facebook\-top\.|\/ad\.aspx\?|\/adconfig\.|\/adconfig\/|\/addefend\.|\/addefend\/|\/adfactor\/|\/adfactor_|\/adwidget\/|\/adwidget_|\/bottomad\.|\/bottomad\/|\/buttonad\/|_buttonad\.|\/adplayer\-|\/adplayer\.|\/adplayer\/|&adclient=|\/adclient\-|\/adclient\.|\/adclient\/|\-Ad300x90\-|\-adcentre\.|\-adhelper\.|\/768x90ad\.|\/ad120x60\.|\/ad1place\.|\/ad290x60_|\/ad468x60\.|\/ad468x80\.|\/AD728cat\.|\/ad728rod\.|\/adarena\/|\/adasset\/|\/adblockl\.|\/adblockr\.|\/adborder\.|\/adbot160\.|\/adbot300\.|\/adbot728\.|\/adbottom\.|\/AdBoxDiv\.|\/adboxes\/|\/adbrite2\.|\/adbucket\.|\/adbucks\/|\/adcast01_|\/adcframe\.|\/adcircle\.|\/adcodes\/|\/adcommon\?|\/adcxtnew_|\/addeals\/|\/adError\/|\/adfooter\.|\/adframe2\.|\/adfront\/|\/adgetter\.|\/adheader\.|\/adhints\/|\/adifyids\.|\/adindex\/|\/adinsert\.|\/aditems\/|\/adlantis\.|\/adleader\.|\/adlinks2\.|\/adloader\.|\/admicro2\.|\/adModule\.|\/adnotice\.|\/adonline\.|\/adpanel\/|\/adparts\/|\/adplace\/|\/adplace5_|\/adremote\.|\/adroller\.|\/adtagcms\.|\/adtaobao\.|\/adtimage\.|\/adtonomy\.|\/adtop160\.|\/adtop300\.|\/adtop728\.|\/adtopsky\.|\/adtvideo\.|\/advert01\.|\/advert24\.|\/advert31\.|\/advert32\.|\/advert33\.|\/advert34\.|\/advert35\.|\/advert36\.|\/advert37\.|\/adverweb\.|\/adviewed\.|\/adviewer\.|\/adzilla\/|\/adzones\/|\/anchorad\.|\/attachad\.|\/bigboxad\.|\/customad\.|\/getmyad\/|\/globalad\.|\/gutterAd\.|\/incmpuad\.|\/injectad\.|\/insertAd\.|\/insideAD\.|\/jamnboad\.|\/jstextad\.|\/leaderad\.|\/localAd\/|\/masterad\.|\/mstextad\?|\/multiad\/|\/noticead\.|\/pencilad\.|\/pledgead\.|\/salesad\/|\/spacead\/|\/squaread\.|\/stickyad\.|\/stocksad\.|\/topperad\.|\/tribalad\.|\/VideoAd\/|\/widgetad\.|=ad320x50\-|=adexpert&|\?adformat=|\?adPageCd=|\?adTagUrl=|_adaptvad\.|_StickyAd\.|\/468x60ad\.|\/admarker\.|\/admarker_|\/commonAD\.|\/footerad\.|\/footerad\?|\/headerad\.|_468x60ad\.|_commonAD\.|_headerad\.|\-admarvel\/|\.admarvel\.|\/admarvel\.|\/adometry\-|\/adometry\.|\/adometry\?|\/adcycle\.|\/adcycle\/|\/adfiles\.|\/adfiles\/|\/adpeeps\.|\/adpeeps\/|\/adproxy\.|\/adproxy\/|\/advalue\/|\/advalue_|\/printad\.|\/printad\/|\/servead\.|\/servead\/|\/adunits\.|\/adunits\/|\/adunits\?|\-adimage\-|\/adimage\.|\/adimage\/|\/adimage\?|\/adpixel\.|&largead=|\-adblack\-|\-adhere2\.|\/ad2gate\.|\/ad2push\.|\/ad300f2\.|\/ad300ws\.|\/ad728f2\.|\/ad728ws\.|\/AdAgent_|\/adanim\/|\/adboxbk\.|\/adbytes\.|\/adcache\.|\/adedge\/|\/adentry\.|\/adfeeds\.|\/adfever_|\/adflash\.|\/adfshow\?|\/adfuncs\.|\/adgear1\-|\/adgear2\-|\/adhtml\/|\/adlandr\.|\/admatch\-|\/admatik\.|\/admicro_|\/adnexus\-|\/adpagem\.|\/adpatch\.|\/adpoint\.|\/adpool\/|\/adpop32\.|\/adprove_|\/adratio\.|\/adroot\/|\/adrotat\.|\/adrotv2\.|\/adtable_|\/adtadd1\.|\/adtagtc\.|\/adtext2\.|\/adtext4\.|\/adtomo\/|\/adtraff\.|\/adutils\.|\/advault\.|\/advdoc\/|\/advert4\.|\/advert5\.|\/advert6\.|\/advert8\.|\/adverth\.|\/advinfo\.|\/adVisit\.|\/advris\/|\/advshow\.|\/adweb33\.|\/adwise\/|\/adzbotm\.|\/adzerk2_|\/adzone1\.|\/adzone4\.|\/bookad\/|\/coread\/|\/flashad\.|\/gamead\/|\/hoverad\.|\/jsonad\/|\/LayerAd[^\w.%-]|\/modalad\.|\/nextad\/|\/panelad\.|\/photoad\.|\/promoAd\.|\/rpgetad\.|\/safead\/|\/ServeAd\?|\/smartAd\?|\/transad\.|\/trendad\.|\?adclass=|\/adbuddy\.|&advtile=|&smallad=|\-advert3\.|\-sync2ad\-|\.adforge\.|\/adcheck\.|\/adcheck\?|\/adfetch\.|\/adfetch\?|\/adforge\.|\/adlift4\.|\/adlift4_|\/adlinks\.|\/adlinks_|\/adttext\-|\/adttext\.|\/advert3\.|\/smallad\-|\/sync2ad\.|\?advtile=|\-adchain\.|\-advert2\.|\/adchain\-|\/adchain\.|\/advert2\-|\/advert2\.|\/layerad\-|\/layerad\.|_layerad\.|\-web\-advert\-|_web\-advert\.|\/google\/analytics\.js|\/adfile\.|\/adfile\/|\/adleft\.|\/adleft\/|\/peelad\.|\/peelad\/|\/adtest\.|\/adtest\/|\/sidead\.|\/sidead\/|\/viewad\.|\/viewad\/|\/viewad\?|_sidead\.|\/socialmedia_|_socialmedia_|&adzone=|\/adzone\.|\/adzone\/|\/adzone_|\?adzone=|\/adinfo\?|\/adtctr\.|\/adtrk\/|&adflag=|&adname=|\/ad000\/|\/ad125b\.|\/ad136\/|\/ad160k\.|\/ad2010\.|\/ad2con\.|\/ad300f\.|\/ad300s\.|\/ad300x\.|\/ad728f\.|\/ad728s\.|\/ad728t\.|\/ad728w\.|\/ad728x\.|\/adbar2_|\/adbase\.|\/adbebi_|\/adbl1\/|\/adbl2\/|\/adbl3\/|\/adblob\.|\/adbox1\.|\/adbox2\.|\/adcast_|\/adclix\.|\/adcomp\.|\/adcss\/|\/add728\.|\/adfeed\.|\/adfly\/|\/adicon_|\/adinit\.|\/adjsmp\.|\/adjson\.|\/adkeys\.|\/adlens\-|\/admega\.|\/adnap\/|\/ADNet\/|\/adnet2\.|\/adnew2\.|\/adpan\/|\/adperf_|\/adping\.|\/adpix\/|\/adplay\.|\/AdPub\/|\/adRoll\.|\/adtabs\.|\/adtago\.|\/adunix\.|\/adutil\.|\/Adv150\.|\/Adv468\.|\/advPop\.|\/advweb\.|\/adweb2\.|\/adx160\.|\/adyard\.|\/adztop\.|\/ajaxAd\?|\/baseAd\.|\/bnrad\/|\/boomad\.|\/cashad\.|\/cubead\.|\/curlad\.|\/cutead\.|\/DemoAd\.|\/dfpad\/|\/divad\/|\/drawad\.|\/ebayad\.|\/flatad\.|\/freead\.|\/fullad\.|\/geoad\/|\/GujAd\/|\/idleAd\.|\/ipadad\.|\/livead\-|\/metaad\.|\/MPUAd\/|\/navad\/|\/Nuggad\?|\/postad\.|\/railad\.|\/retrad\.|\/rollad\.|\/rotad\/|\/svnad\/|\/tinyad\.|\/WebAd\/|=adMenu&|=adView&|\?adarea=|\?advurl=|&adlist=|\.adwolf\.|\.lazyad\-|\.openad\.|\/adback\.|\/adback\?|\/adlist_|\/admain\.|\/admain$|\/adwolf\.|\/adworx\.|\/adworx_|\/footad\-|\/footad\.|\/lazyad\.|\/mainad\.|\/openad\.|\/skinad\.|_mainad\.|_skinad\.|\/adpic\.|\/adpic\/|\/adwiz\.|\/adwiz\/|\/flyad\.|\/flyad\/|\/adtag\.|\/adtag\/|\/adtag\?|\/adtag_|\?adtag=|\/adimp\?|&admid=|&adnum=|\-NewAd\.|\/120ad\.|\/300ad\.|\/468ad\.|\/ad11c\.|\/ad125\.|\/ad160\.|\/ad234\.|\/ad24\/|\/ad350\.|\/ad468\.|\/adban\.|\/adbot_|\/adbug_|\/adCfg\.|\/adcgi\?|\/adfrm\.|\/adGet\.|\/adGpt\.|\/adhug_|\/adixs\.|\/admgr\.|\/adpop\.|\/adrec\.|\/adrun\.|\/adv02\.|\/adv03\.|\/advdl\.|\/advf1\.|\/advhd\.|\/advt2\.|\/adxcm_|\/adyea\.|\/affad\?|\/bizad\.|\/buyad\.|\/ciaad\.|\/cnxad\-|\/getAd;|\/ggad\/|\/gujAd\.|\/layad\.|\/ledad\.|\/mktad\.|\/mpuad\.|\/pubad\.|\/subAd\.|\/txtad\.|\/ypad\/|\?adloc=|\?PopAd=|_125ad\.|_250ad\.|_FLYAD\.|\/adrum\-|\/adrum\.|\.homad\.|\.intad\.|\.intad\/|\/ad728\-|\/ad728\.|\/adrot\.|\/adrot_|\/newad\.|\/newad\?|\/popad\-|\/popad\.|_homad\.|\/cn\-advert\.|\/bin\/stats\?|\/ad\/img\/|\/ad_img\.|\/ad_img\/|\/admp\-|\-ad03\.|\.adru\.|\/ad12\.|\/ad15\.|\/ad16\.|\/ad1r\.|\/ad3i\.|\/ad41_|\/ad4i\.|\/adbn\?|\/adfr\.|\/adjk\.|\/adnl\.|\/adv1\.|\/adv2\.|\/adv5\.|\/adv6\.|\/adv8\.|\/adx2\.|\/adxv\.|\/bbad\.|\/cyad\.|\/o2ad\.|\/pgad\.|\/vs\-track\.js|\/img2\/ad\/|\/images\.adv\/|\/images\/adv\-|\/images\/adv\.|\/images\/adv\/|\/images\/adv_|\/ad8\.|\/jsad\/|\.sharebar\.js|\-facebook\-btn\.|_facebook_btn\.|\/advs\/|\/ad_campaigns\/|\/adhandler\.|\/share\-buttons\-|\/share\-buttons\/|\/share\/buttons\/|\/share_buttons\-|\.cfm\?advideo%|\/adimages\.|\-ad\-server\/|\/ad\-server\.|\/ad\-server\/|\/ad_server\.|\/ad_server\/|\-ad1\.|\/ad1_|\/adgallery1\.|\/adgallery1$|\?adunitid=|\/get\-advert\-|\/ad\-sprite\.|\?affiliate=|\/content\/adv\/|\/stats\/tracker\.js|\/utep_ad\.js|\/bg\-advert\-|_type=adimg&|\/ajax\-advert\-|\/ajax\-advert\.|\.biz\/ad2\/|\/ados\?|\.tv\/log\?event|\/share2\-|\/images\/bg_ad\/|\.uk\/track\?|\/plugins\/ad\.|\/scripts\/adv\.|\/site_under\.|\/ads\/popshow\.|\/ad\/swf\/|\/wp\-srv\/ad\/|\/ad_pop\.|\/click\-stat\.js|\/ajax\/optimizely\-|\/adlabs\.js|\/chitika\-ad\?|\/wp_stat\.php\?|\/adpicture\.|\/js\/tracker\.js|\/ad2\/index\.|\/adv3\.|\/aff_banner\/|\/ss\-social\-|\/banner\.asp\?|\-advert\-placeholder\.|\/ad2\/res\/|\/static\/js\/4728ba74bc\.js|\/adv_script_|\/script\-adv\-|\/ad\-manager\/|\/ad_manager\.|\/ad_manager\/|\/adsatt\.|\/cookie_ws\.|\/cookie_ws\/|\-nav\-ad\.|\/global\-analytics\.js|\/event\-tracking\.js|\-cookie\-notice\.|\/cookie\-notice\-|\/cookie\-notice\.|\/cookie_notice\.|_cookie_notice\-|_cookie_notice\.|_facebook_social_|\/advt\.|\/advt\/|\-twitter\-social\.|\/twitter\-social\-|_twitter_social_|\/bottom\-advert\-|\/twitter2_icon\.|\/exports\/tour\/|\-advertise\/|\/advertise\-|\/advertise_|\.com\/im\-ad\/|\.com\/im_ad\/|\/ads300\.|\-social\-facebook\-|\-social\-facebook\.|\/social\-facebook\-|\/social\-facebook\.|\/social\/facebook\-|\/social\/facebook\/|\/social\/facebook_|\/social_facebook|_social_facebook\.|_tracker_min\.|\-social\-twitter\-|\-social\-twitter\.|\/social\-twitter\-|\/social\-twitter\.|\/social\/twitter\-|\/social\/twitter_|\/social_twitter|_social\-twitter\.|_social_twitter\.|\?advert_key=|\/Ad\.asmx\/|\/adtype\.|\/adtype=|\?adtype=|\.nl\/ad2\/|\-article\-advert\-|\-adswizz\-|\/plugins\/flare\/js\/flare\.js|\-ad\-left\.|\/ad\-left\.|\/ad_left\.|\/ad_left_|\/images\/adds\/|\/ad\-exchange\.|\/adv\.php|\-gif\-advert\.|\/scripts\/ad\-|\/scripts\/ad\.|\/scripts\/ad\/|\/scripts\/ad_|\/widget\/ad\/|_widget_ad\.|\/share\-social\-networks\.|\/log_stats\.php\?|\/twitter\-space\.|\/asesor\-cookies\-|\-ad\.jpg\?|\/tracker\/track\.php\?|\/Twitter_social\.|\/icon\/share\-|\/wp\-content\/plugins\/anti\-block\/|\/adnetwork\/|\/adnetwork_|\/track\/track\.php\?|\/Ad\/Oas\?|\/layer\-advert\-|\/plugins\/CookieInfo\/|\/adx_flash\.|\/adsx\/|\/assets\/sponsored\/|\/jinda\-facebook\-lightbox\/|\/plugins\/anmiated\-twitter\-bird\/|\/follow\-on\-twitter\.|\/share\-twitter1a\.|\-social\-buttons\-|\/social\-buttons\.|\/social\-buttons\/|\/social_buttons\.|\/social_buttons\/|\/stream\-ad\.|\/youtube\-track\-event_|\/twitter_12\.|\/cookie\/visitor\/|\/layer\-cookienotice\.|\/assets\/twitter\-|\/libs\/tracker\.js|_youtube_social_|\/social\-youtube\-|\/social\-youtube\.|\/social_youtube|\/facebook_badge\-|\/facebook_badge\.|_facebook_badge\.|\.com\/ad2\/|\-ads\-manager\/|\/ads_manager\.|\/ad\/afc_|\/ad\/script\/|\/ad_script\.|\/ad_script_|\/facebook\-space\.|\/adb\.policy\.js|\/script\/ad\.|\/share2\.png|\/facebook\-pagelike\-widget\/|\/Google_plus_logo_|\/share\-google1a\.|\/share_googlePlus_|\/share\/googlebookmarks\.|\/share\-on\-diaspora\/|\/follow\-twitter\-|\/follow\-twitter\.|\/follow_twitter\.|\/twitter\-follow\-|\/twitter_follow\.|_twitter_follow\.|\/share\/yahoomyweb\.|\/cookie\-master\.js|\/wp\-content\/plugins\/wp\-super\-popup\-pro\/|\-socialmedia\-sprite\.|\/cookiec\.json|\/facebook\-follow\-|\/facebook_follow\.|\/follow\-facebook\.|\/follow_facebook\.|\/soc_twitter2\.|\/social\-media\-sprite\.|\/wp\-content\/tracker\.|\/stat\-analytics\/|\/facebook\-head\.|\/Twitter_Social_|\/gravity\-beacon\.js|\/ad\-blocking\-alert\/|\/adgeo\/|\/youtube\-space\.|\.com\/adds\/|\/plugins\/sme\-facebook\-|\/addLinkerEvents\-std\.|\/twitter\/facebook_|\/local\-ad\.|\/n4403ad\.|\/get_tracking_id\?|\/eu_rp_cookie\.|\-google\-plus\-|\-google\-plus\.|\-google\-plus_|\/google\-plus_|\/google_plus\-|\/track_social\.|\/share_blogger\.|\/js\/FB\.Share$|\/core\-tracking\.js|\/adjs\.|\/adjs\/|\/adjs\?|\/adjs_|\.jsp\?adcode=|\/twitter_cookies\.|\/show_ads\.js|\/getad\.|\/getad\/|\/getad\?|\/adv\/topBanners\.|\/adv\/bottomBanners\.|\/sponsor%20banners\/|\/g_track\.php\?|\/bi_affiliate\.js|\/Facebook_Social_|\/ad_bar_|\/bar\-ad\.|\-ads\/oas\/|\/ads\/oas\-|\/ads\/oas\/|\-advert\-100x100\.|\/plugins\/cookie\-muncher\/|\/ad\/generate\?|\/generate_ad\.|\/wp\-content\/uploads\/useful_banner_manager_banners\/|\/ad\/files\/|\/ad_files\/|\/affiliate\-assets\/banner\/|\/google\-nielsen\-analytics\.|&admeld_|\/admeld\.|\/admeld\/|\/admeld_|=admeld&|&advert_|\/\!advert_|\/advert\/|\/advert\?|\/advert_|=advert\/|\/files\/ad\-|\/files\/ad\/|_files\/ad\.|\/twitter\/twitter_|\/gadgets\/ad\/|\/follow\/Twitter\-|_googleplus_logo\.|\/twitter\-16px\.|\-cookies\-policy\.|\/cookies\-policy\-|\/cookies\-policy\/|\-mediaplex_|\/sni_cookie_privacy\/|\/click_track\.js|\/adv_image\/|\/image\/adv\/|\/ad_notice\.|\-social\-you\-tube\.|\/ads\.json\?|\/nd_affiliate\.|\/cookies_loading\.php\?|\/twitter\-share\-|\/twitter\-share\.|\/twitter_share\.|\/affiliate\.linker\/|\/affiliate\.1800flowers\.|\/ad\/js\/pushdown\.|\/affiliate\/displayWidget\?|\/ad_space\.|\/space_ad\.|\.widgets\.ad\?|\/jjp_eucookie_|\/icon_32_facebook\.|\/ad\-plugin\/|\/plugin\/ad\/|\/EU\-cookielaw\.|_cookielaw_mip\.|\/twitter_sprite\.|\/images\/twitter|\/native\-advertising\/|\/econa\-site\-search\-ajax\-log\-referrer\.php|\/site\-advert\.|\/tracked_ad\.|\/cookie\-accept\.js|\/cookie_msg\.js|\/mod_jbcookies\/|\/storage\/adv\/|\/ad_campaign\?|\/ads\/head\.|\/p2\/ads\/|\/tracker\.json\.php\?|\/ad_entry_|\/adim\.html\?ad|\/trackingfilter\.json\?|\/smartad\-|\/smartad\.|\/smartad\/|\/facebook_header\.|\/follow\/Facebook\-|_eucookie_compliance_|\/tracking\/track\.php\?|\/you\-tube\.jpg|\/cookies_bar\.js|\/pickle\-adsystem\/|_fullimage_Twitter\.|\/track\/event\/|\/track\?event=|\/jquery\.google\-analytics\.|\/youtube\-follow\.|\/youtube_follow\.|\/follow\-youtube\.|\/facebook\-share\-|\/facebook\-share\.|\/facebook_share\.|\/facebook_share_|\/md\.js\?country=|\/plugins\/facebookpopuppro\/|\/promo\/ad_|_promo_ad\/|\/ad728x15\.|\/ad728x15_|\/cookie_info\.css|\/splash\/twitter\.|\/twitter\-Custom\.|\/ad_bannerPool\-|\/bannerfile\/ad_|\-advertising_|\/advertising\?|\/advertising_|\?advertising=|\/Facebook\-Logo\-|\/ad\/superbanner\.|\/story_ad\.|\-ads\-placement\.|\/cookie\?affiliate|\/color\-twitter\-|\/header\-twitter\.png|\/polopoly_fs\/ad\-|\/ads\-admin\.|\/stats_blog\.js\?|\/Twitter_36\.|\/twitter\-after\-|\/logo_twitter\.|\/twitter\-logo\-|\/twitter\-logo\.|\/twitter_logo\.|\/twitter_logo_|_twitter_logo\.|\/twitter_bird\.|\/twitter_bird_|\/socjal\/twitter\.|\/sp\-analytics\-|\/ad_print\.|\/affiliate\-tracker\.|\/Cookies_Pro\/|\/googleplus_42\.|\/twitter_42\.|\.ws\/ads\/|\/twitter_64x|\/nav\-twitter\-|\/nav_twitter\.|\/affiliate\/small_banner\/|\/body\/share\/|\/twitter_bubble_|\/iconbig\-twitter\-|\/share\.json\?|\/json\/tracking\/|\/ad_fixedad\.|\/ads\/adv\/|\/adv\/ads\/|\/all\/ad\/|\.lazyload\-ad\-|\.lazyload\-ad\.|\/ad_lazyload\.|\/create\-lead\.js|\-cookie\-msg\-bar\.|\/share\-twitter\-|\/share\-twitter\.|\/share\/twitter\.|\/share_twitter\.|\/share_twitter_|_share_twitter\.|\/jquery_FOR_AD\/|\/Facebook_36\.|\/GoogleAnalytics\?utmac=|\/adpage\-|\/adpage\/|\?adpage=|\/googleplus_14\.|\/qpon_big_ad|\/comscore_beacon\.|\/affiliate\/ads\/|\/readReceipt\/notify\/\?img=|\/webmaster_ads\/|\/ad_selectMainfixedad\.|\/ad_contents\/|\/social_logo_|\/youtube\-logo\-)/i;
var bad_url_parts_flag = 1999 > 0 ? true : false;  // test for non-zero number of rules
    
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
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]+)(\\??[\\S]*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24}\\.?)", "i");

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
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                // Redefine url and host to avoid leaking information to the blackhole
                url = "http://127.0.0.1:80";
                host = "127.0.0.1";
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
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
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
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
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return MyFindProxyForURL(url, host);
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
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
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return MyFindProxyForURL(url, host);
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
            // Redefine url and host to avoid leaking information to the blackhole
            url = "http://127.0.0.1:80";
            host = "127.0.0.1";
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
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
