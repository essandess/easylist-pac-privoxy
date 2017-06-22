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
// 70 rules:
var good_da_host_JSON = { "content-img.newsinc.com": null,
"images.sportsworldnews.com": null,
"ads.indeed.com": null,
"ads.m1.com.sg": null,
"ads.pinterest.com": null,
"adserver.bworldonline.com": null,
"adserver.tvcatchup.com": null,
"adsign.republika.pl": null,
"advertise.azcentral.com": null,
"advertising.acne.se": null,
"advertising.autotrader.co.uk": null,
"advertising.scoop.co.nz": null,
"advertising.theigroup.co.uk": null,
"advertising.utexas.edu": null,
"advertising.vrisko.gr": null,
"adverts.cdn.tvcatchup.com": null,
"banners.gametracker.rs": null,
"banners.wunderground.com": null,
"euads.org": null,
"files.coloribus.com": null,
"img.travidia.com": null,
"maps-static.chitika.net": null,
"media.cargocollective.com": null,
"pop.advecs.com": null,
"popad.co": null,
"promo.campaigndog.com": null,
"videosxml.mobileads.indiatimes.com": null,
"vswebapp.com": null,
"ads.nipr.ac.jp": null,
"ads.cvut.cz": null,
"adsystem.pl": null,
"adv.pt": null,
"advert.ee": null,
"forads.pl": null,
"homad.eu": null,
"reklama5.mk": null,
"tvn.adocean.pl": null,
"www.advertising.com": null,
"dashboard.idealmedia.com": null,
"dashboard.lentainform.com": null,
"dashboard.marketgid.com": null,
"dashboard.mgid.com": null,
"dashboard.tovarro.com": null,
"fullad.com.br": null,
"adfox.ru": null,
"adhese.com": null,
"api-merchants.skimlinks.com": null,
"authentication-api.skimlinks.com": null,
"advertising.microsoft.com": null,
"advertise.mxit.com": null,
"ads.stumbleupon.com": null,
"advertise.ru": null,
"ads.acesse.com": null,
"revealads.com": null,
"adsbox.io": null,
"ads.memo2.nl": null,
"ads.askgamblers.com": null,
"ads.twitter.com": null,
"adv.blogupp.com": null,
"adv.welaika.com": null,
"ads.fuckingmachines.com": null,
"ads.ultimatesurrender.com": null,
"logging.apache.org": null,
"metrics.mozilla.com": null,
"metrics.torproject.org": null,
"query.petametrics.com": null,
"siteanalytics.compete.com": null,
"track2.royalmail.com": null,
"trackjs.com": null,
"webtrack.dhlglobalmail.com": null };
var good_da_host_exact_flag = 70 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 0 rules:
var good_da_host_regex = "";
var good_da_host_regex_flag = 0 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 1105 rules:
var good_da_hostpath_JSON = { "cdndoge.xyz/common/js/cookie.js": null,
"cdndoge.xyz/common/js/jquery.js": null,
"cdndoge.xyz/lib/sweetalert/sweetalert.js": null,
"cdndoge.xyz/video-download/js/bootstrap.js": null,
"cdndoge.xyz/video-download/js/dropdown.js": null,
"cdndoge.xyz/video-download/js/event.js": null,
"cdndoge.xyz/video-download/js/waves.js": null,
"4archive.org/js/jquery.min.js": null,
"4archive.org/js/linkify-jquery.min.js": null,
"4archive.org/js/linkify.min.js": null,
"randomarchive.com/js/jquery.min.js": null,
"randomarchive.com/js/linkify-jquery.min.js": null,
"randomarchive.com/js/linkify.min.js": null,
"thebarchive.com/foolfuuka/components/highlightjs/highlight.pack.js": null,
"last.fm/static/js-build/url.js": null,
"vidshare.us/player6/jwplayer.js": null,
"adf.ly/static/image": null,
"imgadult.com/advertisement.js": null,
"imgtaxi.com/advertisement.js": null,
"imgwallet.com/advertisement.js": null,
"gorillavid.in/xupload.js": null,
"flashx.tv/js/jquery.cookie.js": null,
"flashx.tv/js/xfs.js": null,
"flashx.tv/js/xupload.js": null,
"flashx.tv/player6/jwplayer.js": null,
"exashare.com/ad.js": null,
"speedtest.net/javascript/extMouseWheel.js": null,
"speedtest.net/javascript/functions.js": null,
"speedtest.net/javascript/highcharts.js": null,
"speedtest.net/javascript/jquery.placeholder.min.js": null,
"speedtest.net/javascript/jquery.tipTip.js": null,
"speedtest.net/javascript/swfobject.js": null,
"thegatewaypundit.com/wp-content/uploads/submit_tip.png": null,
"thegatewaypundit.com/wp-includes/images/rss.png": null,
"anyporn.com/captcha/comments": null,
"anyporn.com/videos_screenshots": null,
"motherless.com/scripts/auth.min.js": null,
"motherless.com/scripts/bots.min.js": null,
"motherless.com/scripts/classifieds.min.js": null,
"motherless.com/scripts/groups.js": null,
"motherless.com/scripts/home_page.min.js": null,
"motherless.com/scripts/jquery-ui.js": null,
"motherless.com/scripts/jwplayer.html5.js": null,
"motherless.com/scripts/jwplayer.js": null,
"motherless.com/scripts/media.min.js": null,
"motherless.com/scripts/members.min.js": null,
"motherless.com/scripts/perfect-scrollbar.jquery.min.js": null,
"motherless.com/scripts/register.min.js": null,
"motherless.com/scripts/responsive.min.js": null,
"motherless.com/scripts/site.min.js": null,
"motherless.com/scripts/sprintf.min.js": null,
"motherless.com/scripts/store.min.js": null,
"motherless.com/scripts/swfobject.js": null,
"33universal.adprimemedia.com/vn/vna/data/ad.php": null,
"360gig.com/images/1_468x60.png": null,
"53.com/resources/images/ad-rotator": null,
"6waves.com/ads/720x300": null,
"6waves.com/js/adshow.js": null,
"abbyy.com/adx": null,
"abcnews.com/assets/static/ads/fwps.js": null,
"abcnews.go.com/assets/static/ads/fwps.js": null,
"ad.71i.de/crossdomain.xml": null,
"ad.71i.de/global_js/magic/sevenload_magic.js": null,
"ad.adserve.com/crossdomain.xml": null,
"ad.afy11.net/crossdomain.xml": null,
"ad.doubleclick.net/adx/nbcu.nbc/rewind": null,
"ad.doubleclick.net/pfadx/nbcu.nbc/rewind": null,
"ad.reebonz.com/www": null,
"ad.smartclip.net/crossdomain.xml": null,
"ad2.zophar.net/images/logo.jpg": null,
"adap.tv/crossdomain.xml": null,
"adap.tv/redir/client/adplayer.swf": null,
"adap.tv/redir/javascript/vpaid.js": null,
"adf.ly/static/image/ad_top_bg.png": null,
"adflyer.co.uk/adverts": null,
"adhostingsolutions.com/crossdomain.xml": null,
"adimages.go.com/crossdomain.xml": null,
"adotube.com/crossdomain.xml": null,
"ads.dollartree.com/SneakPeek": null,
"ads.fox.com/fox/black_2sec_600.flv": null,
"ads.foxnews.com/js/ad.js": null,
"ads.foxnews.com/js/adv2.js": null,
"ads.foxnews.com/js/omtr_code.js": null,
"ads.intergi.com/crossdomain.xml": null,
"ads.mefeedia.com/flash/flowplayer-3.1.2.min.js": null,
"ads.mefeedia.com/flash/flowplayer.controls-3.0.2.min.js": null,
"ads.nyootv.com/crossdomain.xml": null,
"ads.songs.pk/openx/www/delivery": null,
"ads.trutv.com/crossdomain.xml": null,
"ads.undertone.com/crossdomain.xml": null,
"ads1.msn.com/ads/pronws": null,
"adserver.bigwigmedia.com/ingamead3.swf": null,
"adserver.yahoo.com/crossdomain.xml": null,
"adshost1.com/crossdomain.xml": null,
"adspot.co.za/image.php": null,
"adsremote.scrippsnetworks.com/crossdomain.xml": null,
"adssecurity.com/app_themes/ads/images": null,
"adtechus.com/crossdomain.xml": null,
"adultvideotorrents.com/assets/blockblock/advertisement.js": null,
"advantabankcorp.com/ADV": null,
"advertising.nzme.co.nz/media": null,
"ae.amgdgt.com/crossdomain.xml": null,
"affiliate.kickapps.com/crossdomain.xml": null,
"affiliate.kickapps.com/service": null,
"affiliates.unpakt.com/widget_loader/widget_loader.js": null,
"africam.com/adimages": null,
"airbaltic.com/banners": null,
"airguns.net/advertisement_images": null,
"airguns.net/classifieds/ad_images": null,
"airplaydirect.com/openx/www/images": null,
"ajmadison.com/images/adverts": null,
"al.com/static/common/js/ads/ads.js": null,
"albumartexchange.com/gallery/images/public/ad": null,
"alluc.ee/js/advertisement.js": null,
"alphabaseinc.com/images/display_adz": null,
"alusa.org/store/modules/blockadvertising": null,
"amctv.com/commons/advertisement/js/AdFrame.js": null,
"amwa.net/sites/default/files/styles/promotion_image/public/promotions": null,
"ananzi.co.za/ads": null,
"andomediagroup.com/crossdomain.xml": null,
"annfammed.org/adsystem": null,
"apmex.com/resources/ads": null,
"apwg.org/images/sponsors": null,
"architecturaldigest.com/etc/designs/ad/images/shell/ad-sprite.png": null,
"area51.stackexchange.com/ads": null,
"arthurbrokerage.com/Websites/arthur/templates/overture": null,
"arti-mediagroup.com/crossdomain.xml": null,
"arti-mediagroup.com/flowplayer/amta_plugin.swf": null,
"asiasold.com/assets/home/openx": null,
"assiniboine.mb.ca/files/intrasite_ads": null,
"asterisk.org/sites/asterisk/files/mce_files/graphics/ads/ad-training.png": null,
"athena365.com/web/components/ads/rma.html": null,
"auctionzip.com/cgi-bin/showimage.cgi": null,
"autogespot.info/upload/ads": null,
"aviationclassifieds.com/adimg": null,
"aviationexplorer.com/airline_aviation_ads": null,
"bafta.org/static/site/javascript/banners.js": null,
"bahtsold.com/assets/home/openx/Thailand": null,
"bahtsold.com/assets/images/ads/no_img_main.png": null,
"banmancounselling.com/wp-content/themes/banman": null,
"banner4five.com/banners": null,
"bannerfans.com/banners": null,
"banners.goldbroker.com/widget": null,
"beatthebrochure.com/js/jquery.popunder.js": null,
"bebusiness.eu/js/adview.js": null,
"betar.gov.bd/wp-content/plugins/useful-banner-manager": null,
"betar.gov.bd/wp-content/uploads/useful_banner_manager_banners": null,
"bigfishaudio.com/banners": null,
"bikeexchange.com.au/adverts": null,
"blastro.com/pl_ads.php": null,
"bloomberg.com/rapi/ads/js_config.js": null,
"bluetooth.com/banners": null,
"bonappetit.com/ams/page-ads.js": null,
"boston.com/images/ads/yourtown_social_widget": null,
"boxedlynch.com/advertising-gallery.html": null,
"britannica.com/resources/images/shared/ad-loading.gif": null,
"brocraft.net/js/banners.js": null,
"bsvideos.com/json/ad.php": null,
"btrll.com/crossdomain.xml": null,
"burfordadvertising.com/advertising": null,
"business-supply.com/images/adrotator": null,
"butlereagle.com/static/ads": null,
"buy.com/buy_assets/addeals": null,
"buyandsell.ie/ads": null,
"buyandsell.ie/images/ads": null,
"buyforlessok.com/advertising": null,
"buyselltrade.ca/adimages": null,
"bworldonline.com/adserver": null,
"cache.nymag.com/scripts/ad_manager.js": null,
"calgarysun.com/assets/js/dfp.js": null,
"cameralabs.com/PG_library/Regional/US/Love_a_Coffee_120x240.jpg": null,
"candystand.com/assets/images/ads": null,
"caranddriver.com/assets/js/ads/ads-combined.min.js": null,
"cctv.com/js/cntv_Advertise.js": null,
"cdn.complexmedianetwork.com/cdn/agenda.complex.com/js/jquery.writecapture.js": null,
"cdn.complexmedianetwork.com/cdn/agenda.complex.com/js/jwplayerl.js": null,
"cdn.complexmedianetwork.com/cdn/agenda.complex.com/js/swfobject.js": null,
"cdn.complexmedianetwork.com/cdn/agenda.complex.com/js/writecapture.js": null,
"cdn.pch.com/spectrummedia/spectrum/adunit": null,
"cdn.travidia.com/fsi-page": null,
"cdn.travidia.com/rop-ad": null,
"cdn.travidia.com/rop-sub": null,
"cerebral.s4.bizhat.com/banners": null,
"channel4.com/media/scripts/oasconfig/siteads.js": null,
"checkm8.com/crossdomain.xml": null,
"chemistwarehouse.com.au/images/AdImages": null,
"chicavenue.com.au/assets/ads": null,
"christianhouseshare.com.au/images/publish_ad1.jpg": null,
"cio.com/www/js/ads/gpt_includes.js": null,
"cleveland.com/static/common/js/ads/ads.js": null,
"club777.com/banners": null,
"clustrmaps.com/images/clustrmaps-back-soon.jpg": null,
"collective-media.net/crossdomain.xml": null,
"colorado.gov/airquality/psi/adv.png": null,
"commarts.com/Images/missinganissue_ad.gif": null,
"constructalia.com/banners": null,
"contactmusic.com/advertpro/servlet/view/dynamic": null,
"content.hallmark.com/scripts/ecards/adspot.js": null,
"corporatehousingbyowner.com/js/ad-gallery.js": null,
"cosmopolitan.com/ams/page-ads.js": null,
"countryliving.com/ams/page-ads.js": null,
"cricbuzz.com/includes/ads/images/wct20": null,
"cricbuzz.com/includes/ads/schedule": null,
"csoonline.com/js/doubleclick_ads.js": null,
"cvs.com/webcontent/images/weeklyad/adcontent": null,
"cyberpower.advizia.com/CyberPower/adv.asp": null,
"d3con.org/data1": null,
"data.panachetech.com/crossdomain.xml": null,
"davescomputertips.com/images/ads/paypal.png": null,
"dc.tremormedia.com/crossdomain.xml": null,
"dealerimg.com/Ads": null,
"deliciousdigital.com/data/our-work/advertising": null,
"deviantart.net/minish/advertising/downloadad_splash_close.png": null,
"digiads.com.au/css/24032006/adstyle.css": null,
"digiads.com.au/images/shared/misc/ad-disclaimer.gif": null,
"digsby.com/affiliate/banners": null,
"directwonen.nl/adverts": null,
"disney.com.au/global/swf/banner300x250.swf": null,
"disneyphotopass.com/adimages": null,
"disruptorbeam.com/assets/uploaded/ads": null,
"dolphinimaging.com/banners.js": null,
"dolphinimaging.com/banners": null,
"domandgeri.com/banners": null,
"doubleclick.net/ad/can/chow": null,
"downvids.net/ads.js": null,
"drunkard.com/banners/drunk-korps-banner.jpg": null,
"drunkard.com/banners/drunkard-gear.jpg": null,
"drunkard.com/banners/modern-drunkard-book.jpg": null,
"earthcam.com/swf/ads5.swf": null,
"earthtv.com/player_tmp/overlayad.js": null,
"economist.com/ads_jobs.json": null,
"edmontonjournal.com/js/adsync/adsynclibrary.js": null,
"edmontonsun.com/assets/js/dfp.js": null,
"egotastic.us.intellitxt.com/intellitxt/front.asp": null,
"emergencymedicalparamedic.com/wp-content/themes/AdSense/style.css": null,
"empireonline.com/images/image_index/300x250": null,
"englishanimes.com/wp-content/themes/englishanimes/js/pop.js": null,
"epicgameads.com/crossdomain.xml": null,
"eplayerhtml5.performgroup.com/js/tsEplayerHtml5/js/Eplayer/js/modules/bannerview/bannerview.main.js": null,
"evanscycles.com/ads": null,
"eventim.de/obj/basic/ad2_obj/layout": null,
"ewallpapers.eu/ads/logo.jpg": null,
"expedia.com/daily/common/msi.asp": null,
"explosm.net/comics": null,
"explosm.net/db/files/comics": null,
"expressclassifiedstt.com/adimg.php": null,
"faceinhole.com/adsense.swf": null,
"feedroom.speedera.net/static.feedroom.com/affiliate": null,
"festina.com/txt/advertising.xml": null,
"firstpost.in/wp-content/uploads/promo/social_icons.png": null,
"flossmanuals.net/site_static/xinha/plugins/DoubleClick": null,
"folklands.com/health/advertise_with_us_files": null,
"forex.com/adx": null,
"forums.realgm.com/banners": null,
"freeads.in/classifieds/common/postad.css": null,
"freeads.in/freead.png": null,
"freeride.co.uk/img/admarket": null,
"fs-freeware.net/images/jdownloads/downloadimages/banner_ads.png": null,
"gcultra.com/js/exit_popup.js": null,
"getgamesgo.com/Banners": null,
"glamour.com/aspen/components/cn-fe-ads/js/cn.dart.js": null,
"glamour.com/aspen/js/dartCall.js": null,
"globaltv.com/js/smdg_ads.js": null,
"gmfreeze.org/site_media//uploads/page_ad_images": null,
"goodyhoo.com/banners": null,
"gotoassist.com/images/ad": null,
"guardian4.com/banners": null,
"gulflive.com/static/common/js/ads/ads.js": null,
"guysen.com/script/ads.js": null,
"hallo.co.uk/advert": null,
"harmonsgrocery.com/ads": null,
"hawaii-scuba.com/ads_styles.css": null,
"healthadnet.adprimemedia.com/vn/vna/data/ad.php": null,
"healthline.com/resources/base/js/responsive-ads.js": null,
"hebdenbridge.co.uk/ads/images/smallads.png": null,
"hellotv.in/livetv/advertisements.xml": null,
"hentai-foundry.com/themes/default/images/buttons/add_comment_icon.png": null,
"hillvue.com/banners": null,
"hipsterhitler.com/hhcomic/wp-content/uploads/2011/10/20_advertisement.jpg": null,
"hipsterhitler.com/wp-content/webcomic": null,
"hologfx.com/banners": null,
"housebeautiful.com/ams/page-ads.js": null,
"howcast.com/flash/assets/ads/liverail.swf": null,
"huffingtonpost.co.uk/_uac/adpage.html": null,
"huffingtonpost.com/_uac/adpage.html": null,
"huffingtonpost.com/images/ads": null,
"identity-us.com/ads/ads.html": null,
"images.dashtickets.co.nz/advertising/featured": null,
"images.forbes.com/video/ads/blank_frame.flv": null,
"images.frys.com/art/ads/images": null,
"images.mmorpg.com/scripts/advertisement.js": null,
"images.nationalgeographic.com/wpf/media-live/graphic": null,
"images.nickjr.com/ads/promo": null,
"imasdk.googleapis.com/flash/sdkloader/adsapi_3.swf": null,
"img.thedailywtf.com/images/ads": null,
"imobie.com/js/anytrans-adv.js": null,
"indiaresults.com/advertisements/submit.png": null,
"infoworld.com/www/js/ads/gpt_includes.js": null,
"inserts2online.com/images/site/viewad.gif": null,
"inspire.net.nz/adverts": null,
"investors.com/Scripts/AdScript.js": null,
"inviziads.com/crossdomain.xml": null,
"iolproperty.co.za/images/ad_banner.png": null,
"island.lk/userfiles/image/danweem/island.gif": null,
"jobs.wa.gov.au/images/advertimages": null,
"jobstreet.com/_ads": null,
"jsstatic.com/_ads": null,
"justin-klein.com/banners": null,
"karolinashumilas.com/img/adv": null,
"kingofgames.net/gads/kingofgames.swf": null,
"kotak.com/banners": null,
"krispykreme.com/content/images/ads": null,
"larazon.es/larazon-theme/js/publicidad.js": null,
"lehighvalleylive.com/static/common/js/ads/ads.js": null,
"lesacasino.com/banners": null,
"limecellular.com/resources/images/adv": null,
"lipsum.com/images/banners": null,
"live365.com/scripts/liveads.js": null,
"lovefilm.com/static/scripts/advertising/dart.overlay.js": null,
"lyngsat-logo.com/icon/flag/az/ad.gif": null,
"mac-sports.com/ads2/508128.swf": null,
"macworld.com/www/js/ads/jquery.lazyload-ad.js": null,
"magicbricks.com/img/adbanner": null,
"mail.yahoo.com/neo/assets/swf/uploader.swf": null,
"manilatimes.net/images/banners/logo-mt.png": null,
"mansioncasino.com/banners": null,
"marciglesias.com/publicidad": null,
"marcokrenn.com/public/images/pages/advertising": null,
"marieclaire.com/ams/page-ads.js": null,
"marines.com/videos/commercials": null,
"masslive.com/static/common/js/ads/ads.js": null,
"mcfc.co.uk/js/core/adtracking.js": null,
"mcpn.us/resources/images/adv": null,
"media.washingtonpost.com/wp-srv/ad/ad_v2.js": null,
"media.washingtonpost.com/wp-srv/ad/photo-ad-config.jsonp": null,
"media.washingtonpost.com/wp-srv/ad/tiffany_manager.js": null,
"medscapestatic.com/pi/scripts/ads/dfp/profads2.js": null,
"meritline.com/banners": null,
"merkatia.com/adimages": null,
"metacafe.com/banner.php": null,
"minecraftservers.org/banners": null,
"miniclip.com/scripts/js.php": null,
"miniclipcdn.com/content/push-ads": null,
"mircscripts.org/advertisements.js": null,
"mlb.com/scripts/dc_ads.js": null,
"mlb.com/shared/components/gameday/v6/js/adproxy.js": null,
"mlive.com/static/common/js/ads/ads.js": null,
"mobilefish.com/scripts/advertisement.js": null,
"moneybookers.com/ads": null,
"moneymailer.com/direct-mail-advertise": null,
"motortrade.me/advert": null,
"mp32u.net/adframe.js": null,
"msi.com/js/topad/topad.css": null,
"msi.com/pic/banner": null,
"msy.com.au/images/ADbanner/eletter": null,
"mudah.my/css/mudah_adview_min.css": null,
"mutualofomaha.com/images/ads": null,
"myadt.com/js-ext/smartbanner": null,
"mycricket.com/openx/offers": null,
"myhouseabroad.com/js/adview.js": null,
"mymemory.co.uk/images/adverts": null,
"myrecipes.com/static/advertising": null,
"nationalbusinessfurniture.com/product/advertising": null,
"nationmultimedia.com/new/js/doubleclick.js": null,
"nature.com/advertising": null,
"nbcmontana.com/html/js/endplay/ads/ad-core.js": null,
"ncregister.com/images/ads": null,
"ncregister.com/images/sized/images/ads": null,
"nedbank.co.za/website/content/home/google_ad_Cut.jpg": null,
"neodrive.co/cam/directrev.js": null,
"networkworld.com/www/js/ads/gpt_includes.js": null,
"newgrounds.com/ads/ad_medals.gif": null,
"newgrounds.com/ads/advertisement.js": null,
"newsarama.com/common/js/advertisements.js": null,
"newyorker.com/wp-content/assets/js/vendors/cn-fe-ads/cn.dart.js": null,
"newzimbabwe.com/banners/350x350": null,
"nextmedia.com/admedia": null,
"nick.com/js/ads.jsp": null,
"nickjr.com/assets/ad-entry": null,
"nickjr.com/global/scripts/overture/sponsored_links_lib.js": null,
"nj.com/static/common/js/ads/ads.js": null,
"nola.com/static/common/js/ads/ads.js": null,
"nsandi.com/files/asset/banner-ads": null,
"oas.absoluteradio.co.uk/realmedia/ads": null,
"oascentral.ibtimes.com/crossdomain.xml": null,
"oascentral.post-gazette.com/realmedia/ads": null,
"oascentral.sumworld.com/crossdomain.xml": null,
"oascentral.surfline.com/crossdomain.xml": null,
"oldergames.com/adlib": null,
"omgili.com/ads.search": null,
"oregonlive.com/static/common/js/ads/ads.js": null,
"ottawasun.com/assets/js/dfp.js": null,
"oxfordlearnersdictionaries.com/external/scripts/doubleclick.js": null,
"ozspeedtest.com/js/pop.js": null,
"pachanyc.com/_images/advertise_submit.gif": null,
"pagesinventory.com/_data/flags/ad.gif": null,
"pandasecurity.com/banners": null,
"pantherssl.com/banners": null,
"partners.thefilter.com/crossdomain.xml": null,
"patient-education.com/banners": null,
"pcworld.com/www/js/ads/jquery.lazyload-ad.js": null,
"pennlive.com/static/common/js/ads/ads.js": null,
"perbang.dk/_pub/advertisement.js": null,
"perezhilton.com/included_ads": null,
"petapixel.com/ads": null,
"petcarerx.com/banners": null,
"phonealchemist.com/api/affiliation": null,
"photo.ekathimerini.com/ads/extra": null,
"photofunia.com/effects": null,
"piercesnorthsidemarket.com/ads": null,
"pioneerfcu.org/assets/images/bannerads/pfcu-system-upgrade-banner-02-180x218.gif": null,
"pitchfork.com/desktop/js/pitchfork/ads/interstitial.js": null,
"planetrecruit.com/ad": null,
"player.goviral-content.com/crossdomain.xml": null,
"player.vioapi.com/ads/flash/vioplayer.swf": null,
"playintraffik.com/advertising": null,
"politico.com/js/magazine/ads.js": null,
"popcap.com/sites/all/modules/popcap/js/popcap_openx.js": null,
"powercolor.com/image/ad": null,
"pressdisplay.com/advertising/showimage.aspx": null,
"procato.com/_pub/advertisement.js": null,
"productioncars.com/pics/menu/ads.gif": null,
"productioncars.com/pics/menu/ads2.gif": null,
"promophot.com/photo/ad": null,
"proprofs.com/quiz-school/js/modernizr_ads.js": null,
"q2servers.com/pop.js": null,
"quit.org.au/images/images/ad": null,
"r2games.com/bannerad": null,
"rad.org.uk/images/adverts": null,
"rainbowdressup.com/ads/adsnewvars.swf": null,
"rapoo.com/images/ad": null,
"rcards.net/wp-content/plugins/useful-banner-manager": null,
"rcards.net/wp-content/uploads/useful_banner_manager_banners": null,
"readwrite.com/files/styles": null,
"realbeauty.com/ams/page-ads.js": null,
"realmedia.channel4.com/realmedia/ads/adstream_sx.ads/channel4.newcu": null,
"realvnc.com/assets/img/ad-bg.jpg": null,
"redbookmag.com/ams/page-ads.js": null,
"remo-xp.com/wp-content/themes/adsense-boqpod/style.css": null,
"replgroup.com/banners": null,
"rosauers.com/locations/ads.html": null,
"rotate.infowars.com/www/delivery/spcjs.php": null,
"russellrooftiles.co.uk/images/rrt_envirotile_home_advert.png": null,
"s.w.org/plugins/ad-inserter": null,
"sabotage-films.com/ads": null,
"sal.co.th/ads": null,
"salfordonline.com/wp-content/plugins/wp_pro_ad_system/templates/js/jquery.jshowoff.min.js": null,
"salon.com/content/plugins/salon-ad-controller/ad-utilities.js": null,
"sascdn.com/crossdomain.xml": null,
"save.ca/img/ads": null,
"scanscout.com/crossdomain.xml": null,
"scrippsnetworks.com/common/adimages/networkads/video_ad_vendor_list/approved_vendors.xml": null,
"scutt.eu/ads": null,
"sdcdn.com/cms/ads/piczo": null,
"sdelkino.com/images/ad": null,
"sec-ads.bridgetrack.com/ads_img": null,
"sekonda.co.uk/advert_images": null,
"serviceexpress.net/js/pop.js": null,
"seventeen.com/ams/page-ads.js": null,
"share.pingdom.com/banners": null,
"shawfloors.com/adx": null,
"siamautologistics.com/ads": null,
"sihanoukvilleonline.com/banners/sologo.png": null,
"silive.com/static/common/js/ads/ads.js": null,
"sillyvamp.com/ads/Donate.png": null,
"site-jump.com/banners": null,
"sjsuspartans.com/ads2": null,
"slotsheaven.com/banners": null,
"slowblog.com/ad.js": null,
"smctemple.wpengine.com/advertising": null,
"softwarepromotions.com/images/google-adwords-professional.gif": null,
"somethingsexyplanet.com/image/adzones": null,
"somewheresouth.net/banner/banner.php": null,
"songza.com/advertising/top": null,
"sonicstate.com/video/hd/hdconfig-geo.cfm": null,
"spectrum.ieee.org/assets/js/masonry-ads-right.min.js": null,
"spendino.de/admanager": null,
"spotxchange.com/crossdomain.xml": null,
"springboardplatform.com/storage/lightbox_code/static/companion_ads.js": null,
"statedesign.com/advertisers": null,
"stclassifieds.sg/images/ads": null,
"stickam.com/css/ver1/asset/sharelayout2col_ad300x250.css": null,
"subscribe.newyorker.com/ams/page-ads.js": null,
"subscribe.teenvogue.com/ams/page-ads.js": null,
"summitracing.com/global/images/bannerads": null,
"supercartoons.net/ad-preroll.html": null,
"superfundo.org/advertisement.js": null,
"support.dlink.com/Scripts/custom/pop.js": null,
"syracuse.com/static/common/js/ads/ads.js": null,
"take40.com/common/javascript/ads.js": null,
"tbns.com.au/shops/images/ads": null,
"telegraphcouk.skimlinks.com/api/telegraph.skimlinks.js": null,
"temple.edu/advertising": null,
"tetrisfriends.com/ads/google_dfp_video_ad.html": null,
"texasstudentmedia.com/advertise": null,
"thedailygreen.com/ams/page-ads.js": null,
"thefrisky.com/js/adspaces.min.js": null,
"theloop.com.au/js/simplejob_ad_content.js": null,
"thenewage.co.za/classifieds/images2/postad.gif": null,
"theory-test.co.uk/css/ads.css": null,
"thetvdb.com/banners": null,
"thomsonlocal.com/js/adsense-min.js": null,
"thrifty.co.uk/bannerads": null,
"tiads.timeinc.net/ads/tgx.js": null,
"timeout.com/images/ads/weather": null,
"tinbuadserv.com/js/integrate/ads_common.js": null,
"tinysubversions.com/clickbait/adjs.json": null,
"tnol.com/adimages/digitaledition": null,
"tooltrucks.com/ads": null,
"tooltrucks.com/banners": null,
"topusajobs.com/banners": null,
"torontosun.com/assets/js/dfp.js": null,
"trade-a-plane.com/AdBox/js/jquery.TAP_AdBox.js": null,
"tradecarview.com/material/housead": null,
"traktorpool.de/scripts/advert": null,
"traumagame.com/trauma_data/ads/ad2.jpg": null,
"travidia.com/ss-page": null,
"tremor.nuggad.net/crossdomain.xml": null,
"trialpay.com/js/advertiser.js": null,
"trifort.org/ads": null,
"tubemogul.com/bootloader/tubemogulflowplayer.swf": null,
"tubemogul.com/crossdomain.xml": null,
"tut.by/uppod/frameid406/ads1": null,
"twofactorauth.org/img": null,
"ucaster.eu/static/scripts/adscript.js": null,
"ultimate-guitar.com/js/ug_ads.js": null,
"ultrabrown.com/images/adheader.jpg": null,
"undsports.com/ads2": null,
"upload.wikimedia.org/wikipedia": null,
"urbanog.com/banners": null,
"usps.com/adserver": null,
"utdallas.edu/maps/images/img": null,
"valueram.com/banners/ads": null,
"vancouversun.com/js/adsync/adsynclibrary.js": null,
"vanityfair.com/ads/js/cn.dart.bun.min.js": null,
"veetle.com/images/common/ads": null,
"video.economist.com/adfinder.jsp": null,
"villermen.com/minecraft/banner/banner.php": null,
"virginradiodubai.com/wp-content/plugins/wp-intern-ads/jquery.internads.js": null,
"vistek.ca/ads": null,
"vitalitymall.co.za/images/adrotator": null,
"vmagazine.com/web/css/ads.css": null,
"wahooads.com/Ads.nsf": null,
"wappalyzer.com/sites/default/files/icons": null,
"washingtonpost.com/wp-adv/advertisers/russianow": null,
"washingtonpost.com/wp-srv/ad/generic_ad.js": null,
"washingtonpost.com/wp-srv/ad/textlink_driver.js": null,
"washingtonpost.com/wp-srv/ad/textlinks.js": null,
"washingtonpost.com/wp-srv/ad/textlinks_config.js": null,
"washingtonpost.com/wp-srv/ad/wp_ad.js": null,
"washingtonpost.com/wp-srv/ad/wpni_generic_ad.js": null,
"wellsfargo.com/img/ads": null,
"whittakersworldwide.com/site-media/advertisements": null,
"williamsauction.com/Resources/images/ads": null,
"winnipegsun.com/assets/js/dfp.js": null,
"wirefly.com/_images/ads": null,
"wisegeek.com/res/contentad": null,
"wortech.ac.uk/publishingimages/adverts": null,
"xbox.com/assets/ad": null,
"yahoo.net/1/adnetwork": null,
"yellowpages.com.mt/Images/Design/Buttons/advert.png": null,
"ykhandler.com/adframe.js": null,
"yokosonews.com/files/cache": null,
"youtube.com/yt/advertise/medias/images": null,
"youtube.com/yt/css/www-advertise.css": null,
"yumenetworks.com/crossdomain.xml": null,
"zap2it.com/ads/newsletter": null,
"zedo.com/crossdomain.xml": null,
"ziehl-abegg.com/images/img_adverts": null,
"10-download.com/ad/adframe.js": null,
"95.211.184.210/js/advertisement.js": null,
"9xbuddy.com/js/ads.js": null,
"ad.leadbolt.net/show_cu.js": null,
"adserver.liverc.com/getBannerVerify.js": null,
"akstream.video/include/advertisement.js": null,
"amk.to/js/adcode.js": null,
"ancensored.com/sites/all/modules/player/images/ad.jpg": null,
"animenewsnetwork.com/javascripts/advertisement.js": null,
"animizer.net/js/adframe.js": null,
"antena3.com/adsxml": null,
"anti-adblock-scripts.googlecode.com/files/adscript.js": null,
"ar51.eu/ad/advertisement.js": null,
"arsopo.com/ads.php": null,
"arto.com/includes/js/adtech.de/script.axd/adframe.js": null,
"atresmedia.com/adsxml": null,
"atresplayer.com/adsxml": null,
"atresplayer.com/static/js/advertisement.js": null,
"auroravid.to/banner.php": null,
"autolikergroup.com/advertisement.js": null,
"bilzonen.dk/scripts/ads.js": null,
"binbox.io/adblock.js": null,
"bitcoinspace.net/freebitcoins/display_ads.js": null,
"boincstats.com/js/adframe.js": null,
"bollywoodshaadis.com/js/ads.js": null,
"boxxod.net/advertisement.js": null,
"bsmotoring.com/adframe.js": null,
"bulletproofserving.com/scripts/ads.js": null,
"captchme.net/js/advertisement-min.js": null,
"captchme.net/js/advertisement.js": null,
"catchvideo.net/adframe.js": null,
"celogeek.com/stylesheets/blogads.css": null,
"cinestrenostv.tv/reproductores/adblock.js": null,
"cityam.com/assets/js/dfp/dfp.js": null,
"codingcrazy.com/demo/adframe.js": null,
"coincheckin.com/js/adframe.js": null,
"computerworld.com/www/js/ads/gpt_includes.js": null,
"cssload.net/js/adframe.js": null,
"dailymaverick.co.za/js/ads/ads.js": null,
"destinypublicevents.com/src/advertisement.js": null,
"dinozap.tv/adimages": null,
"domain.com/ads.html": null,
"dontdrinkandroot.net/js/adframe.js": null,
"ebkimg.com/banners": null,
"elrellano.com/ad/ad.js": null,
"eskago.pl/html/js/ads-banner.js": null,
"eskago.pl/html/js/adv.bbelements.js": null,
"eskago.pl/html/js/advertisement.js": null,
"exoclick.com/wp-content": null,
"exrapidleech.info/templates": null,
"ezcast.tv/static/scripts/adscript.js": null,
"fastcocreate.com/js/advertisement.js": null,
"fastcodesign.com/js/advertisement.js": null,
"fastcoexist.com/js/advertisement.js": null,
"fastcolabs.com/js/advertisement.js": null,
"fastcompany.com/js/advertisement.js": null,
"filecom.net/advertisement.js": null,
"fileice.net/js/advertisement.js": null,
"flvto.biz/scripts/ads.js": null,
"fm.tuba.pl/tuba3/_js/advert.js": null,
"freebtc.click/display_ads.js": null,
"freegamehosting.nl/advertisement.js": null,
"freegamehosting.nl/js/advertisement.js": null,
"freesportsbet.com/js/advertisement.js": null,
"funniermoments.com/adframe.js": null,
"gallery.aethereality.net/advertisement.js": null,
"gamereactor.net/advertisement.js": null,
"gamersconnexion.com/js/advert.js": null,
"games.latimes.com/Scripts/advert.js": null,
"gameshark.com/images/ads": null,
"gamespot.com/js/ads.js": null,
"gdataonline.com/exp/textad.js": null,
"genvideos.org/js/showads.js": null,
"getdebrid.com/advertisement.js": null,
"go4up.com/advertisement.js": null,
"gofirstrow.eu/advertisement.js": null,
"gorillavid.in/script/ad.js": null,
"hackers.co.id/adframe/adframe.js": null,
"hackintosh.zone/adblock/advertisement.js": null,
"hardware.no/ads": null,
"harvardgenerator.com/js/ads.js": null,
"hdfree.tv/live/ad.php": null,
"hqpdb.com/ads/banner.jpg": null,
"ibtimes.co.uk/js/ads.js": null,
"iconizer.net/js/adframe.js": null,
"iguide.to/js/advertisement.js": null,
"imageontime.com/ads/banner.jpg": null,
"imagepearl.com/asset/javascript/ads.js": null,
"imgclick.net/jss/show_ads.js": null,
"imgleech.com/ads/banner.jpg": null,
"imgsure.com/ads/banner.jpg": null,
"imgve.com/pop.js": null,
"incredibox.com/js/advertisement.js": null,
"inskinmedia.com/crossdomain.xml": null,
"investigationdiscovery.com/shared/ad-enablers": null,
"ipneighbour.com/ads.js": null,
"iriptv.com/player/ads.js": null,
"jevvi.es/adblock": null,
"jkanime.net/assets/js/advertisement.js": null,
"jpost.com/JavaScript/ads.js": null,
"kbb.com/js/advert.js": null,
"kdliker.com/js/advert.js": null,
"koparos.info/ads.php": null,
"lapurno.info/ads.php": null,
"lasexta.com/adsxml": null,
"lcpdfr.com/adblock.js": null,
"leaguesecretary.com/advertisement.js": null,
"liberallogic101.com/show_ads.js": null,
"lilfile.com/js/advertise-2.js": null,
"lilfile.com/js/advertise.js": null,
"liquidcompass.net/js/advertisement.js": null,
"litecoin-faucet.tk/advertisement.js": null,
"litecoiner.net/advertisement.js": null,
"lpg-forum.pl/advertise.js": null,
"macobserver.com/js/adlink.js": null,
"makemehost.com/js/ads.js": null,
"mamahd.com/advertisement.js": null,
"manga-news.com/js/advert.js": null,
"mangahost.com/ads.js": null,
"marketmilitia.org/advertisement.js": null,
"megadown.us/advertisement.js": null,
"megafiletube.xyz/js/adblock.js": null,
"megavideodownloader.com/adframe.js": null,
"megawypas.pl/includes/adframe.js": null,
"mgcash.com/common/adblock.js": null,
"miniclipcdn.com/js/advertisement.js": null,
"mix.dj/jscripts/jquery/mdj_adverts.js": null,
"mma-core.com/Scripts/adscript.js": null,
"mmatko.com/images/ad": null,
"moneyinpjs.com/advertisement.js": null,
"monova.org/js/adframe.js": null,
"monova.unblocked.la/js/adframe.js": null,
"monsoonads.com/crossdomain.xml": null,
"moon-faucet.tk/advertisement.js": null,
"mousebreaker.com/scripts/ads.js": null,
"mrtzcmp3.net/advertisement.js": null,
"mwfiles.net/advertisement.js": null,
"mybannermaker.com/banner.php": null,
"myfineforum.org/advertisement.js": null,
"myfreeforum.org/advertisement.js": null,
"needrom.com/advert1.js": null,
"nextthreedays.com/Include/Javascript/AdFunctions.js": null,
"nosvideo.com/ads.js": null,
"omnipola.com/ads.php": null,
"onrpg.com/advertisement.js": null,
"openrunner.com/js/advertisement.js": null,
"overclock3d.net/js/advert.js": null,
"pandora.com/static/ads": null,
"paste.org/style/adframe.js": null,
"perkuinternete.lt/modules/mod_jpayday/js/advertisement.js": null,
"pipocas.tv/js/advertisement.js": null,
"plantuml.com/adsbygoogle.js": null,
"player.utv.ie/assets/js/adframe.js": null,
"playhd.eu/advertisement.js": null,
"playindiafilms.com/advertisement.js": null,
"playlive.pw/advertisement.js": null,
"pokewatchers.com/ads.js": null,
"postimg.org/js/adframe.js": null,
"preloaders.net/jscripts/adframe.js": null,
"premiumleecher.com/inc/adframe.js": null,
"premiumleecher.com/inc/adsense.js": null,
"primewire.ag/js/advertisement.js": null,
"promptfile.com/js/showads.js": null,
"puromarketing.com/js/advertisement.js": null,
"radar-toulouse.fr/advertisement.js": null,
"ratebeer.com/javascript/advertisement.js": null,
"savevideo.me/images/banner_ads.gif": null,
"sawlive.tv/adscript.js": null,
"scan-manga.com/ads.html": null,
"scan-manga.com/ads/banner.jpg": null,
"scoutingbook.com/js/adsense.js": null,
"senmanga.com/advertisement.js": null,
"sheepskinproxy.com/js/advertisement.js": null,
"shimory.com/js/show_ads.js": null,
"shink.in/js/showads.js": null,
"skidrowcrack.com/advertisement.js": null,
"skylinewebcams.com/player/ad2.swf": null,
"sparkylinux.org/images/ad": null,
"springstreetads.com/scripts/advertising.js": null,
"srnk.co/js/ads.js": null,
"stackexchange.com/affiliate": null,
"stockmarketwire.com/js/advertisement.js": null,
"streamin.to/adblock/advert.js": null,
"streamlive.to/js/ads.js": null,
"streamplay.to/js/ads.js": null,
"superfilm.pl/advertisement.js": null,
"talksport.com/sites/default/files/ben/advert.js": null,
"team-vitality.fr/assets/images/advert.png": null,
"teknogods.com/advert.js": null,
"telemetryverification.net/crossdomain.xml": null,
"thecountrycaller.com/showads.php": null,
"thenextweb.com/wp-content/advertisement.js": null,
"thevideos.tv/js/ads.js": null,
"tpmrpg.net/adframe.js": null,
"twitch.tv/ads/ads.js": null,
"ucoz.com/ads/banner.jpg": null,
"uktv.co.uk/static/js/ads.js": null,
"universityherald.com/common/js/common/ads.js": null,
"up-flow.org/advertisement.js": null,
"uploadrocket.net/ads.js": null,
"uploadrocket.net/advertising/ads.js": null,
"upshare.org/advertisement.js": null,
"urdupoint.com/js/advertisement.js": null,
"usaupload.net/ads.js": null,
"uvnc.com/advertisement.js": null,
"vdrive.to/js/pop.js": null,
"veedi.com/player/js/ads/advert.js": null,
"vercanalestv.com/adblock.js": null,
"verticalscope.com/js/advert.js": null,
"vidlox.tv/pop.js": null,
"vietvbb.vn/up/clientscript/google_ads.js": null,
"vipbox.tv/js/ads.js": null,
"vipleague.se/js/ads.js": null,
"wallpaperbeta.com/js/adsbygoogle.js": null,
"wallpapermania.eu/assets/js/advertisement.js": null,
"wallpapershacker.com/js/adsbygoogle.js": null,
"wanamlite.com/images/ad": null,
"watchcartoononline.com/advertisement.js": null,
"webfirstrow.eu/advertisement.js": null,
"webtv.rs/media/blic/advertisement.jpg": null,
"welovebtc.com/show_ads.js": null,
"whosampled.com/ads.js": null,
"windows7themes.net/wp-content/advert.js": null,
"world-of-hentai.to/advertisement.js": null,
"xmovies8.org/js/showads.js": null,
"xooimg.com/magesy/js-cdn/adblock.js": null,
"yellowbridge.com/ad/show_ads.js": null,
"youwatch.org/js/show_ads.js": null,
"www.google.com/adsense/search/async-ads.js": null,
"ad.e-kolay.net/ad.js": null,
"ad.e-kolay.net/Medyanet.js": null,
"ad.e-kolay.net/mnetorfad.js": null,
"ad.nl/ad/css": null,
"ads.hosting.vcmedia.vn/crossdomain.xml": null,
"ads.hosting.vcmedia.vn/jinfo.ashx": null,
"ads.peteava.ro/crossdomain.xml": null,
"ads.postimees.ee/crossdomain.xml": null,
"ads.telecinco.es/crossdomain.xml": null,
"ads.us.e-planning.net/crossdomain.xml": null,
"advertising.sun-sentinel.com/el-sentinel/elsentinel-landing-page.gif": null,
"alio.lt/public/advertisement/texttoimage.html": null,
"applevideo.edgesuite.net/admedia": null,
"atresplayer.com/static/imgs/no_ads.jpg": null,
"bancodevenezuela.com/imagenes/publicidad": null,
"biancolavoro.euspert.com/js/ad.js": null,
"bmwoglasnik.si/images/ads": null,
"bn.uol.com.br/html.ng": null,
"bolha.com/css/ad.css": null,
"cadena100.es/static/plugins/vjs/js/videojs.ads.js": null,
"custojusto.pt/user/myads": null,
"eenadu.net/ads.js": null,
"emediate.eu/crossdomain.xml": null,
"emediate.se/crossdomain.xml": null,
"ensonhaber.com/player/ads.js": null,
"epaper.andhrajyothy.com/js/newads.js": null,
"fajerwerkilider.pl/environment/cache/images/300_250_productGfx_": null,
"felcia.co.uk/css/ads-common.css": null,
"felcia.co.uk/css/advert-view.css": null,
"felcia.co.uk/js/ads_common.js": null,
"filmon.com/ad/affiliateimages/banner-250x350.png": null,
"folha.uol.com.br/paywall/js/1/publicidade.ads.js": null,
"fotolog.com/styles/flags/ad.gif": null,
"freeride.se/img/admarket": null,
"happymtb.org/annonser": null,
"hizlial.com/banners": null,
"hry.cz/ad/adcode.js": null,
"jesper.nu/javascript/libs/videoads.js": null,
"jyllands-posten.dk/js/ads.js": null,
"krotoszyn.pl/uploads/pub/ads_files": null,
"lrytas.lt/ads/video_feed.js": null,
"megastar.fm/static/plugins/vjs/js/videojs.ads.js": null,
"mmgastro.pl/img/reklama": null,
"mmgastro.pl/js/reklama": null,
"moviezone.cz//moviezone/reklama": null,
"niedziela.nl/adverts": null,
"nordjyske.dk/scripts/ads/StoryAds.js": null,
"openimage.interpark.com/_nip_ui/category_shopping/shopping_morningcoffee/leftbanner/null.jpg": null,
"openx.zomoto.nl/live/www/delivery/fl.js": null,
"peoplegreece.com/assets/js/adtech_res.js": null,
"ptchan.net/imagens/banner.php": null,
"quebarato.com.br/css/static/ad_detail.css": null,
"quebarato.com.br/css/static/ad_search.css": null,
"r7.com/js/ads.js": null,
"rocking.gr/js/jquery.dfp.min.js": null,
"rtl.lu/ipljs/adtech_async.js": null,
"run.admost.com/adx/js/admost.js": null,
"s-nk.pl/img/ads/icons_pack": null,
"sigmalive.com/assets/js/jquery.openxtag.js": null,
"smartadserver.com/crossdomain.xml": null,
"sms.cz/bannery": null,
"soov.ee/js/newad.js": null,
"submarino.com.br/openx/www/delivery": null,
"thewineplace.es/wp-content/plugins/m-wp-popup/js/wpp-popup-frontend.js": null,
"tvp.pl/files/tvplayer": null,
"videonuz.ensonhaber.com/player/hdflvplayer/xml/ads.xml": null,
"vinden.se/ads": null,
"yapo.cl/js/viewad.js": null,
"ziarelive.ro/assets/js/advertisement.js": null,
"support.google.com/adsense": null,
"www.google.com/doubleclick/images/favicon.ico": null,
"advertise.bingads.microsoft.com/wwimages/search/global": null,
"integralplatform.com/static/js/Advertiser": null,
"adservice.com/wp-content/themes/adservice": null,
"adservicemedia.dk/images": null,
"cinemanow.com/images/banners/300x250": null,
"cubeecraft.com/images/home/features/300x250": null,
"disney.com.au/global/swf/banner160x600.swf": null,
"freetvhub.com/ad1_300x250.html": null,
"heathceramics.com/media/300x250": null,
"komikslandia.pl/environment/cache/images/300_250_": null,
"msecnd.net/socialfactoryimagesresized/mediaspotlight/2/300x250": null,
"mxtoolbox.com/Public/images/banners/Mx-Pro-160x600.jpg": null,
"nc-myus.com/images/pub/www/uploads/merchant-logos": null,
"union.edu/media/galleryPics/400x250": null,
"worlds-luxury-guide.com/sites/default/files/rectangle-300x250-newsletter.jpg": null,
"zorza-polarna.pl/environment/cache/images/300_250_": null,
"ads.affiliatecruise.com/redirect.aspx": null,
"ads.casumoaffiliates.com/redirect.aspx": null,
"ads.eurogrand.com/redirect.aspx": null,
"ads.honestpartners.com/redirect.aspx": null,
"ads.kabooaffiliates.com/redirect.aspx": null,
"ads.thrillsaffiliates.com/redirect.aspx": null,
"ads.toplayaffiliates.com/redirect.aspx": null,
"g.doubleclick.net/ads/preferences": null,
"youtube.com/ads/preferences": null,
"ad.thisav.com/player/config.xml": null,
"ad.thisav.com/player/jw.swf": null,
"boyzshop.com/affimages": null,
"boyzshop.com/images/affbanners": null,
"burningcamel.com/ads/banner.jpg": null,
"fucktube.com/work/videoad.php": null,
"gaynetwork.co.uk/Images/ads/bg": null,
"hdzog.com/js/advertising.js": null,
"iafd.com/graphics/headshots/thumbs/th_iafd_ad.gif": null,
"manhuntshop.com/affimages": null,
"manhuntshop.com/images/affbanners": null,
"nonktube.com/img/adyea.jpg": null,
"sextoyfun.com/admin/aff_files/BannerManager": null,
"sextoyfun.com/control/aff_banners": null,
"skimtube.com/advertisements.php": null,
"starcelebs.com/logos/logo10.jpg": null,
"store.adam4adam.com/affimages": null,
"store.adam4adam.com/images/affbanners": null,
"sundaysportclassifieds.co.uk/ads": null,
"xhcdn.com/images/flag/AD.gif": null,
"xxxporntalk.com/images/xxxpt-chrome.jpg": null,
"google.com/recaptcha": null,
"phncdn.com//js/popUnder/exclusions-min.js": null,
"pornhub.com/www-static/images": null,
"pornhubcommunity.com/cdn_files/images": null,
"redtube.com/_thumbs": null,
"redtube.com/media/avatars": null,
"tube8.com/favicon.ico": null,
"tube8.com/images": null,
"upload.pornhub.com/temp/images": null,
"youporn.com/bundles": null,
"youporngay.com/bundles": null,
"ad.thisav.com/player/swfobject.js": null,
"cntrafficpro.com/scripts/advertisement.js": null,
"desihoes.com/advertisement.js": null,
"exoclick.com/ad_track.js": null,
"exoclick.com/invideo.js": null,
"hclips.com/js/advertising.js": null,
"hentaimoe.com/js/advertisement.js": null,
"imgadult.com/js/advertisement.js": null,
"jporn4u.com/js/ads.js": null,
"n4mo.org/advertisement.js": null,
"noracam.com/js/ads.js": null,
"ooporn.com/ads.js": null,
"phncdn.com/js/advertisement.js": null,
"porndoo.com/showads.js": null,
"pornfun.com/js/ads.js": null,
"sexix.net/adframe.js": null,
"sexvidx.tv/js/eroex.js": null,
"sexwebvideo.com/js/ads.js": null,
"tube8.com/js/advertisement.js": null,
"voyeurperversion.com/inc/showads.js": null,
"watchingmysistergoblack.com/pop.js": null,
"xibitnet.com/check/advertisement.js": null,
"xibitnet.com/check/advertisements.js": null,
"ads.b10f.jp/flv": null,
"imagebam.com/image": null,
"aliyun.com/nocaptcha/analyze.jsonp": null,
"analytics.atomiconline.com/services/jquery.js": null,
"anthem.com/includes/foresee/foresee-trigger.js": null,
"atdmt.com/ds/yusptsprtspr": null,
"atpworldtour.com/assets/js/util/googleAnalytics.js": null,
"att.com/webtrends/scripts/dcs_tag.js": null,
"autoscout24.net/unifiedtracking/ivw.js": null,
"barclays.co.uk/touchclarity/mbox.js": null,
"behanceserved.com/stats/stats.js": null,
"benswann.com/decor/javascript/magnify_stats.js": null,
"bettycrocker.com/Shared/Javascript/ntpagetag.js": null,
"bettycrocker.com/Shared/Javascript/UnicaTag.js": null,
"bitgo.com/vendor/googleanalytics/angular-ga.min.js": null,
"bolha.com/clicktracker": null,
"bootcamp.mit.edu/js/angulartics-google-analytics.min.js": null,
"borderfree.com/assets/utils/google-analytics.js": null,
"britishairways.com/cms/global/scripts/applications/tracking/visualsciences.js": null,
"canada.com/js/ooyala/comscore.js": null,
"care2.com/assets/scripts/cookies/care2/NitroCookies.js": null,
"cio.com/js/demandbase.js": null,
"cisco.com/web/fw/lib/ntpagetag.js": null,
"cisco.com/web/fw/m/ntpagetag.min.js": null,
"citiretailservices.citibankonline.com/USCRSF/USCRSGBL/js/AppMeasurement.js": null,
"collegeboard.org/webanalytics": null,
"contentdef.com/assets/common/js/google-analytics.js": null,
"csoonline.com/js/demandbase.js": null,
"dailyfinance.com/traffic": null,
"dailymail.co.uk/brightcove/tracking/ted3.js": null,
"debenhams.com/foresee/foresee-trigger.js": null,
"diablo3.com/assets/js/jquery.google-analytics.js": null,
"dopemagazine.com/wp-content/plugins/masterslider/public/assets/css/blank.gif": null,
"ecostream.tv/js/ecos.js": null,
"egencia.com/pubspec/scripts/include/omnitureAnalytics.js": null,
"egencia.com/pubspec/scripts/include/siteanalytics_include.js": null,
"epixhd.com/styleassets/js/google-analytics.js": null,
"expedia.com/static/default/default/scripts/siteAnalytics.js": null,
"expedia.com/static/default/default/scripts/TealeafSDK.js": null,
"flagshipmerchantservices.com/clickpathmedia.js": null,
"freefilefillableforms.com/js/lib/irs/fingerprint.js": null,
"games.pch.com/js/analytics.js": null,
"gardenista.com/media/js/libs/ga_social_tracking.js": null,
"go.com/stat/dolwebanalytics.js": null,
"go.com/stat/flash/analyticreportingas3.swf": null,
"goldbet.com/Scripts/googleAnalytics.js": null,
"goldmansachs.com/a/pg/js/prod/gs-analytics-init.js": null,
"grapeshot.co.uk/image-resize": null,
"grapeshot.co.uk/sare-api": null,
"graphracer.com/js/libs/heatmap.js": null,
"halowars.com/stats/images/Buttons/MapStats.jpg": null,
"harvard.edu/scripts/ga_social_tracking.js": null,
"haystax.com/components/leaflet/heatmap.js": null,
"hhgregg.com/wcsstore/MadisonsStorefrontAssetStore/javascript/Analytics/AnalyticsTagDataObject.js": null,
"homedepot.com/static/scripts/resxclsa.js": null,
"hostlogr.com/etc/geo.php": null,
"kentucky.com/mistats/finalizestats.js": null,
"latimes.com/hive/javascripts/loggingService.js": null,
"leretourdelautruche.com/map/nuke/heatmap.js": null,
"lininteractive.com/chartbeat": null,
"lipmonthly.com/js/angulartics-google-analytics/dist/angulartics-ga.min.js": null,
"live.indiatimes.com/trackjs.cms": null,
"lloydstsb.com/it/xslt/touchclarity/omtr_tc.js": null,
"logmein.com/scripts/Tracking/Tracking.js": null,
"mec.ca/media/javascript/resxclsx.js": null,
"medicare.gov/SharedResources/widgets/foresee/foresee-trigger.js": null,
"metrics.ctvdigital.net/global/CtvAd.js": null,
"metrics.nissanusa.com/b/ss/nissanusacom": null,
"microsoft.com/click/services/RioTracking2.js": null,
"mightyspring.com/static/js/beacon.js": null,
"milb.com/shared/scripts/bam.tracking.js": null,
"mlb.com/shared/scripts/bam.tracking.js": null,
"motorolasolutions.com/wrs/b2bsdc.js": null,
"munchkin.marketo.net/munchkin.js": null,
"musicvideogenome.com/javascripts/stats.js": null,
"nasa.gov/js/libraries/angulartics/angulartics-google-analytics.js": null,
"nationalgeographic.com/assets/scripts/utils/event-tracking.js": null,
"necn.com/includes/AppMeasurement.js": null,
"nerdwallet.com/lib/dist/analytics.min.js": null,
"netinsight.travelers.com/scripts/ntpagetaghttps.js": null,
"novell.com/common/util/demandbase_data.php": null,
"nymag.com/decor/javascript/magnify_stats.js": null,
"ooyala.com/crossdomain.xml": null,
"palerra.net/apprity/api/analytics": null,
"patrick-wied.at/static/heatmapjs/src/heatmap.js": null,
"pillsbury.com/Shared/StarterKit/Javascript/ntpagetag.js": null,
"pillsbury.com/Shared/StarterKit/Javascript/UnicaTag.js": null,
"piwik.pro/images": null,
"pixel.facebook.com/ajax/gigaboxx/endpoint/UpdateLastSeenTime.php": null,
"playtheend.com/api/v1/players/heatmap.json": null,
"polycom.com/polycomservice/js/unica/ntpagetag.js": null,
"propelmedia.com/resources/images/load.gif": null,
"ps.w.org/google-analytics-dashboard-for-wp/assets": null,
"pshared.5min.com/Scripts/OnePlayer/Loggers/ComScore.StreamSense.js": null,
"pshared.5min.com/Scripts/OnePlayer/Loggers/ComScore.Viewability.js": null,
"push2check.com/stats.php": null,
"randomhouse.com/book/css/certona.css": null,
"rawstory.com/decor/javascript/magnify_stats.js": null,
"redditenhancementsuite.com/js/jquery.google-analytics.js": null,
"redfin.com/stingray/clicktracker.jsp": null,
"remodelista.com/media/js/libs/ga_social_tracking.js": null,
"rockingsoccer.com/js/match_stats.js": null,
"samepage.io/assets/lib/google-analytics/GoogleAnalytics.js": null,
"scorecardresearch.com/c2/plugins/streamsense_plugin_html5.js": null,
"scorecardresearch.com/c2/plugins/streamsense_plugin_theplatform.js": null,
"snapchat.com/static/js/google-analytics.js": null,
"sportsgrid.com/decor/javascript/magnify_stats.js": null,
"star-telegram.com/mistats/sites/dfw/startelegram.js": null,
"statcounter.com/js/fusioncharts.js": null,
"statcounter.com/msline.swf": null,
"statefillableforms.com/js/lib/irs/fingerprint.js": null,
"static.chartbeat.com/crossdomain.xml": null,
"stats.jtvnw.net/crossdomain.xml": null,
"support.thesslstore.com/visitor/index.php": null,
"tablespoon.com/library/js/TBSP_ntpagetag.js": null,
"ted.com/decor/javascript/magnify_stats.js": null,
"teenvogue.com/js/eventTracker.js": null,
"telegraph.co.uk/template/ver1-0/js/webtrends/live/wtid.js": null,
"texasroadhouse.com/common/javascript/google-analytics.js": null,
"thestreet-static.com/video/js/kGoogleAnalytics.js": null,
"thetenthwatch.com/js/tracking.js": null,
"tracking.unrealengine.com/tracking.js": null,
"ultimedia.com/js/common/jquery.gatracker.js": null,
"unity3d.com/profiles/unity3d/themes/unity/images/services/analytics": null,
"utm.arc.nasa.gov/common/css": null,
"utm.arc.nasa.gov/common/js/common.js": null,
"utm.arc.nasa.gov/common/js/hideEmail.js": null,
"utm.arc.nasa.gov/common/js/nav.js": null,
"utm.arc.nasa.gov/common/js/swap.js": null,
"utm.arc.nasa.gov/images": null,
"uverseonline.att.net/report/click_tracking_nes.json": null,
"vizio.com/resources/js/vizio-module-tracking-google-analytics.js": null,
"vulture.com/decor/javascript/magnify_stats.js": null,
"walmart.com/__ssobj/core.js": null,
"wbshop.com/fcgi-bin/iipsrv.fcgi": null,
"websimages.com/JS/Tracker.js": null,
"westjet.com/js/webstats.js": null,
"whirlpool.com/foresee/foresee-trigger.js": null,
"wwe.com/sites/all/modules/wwe/wwe_analytics/s_wwe_code.js": null,
"youtube.com/api/analytics": null,
"zappos.com/js/trackingPixel/mercentTracker.js": null,
"zylom.com/images/site/zylom/scripts/google-analytics.js": null,
"aplus.com/p.gif": null,
"fandango.com/b/ss": null,
"kaspersky.co.uk/b/ss": null,
"metrics.ancestry.com/b/ss": null,
"metrics.brooksbrothers.com/b/ss": null,
"metrics.consumerreports.org/b/ss": null,
"metrics.nationwide.co.uk/b/ss": null,
"metrics.target.com/b/ss": null,
"metrics.thetrainline.com/b/ss": null,
"metrics.ticketmaster.com/b/ss": null,
"smetrics.target.com/b/ss": null,
"smetrics.ticketmaster.com/b/ss": null,
"smetrics.walmartmoneycard.com/b/ss": null,
"stat.safeway.com/b/ss": null };
var good_da_hostpath_exact_flag = 1105 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 434 rules:
var good_da_hostpath_regex = `thebarchive.com/foolfuuka/foolz/*/board.js
thebarchive.com/foolfuuka/foolz/*/bootstrap.min.js
thebarchive.com/foolfuuka/foolz/*/plugins.js
gorillavid.in^*/jsSelect.js
gorillavid.in^*/jwplayer.js
speedtest.net/javascript/jquery-*.min.js
speedtest.net/javascript/jquery.ui*.js
motherless.com/scripts/jquery-*.min.js
motherless.com/scripts/jquery.*.js
247realmedia.com^*/farecomp/
24ur.com/adserver/adall.
24ur.com/static/*/banners.js
a.giantrealm.com/assets/vau/grplayer*.swf
addictinggames.com^*/mtvi_ads_reporting.js
adf.ly/images/ad*.png
ads.foxnews.com/api/*-slideshow-data.js
ads.globo.com^*/globovideo/player/
ads.yimg.com/ev/eu/any/vint/videointerstitial*.js
ads.yimg.com^*/search/b/syc_logo_2.gif
ads.yimg.com^*videoadmodule*.swf
akamaihd.net/hads-*.mp4
aone-soft.com/style/images/ad*.jpg
apple.com^*/includes/ads
apple.com^*/video-ad.html
att.com/images/*/admanager/
autotrader.co.uk/static/*/images/adv/icons.png
bonappetit.com^*/cn.dart.js
box10.com/advertising/*-preroll.swf
britishairways.com/cms/global/styles/*/openx.css
bthomehub.home/images/adv_
burbankleader.com/hive/images/adv_
canadianlisted.com/css/*/ad/index.css
cbsistatic.com^*/sticky-ads.js
cdn.turner.com^*/video/336x280_ad.gif
cdn77.org/static/js/advertisement*.js
chase.com^*/adserving/
classistatic.com^*/banner-ads/
coastlinepilot.com/hive/images/adv_
comsec.com.au^*/homepage_banner_ad.gif
crazygamenerd.web.fc2.com^*/ads.png
csair.com/*/adpic.js
ctv.ca/players/mediaplayer/*/AdManager.js^
cyberpower.advizia.com^*/scripts/adv.js
dailyhiit.com/sites/*/ad-images/
dailymail.co.uk^*/googleads--.js
dailypilot.com/hive/images/adv_
delish.com/cm/shared/scripts/refreshads-*.js
developer.apple.com/app-store/search-ads/images/*-ad
dolidoli.com/images/ads-
dragon-mania-legends-wiki.mobga.me^*_advertisement.
dragon-mania-legends-wiki.mobga.me^*_Advertisement_
drupal.org^*/revealads.png
earthtechling.com^*/imasters-wp-adserver-styles.css
economist.com.na^*/banners/cartoon_
eduspec.science.ru.nl^*-images/ad-
esi.tech.ccp.is^*/affiliation/
expedia.com/minify/ads-min-*.js
farecompare.com^*/farecomp/
flysaa.com^*/jquery.adserver.js
freeviewnz.tv^*/uploads/ads/
garmin.com^*/Sponsors.js
glendalenewspress.com/hive/images/adv_
guim.co.uk^*/styles/wide/google-ads.css
gumtree.com^*/postAd.js
hbindependent.com/hive/images/adv_
homedepot.com^*/thdGoogleAdSense.js
hotnewhiphop.com/web_root/images/ads/banner-*.png
housebeautiful.com/cm/shared/scripts/refreshads-*.js
hulu.com/published/*.flv
hulu.com/published/*.mp4
i.cdn.turner.com^*/adserviceadapter.swf
icefilms.info/jquery.lazyload-ad-*-min.js
iframe.ivillage.com/iframe_render
ikea.com^*/img/ad_
ikea.com^*/img/ads/
itv.com^*.adserver.js
itv.com^*/tvshows_adcall_08.js
itweb.co.za/banners/en-cdt*.gif
jobsearch.careerone.com.au^*/bannerad.asmx/
joyhubs.com/View/*/js/pop.js
kcna.kp/images/ads_arrow_
kcra.com^*/adpositionsizein-min.js
ksl.com/resources/classifieds/graphics/ad_
l.yimg.com/*/adservice/
lacanadaonline.com/hive/images/adv_
lanacion.com.ar/*/publicidad/
live365.com/web/components/ads/*.html
mail.google.com^*/uploaderapi*.swf
maps.googleapis.com/maps-api-*/adsense.js
maps.gstatic.com/maps-api-*/adsense.js
marcs.com^*/AdViewer.js
media.expedia.com/*/ads/
medscape.com/html.ng/*slideshow
metalmusicradio.com^*/banner.php
miller-mccune.com/wp-content/plugins/*/oiopub-direct/images/style/output.css
mobinozer.com^*/gads.js
monster.com/awm/*/ADVERTISING-
msnbcmedia.msn.com^*/sitemanagement/ads/*/blog_printbutton.png
mussil.com/mussilcomfiles/commercials/*.jpg
myhouseabroad.com/*/ads/
news.nate.com/etc/adrectanglebanner
nfl.com^*/ads.js
nflcdn.com/static/*/global/ads.js
nytimes.com/ads/interstitial/skip*.gif
nytimes.com/adx/images/ads/*_buynow_btn_53x18.gif
nytimes.com/adx/images/ads/*_premium-crosswords_bg_600x329.gif
oas.absoluteradio.co.uk^*/www.absoluteradio.co.uk/player/
objects.tremormedia.com/embed/swf/admanager*.swf
omgubuntu.co.uk^*/banner.js
onionstatic.com^*/videoads.js
opgevenisgeenoptie.nl^*/favicon_ad6.ico
pbs.org^*/sponsors/flvvideoplayer.swf
pets4homes.co.uk/*/advert.js
pets4homes.co.uk^*/advert.css
plugcomputer.org^*/ad1.jpg
purebilling.com^*/pb.min.js
radiotimes.com/rt-service/resource/jspack
refline.ch^*/advertisement.css
rsvlts.com/wp-content/uploads/*-advertisment-
secondlife.com/assets/*_AD3.jpg
shelleytheatre.co.uk/filmimages/banners/160
smmirror.com^*/getads.php
socialblogsitewebdesign.com^*/advertising_conversion_images/
songza.com/static/*/songza/ads/iframe.js
sonypictures.com^*/admedia/
southwest.com/assets/images/ads/ad_select_flight_
southwest.com^*/homepage/ads/
spotrails.com^*/flowplayeradplayerplugin.swf
springbokradio.com/images/ads-
springbokradio.com/sitebuilder/images/ads-
st.com^*/banners.js
teknikor.com/content/wp-content/themes/*-adv.jpg
theepochtimes.com^*/article-ads.js
thefourthperiod.com/ads/tfplogo_
thomann.de/thumb/*/pics/adv/adv_image_
thunderheadeng.com/wp-content/uploads/*300x250
timeinc.net^*/tii_ads.js
tkcarsites.com/soba/bannersservice
tntexpress.com.au^*/marketing/banners/
topgear.com^*/ads.min.js
traktorpool.de^*/advert.
translate.google.com/translate/static/*-ads/
trustedreviews.com^*/adtech.js
turner.com^*/ads/freewheel/*/AdManager.js
turner.com^*/ads/freewheel/*/admanager.swf
tv-kino.net/wp-content/themes/*/advertisement.js
tvnz.co.nz/*/advertisement.js
twitvid.com/mediaplayer_*.swf
ukbride.co.uk/css/*/adverts.css
usanetwork.com^*/usanetwork_ads.s_code.js
utdallas.edu^*/banner.js
vacationstarter.com/hive/images/adv_
vagazette.com/hive/images/adv_
vid.ag/static/js/adver*.js
video.nbcuni.com^*/ad_engine_extension_nbc.swf
video.nbcuni.com^*/inext_ad_engine/ad_engine_extension.swf
vidtech.cbsinteractive.com/plugins/*_adplugin.swf
vizanime.com/ad/get_ads
vtstage.cbsinteractive.com/plugins/*_adplugin.swf
walmartmoneycard.com^*/shared/ad_rotater.swf
whitepages.com^*/google_adsense.js
widget.slide.com^*/ads/*/preroll.swf
wired.com^*/cn-fe-ads/cn.dart.js
worldstarhiphop.com^*/dj2.swf
wp.com/_static/*/criteo.js
yimg.com^*/java/promotions/js/ad_eo_1.1.js
4fuckr.com^*/adframe.js
4sysops.com^*/adframe.js
ahmedabadmirror.com/*ads.cms
amazonaws.com^*/videoads.js
anisearch.com^*/ads/
bestofmedia.com^*/advertisement.js
bestream.tv/advert*.js
brainyquote.com^*/ad*.js
brassyobedientcotangent.com^*/ads.js
cdn-seekingalpha.com^*/ads.js
coolgames.com^*/ads.js
credio.com/ad
crunchyroll.com^*/ads_enabled_flag.js
decomaniacos.es^*/advertisement.js
designtaxi.com/js/ad*.js
divisionid.com^*/ads.js
drakulastream.tv^*/flash_popunder.js
dressup.com^*/ads.js
dressuppink.com^*/ads.js
dvbtmap.eu^*/ad*.js
eska.pl^*bbelements.js
eu5.org^*/advert.js
exsite.pl^*/advert.js
ffiles.com/images/mmfiles_
findthedata.com/ad
freebitcoin.wmat.pl^*/advertisement.js
gallerynova.se^*/advertisement.js
gamesgames.com^*/advertisement.js
getlinkyoutube.com^*/adframe.js
girlgames.com^*/ads.js
girlsaskguys.com^*/js/ads.
girlsocool.com^*/ads.js
gofirstrow.eu^*/advertisement.js
grouchyaccessoryrockefeller.com^*/ads.js
guygames.com^*/ads.js
hallpass.com^*/ads.js
hdmovie14.net/js/ad*.js
hentai-foundry.com^*/ads.js
hindustantimes.com^*/ads.js
hpfanficarchive.com^*/advertisement.js
intoday.in^*/ads.js
investing.com^*/ads.js
investors.com^*/ads.js
jkanime.net^*/advertisement2.js
juba-get.com^*/advertisement.js
juzupload.com/advert*.js
katsomo.fi^*/advert.js
katsomo.fi^*/advertisement.js
kbb.com^*/ads.js
kotaku.com.au^*/ads.js
lifehacker.com.au^*/ads.js
live2.snopes.com^*/adframe.js
lookr.com^*/advertisement.js
majorleaguegaming.com/live/assets/advertisement-*.js
mangakaka.com^*/advertiser.js
megahd.me^*/advertisement.js
mix.dj^*/advertisement.js
mobinozer.com^*/advert.js
mp3clan.com^*/advertisement.js
mtlblog.com/wp-content/*/advert.js
myiplayer.com/ad*.js
nationalgeographic.com^*/advertising.js
nettavisen.no^*/advertisement.js
onlinevideoconverter.com^*ad*.js
photofacefun.com^*/adblock.js
pleaseletmeadvertise.com/.adcenter.
pleaseletmeadvertise.com^*/ads.js
pubdirecte.com^*/advertisement.js
qrrro.com^*/adhandler/
racedepartment.com^*/advertisement.js
radioio.com^*/adframe.js
rincondelvago.com^*_adsense.js
runners.es^*/advertisement.js
sbs.com.au^*/advertisement.js
securenetsystems.net^*/ads.js
securenetsystems.net^*/adv.js
sepulchralconestogaleftover.com^*/ads.js
share-online.biz^*/ads.js
shipthankrecognizing.info^*/ads.js
showsport-tv.com/adv*.js
siamfishing.com^*/advert.js
sitepoint.com^*/ad-server.js
slacker.com^*/Advertising.js
sounddrain.net^*/advertisement.js
stickgames.com^*/ads.js
techweekeurope.co.uk^*/advertising.js
telegraph.co.uk^*/ads.js
tf2center.com^*/advert.js
thetechpoint.org^*/ads.js
thevideo.me/js/ad*.js
theweatherspace.com^*/advertisement.js
tvpelis.net^*/advertisement2.js
veedi.com^*/ADS.js
vgunetwork.com/public/js/*/advertisement.js
videocelebrities.eu^*/adframe/
virtualpets.com^*/ads.js
weather.com^*/advertisement.js
webfirstrow.eu^*/advertisement.js
wwg.com^*/ads.js
yellowbridge.com^*/advertisement.js
ytconv.net/*google_ads.js
ad.e-kolay.net/jquery-*-Medyanet.min.js
ad.nl^*/themes/ad/ad.css
ads.nicovideo.jp/assets/js/ads-*.js
bancainternet.com.ar/eBanking/images/*-PUBLICIDAD.
blocket.se^*/newad.js
di.se^*/advertisement.js
ettevotja.ee/templates/*/images/advert.gif
fotojorgen.no/images/*/webadverts/
fotosioon.com/wp-content/*/images/advert.gif
izigo.pt^*/adsearch
kanalfrederikshavn.dk^*/jquery.openx.js
kompas.com^*/supersized.*.min_ads.js
minuripsmed.ee/templates/*/images/advert.gif
trrsf.com^*/admanager.js
tugaleaks.com^*/wp-super-popup-pro/sppro.js
tugaleaks.com^*/wp-super-popup-pro/sppro.php
ynet.co.il^*/ads.js
paymentgate.ru/payment/*_Advert/
arnhemland-safaris.com/images/*_480_80_
artserieshotels.com.au/images/*_460_60.
assets.vice.com^*_120x60.jpg
breakingisraelnews.com/wp-content/uploads/*-300x250-
canada.com/news/*-300-250.gif
consumerist-com.wpengine.netdna-cdn.com/assets/*300x250
crowdignite.com/img/upload/*300x250
dawn.com/wp-content/uploads/*_300x250.jpg
discovery.com^*/ratio-size/pixel-ratio/300x250.png
disney.com.au/global/swf/*728x90.swf
efvi.eu/badge/*-120x60.png
film.com/plugins/*-300x250
firestormgames.co.uk/image/*-120x60.
gujaratsamachar.com/thumbprocessor/cache/300x250-
imdb.com/images/*doubleclick/*300x250
imdb.com/images/*doubleclick/*320x240
marketing.beatport.com.s3.amazonaws.com^*/728x90_
motherboard.tv/content-images/*_120x60.
nationalgeographic.com/exposure/content/*300x250
onescreen.net/os/static/widgets/*300x250
opposingviews.com^*/300x250/
rehabs.com^*/xicons_social_sprite_400x60.png
static-origin.openedition.org^*-120x240.jpg
tribune.com.ng/news2013/cache/mod_yt_k2megaslider/images/*_120_60.jpg
turner.com/v5cache/TCM/images/*_120x60.
turner.com/v5cache/TCM/Images/*_120x60_
usanetwork.com/sites/usanetwork/*300x250
usopen.org/images/pics/misc/*.300x250.jpg
vortex.accuweather.com^*_120x60_bg.jpg
vortex.accuweather.com^*_160x600_bg.jpg
vortex.accuweather.com^*_300x250_bg.jpg
w3easy.org/templates/*_120x60.
w3easy.org/templates/*_120x60_
weatherbug.com/images/stickers/*/728x90/
weatherbug.com/style/stickers/*_728x90.css
pornhubpremium.com/user/login_status
209.58.131.22^*/advertisement.js
25643e662a2.com/ad*.js
fuqer.com^*/advertisement.js
n4mo.org/wp-content/*/ads/
phncdn.com^*/ads.js
4game.com^*/yandex-metrika.js
about-australia.com/*/clickheat.js
accorhotels.com^*/xtanalyzer_roi.js
adidas.com^*/adidasAnalytics.js
alicdn.com^*/click_stat/
aliunicorn.com^*/click-stat.js
aliunicorn.com^*/click_stat/
amctv.com^*/comscore.js
arcgis.com^*/heatmap.js
bc.geocities.*/not_found/
beacon.guim.co.uk/accept-beacon
bountysource.com/badge/tracker
boxtops4education.com^*/ntpagetag.js
bt.com^*/touchclarity/homepage/omtr_tc.js
buffalowildwings.com^*/google-analytics.js
cache.nymag.com^*/clickability.js
canadiantire.ca^*/analytics.sitecatalyst.js
cbc.ca/g/stats/videoheartbeat/*/cbc-videoheartbeat.js
cbc.ca^*/loggingservice.js
cdn-redfin.com^*/page_analytics.xd.js
coremetrics.com*/eluminate.js
craveonline.com^*/google-analytics.min.js
cschat.ebay.com^*/scripts/log.js
ctv.ca/players/mediaplayer/*/comscorebeacon.js
dailycaller.com^*_chartbeat.js
deals.nextag.com^*/ClickTracker.jsp
demandware.edgesuite.net^*/js/tracking.js
directline.com^*/analytics.sitecatalyst.js
evernote.com^*/google-analytics-util.js
faostat3.fao.org^*/google-analytics-manager.js
fccbrea.org^*/swfaddress.js
fifa.com^*/webanalytics.js
firstdirect.com^*/logging-code.js
flipps.com^*/page-tracking.js
focus.ti.com^*/metrics-min.js
foodnetwork.com^*/analytics.sitecatalyst.js
gameplayer.io^*/EventTracker.js
go.com^*/analytics/tracker.otv.js
healthcare.gov/marketplace/*/clear.gif
highcharts.com^*/heatmap.js
hotmail.com/mail/*/i2a.js
ibis.com/scripts-*/xtanalyzer_roi.js
imrworldwide.com^*/flashdetect.js
imrworldwide.com^*/swfobject.js
intel.com^*/angular-google-analytics.js
itworld.com/elqnow/elq*.js
jackjones.com^*/google-analytics-tagging.js
js.vpro.nl/vpro/*/statcounter.js
juxtacommons.org^*/heatmap.js
kaltura.com/content/*/comscorePlugin.swf
keremerkan.net/wp-content/plugins/wp-minify/min/*/google-analyticator/
koldcast.tv/mint/*/tracker.php
lenovo.com^*/GoogleAnalytics.js
lg.com^*/foresee/foresee-trigger.js
lightningmaps.org^*/piwik.js
link.theplatform.com/*/tracker.log
lordandtaylor.com^*/javascript/Analytics/CartEventDataInit.js
lsi.com^*/google-analytics.js
lufthansa.com^*/mmcore.js
magnify.net^*/magnify_stats.js
maserati.com^*/transparent1x1.png
media-imdb.com^*/clickstream.js
media.ticketmaster.*/click_track.js
narf-archive.com^*/clickstream.js
nationalreview.com^*/chartbeat.js
ncbi.nlm.nih.gov/stat
networkworld.com^*/demandbase.js
nytimes.com^*/EventTracker.js
nytimes.com^*/wtbase.js
nytimes.com^*/wtinit.js
odcdn.com^*/cm.js
officeworks.com.au^*/site-tracker.js
ourworld.com/ow/evercookie_
periscope.tv^*/bugsnag-*.min.js
playcanvas.com.*/keen.min.js
pokemonblackwhite.com^*/jquery.google-analytics.js
popmoney.com^*/jquery.analytics.js
qz.com^*/tracking/bizo.js
qz.com^*/tracking/chartbeat.js
qz.com^*/tracking/comscore.js
rawgit.com^*/heatmap.js
res-x.com^*/Resonance.aspx
safelinkwireless.com/enrollment/*/GoogleAnalytics.js
sears.com^*/analytics.sitecatalyst.js
sijcc.org^*/page-tracking.js
skypicker.com/places/BCN
southwest.com^*/mbox.js
tc.bankofamerica.com/c
thehotelwindsor.com.au^*/javascript.googleAnalytics.js
ticketm.net^*/click_track.js
trustedreviews.com^*/google/analytics.js
uefa.com^*/chartbeat-trending-carousel.js
unifi.me/mootools/classes/*-tracking
vice.com^*/vmp_analytics.js
vidible.tv^*/ComScore.StreamSense.js
vidible.tv^*/ComScore.Viewability.js
visa.com^*/vendor/unica.js
volvocars.com^*/swfaddress.js
westelm.com^*/bloomreach.js
widgets.outbrain.com^*/comScore/comScore.htm
wikia.nocookie.net^*/AnalyticsEngine/js/analytics_prod.js
wikimedia.org^*/trackClick.js
windward.eu^*/angulartics-google-analytics.min.js
wired.com^*/cn-fe-stats/
wp.com/_static/*/gaAddons.js
wp.com^*/wp-content/plugins/wunderground/assets/img/icons/k/clear.gif
xcweather.co.uk/*/geo.php
xfinity.com^*/Comcast.SelfService.Sitecatalyst.js`;
var good_da_hostpath_regex_flag = 434 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 122 rules:
var good_da_regex = `flashx.tv/js/jquery.min.js|
flashx.tv/js/light.min.js|
speedtest.net/javascript/speedtest-main.js?p=*&r=*&q=*%3*&s=*%3*=
speedtest.net/javascript/speedtest-main.js?v=
ad.doubleclick.net/ad/can/cbs/*;pausead=1;
ads.nyootv.com:8080/crossdomain.xml
ads.pandora.tv/netinsight/text/pandora_global/channel/icf@
ads.sudpresse.be/adview.php?what=zone:
ads.trutv.com/html.ng/tile=*&site=trutv&tru_tv_pos=preroll&
adtech.de/?advideo/3.0/1215.1/3228528/*;vidas=pre_roll;
allot.com/Banners/*.swf$object
andcorp.com.au^*.swf?clicktag=
bing.net/images/thumbnail.aspx?q=
casino.com/banners/flash/$object,~third-party
cbs.com/sitecommon/includes/cacheable/combine.php?*/adfunctions.
checkerdist.com/product-detail.cfm?*advert_id=
completemarkets.com/pictureHandler.ashx?adid=
css.wpdigital.net/wpost/css/combo?*/ads.css
dailymotion.com/videowall/*&clickTAG=http
directtextbook.com^*.php?ad_
discovery.com/components/consolidate-static/?files=*/adsense-
disney.go.com/dxd/data/ads/game_ad.xml?gameid=
espn.co.uk/ads/gamemodule_v0.2.swf$object
expedia.co.nz/html.cms/tpid=*&adsize=
flyerservices.com/cached_banner_pages/*bannerid=
freeonlinegames.com/advertising/adaptv-as3.swf?$object
freeonlinegames.com/advertising/google-loader.swf?$object
funiaste.net/obrazki/*&adtype=
g.doubleclick.net/pagead/ads?ad_type=text_dynamicimage_flash^
game.zylom.com^*.swf?*&adURL=$object
game.zylom.com^*/cm_loader.*.swf?$object
gameitnow.com/ads/google_loader.swf$object
girlsplay.com/banners/ima3_preloader_$object
gmx.com/images/outsource/application/mailclient/mailcom/resource/mailclient/flash/multiselection_upload/multiselectionupload-*.swf$object
godtube.com/resource/mediaplayer/*&adzone=
healthline.com/v2/ad-mr2-iframe?useAdsHost=*&dfpAdSite=
i.espn.co.uk/ads/gamemodule_$object
ifeelgoood.com/tapcontent-*.swf?clicktag=$object
itv.com^*/flvplayer.swf?$object
kiz10.com/template/publicidad/ficha/ads_preloadgame/ima3_preloader_$object
koaa.com/videoplayer/iframe.cfm?*&hide_ads=
lightningcast.net/servlets/getplaylist?*&responsetype=asx&$object
mofunzone.com/ads/ima3_preloader_*.swf$object
nationalgeographic.com/channel/videos/satellite/*.swf?adsite=
ox-d.sbnation.com/w/1.0/jstag|
pacogames.com/ad/ima3_preloader_$object
ping.indieclicktv.com/www/delivery/ajs.php?zoneid
pinkbike.org^*.swf?ad=0&$object
player.onescreen.net/*/MediaPlayer.swf?ads=
player.streamtheworld.com/liveplayer.php?*adstype=
radioguide.fm/minify/?*/Advertising/webroot/css/advertising.css
rthk.hk/assets/flash/rthk/*/ad_banner$object
rthk.org.hk/assets/flash/rthk/*/ad_banner$object
server.cpmstar.com/adviewas3.swf?contentspotid=
sify.com/news/postcomments.php?*468x60.html
sploder.com/prerollad.swf?s=
static.cricinfo.com^*/ADVERTS/*/liveScores.swf$object
style.com/flashxml/*.doubleclick$object
style.com/images/*.doubleclick$object
supersonicads.com/api/v1/trackCommission.php*password=
terraristik.com^*&ad_type=
toongames.com/advertising/toon-google-preloader.swf$object
trutv.com/includes/banners/de/video/*.ad|
tudouui.com/bin/player2/*&adsourceid=
upc-cablecom.ch^*.swf?clicktag=http$object
vombasavers.com^*.swf?clickTAG=$object,~third-party
washingtonpost.com/wpost/css/combo?*/ads.css
washingtonpost.com/wpost2/css/combo?*/ads.css
washingtonpost.com^*=/ad/audsci.js
wrapper.teamxbox.com/a?size=headermainad
yimg.com/zz/combo?*&*.js
yimg.com^*&yat/js/ads_
zattoo.com/?advideo/*;vidAS=PRE_ROLL;
zeenews.india.com/ads/jw/player.swf$object
channel4.com/ad/l/1?|
coinurl.com/get.php?id=18045
majorleaguegaming.com^*.png?*=
moje-dzialdowo.pl/images/*.swf|$object
monsoonads.com:8080/crossdomain.xml
ads.peteava.ro/www/serve_ads/serve2.php?campaign=
autotube.cz/ui/player/ad.php?id=
flashgames247.com/advertising/preroll/google-fg247-preloader.swf$object
haberler.com/video-haber/adsense_news_politics.swf?$object
openx.zomoto.nl/live/www/delivery/spcjs.php?id=
ring.bg/adserver/adall.php?*&video_on_page=1
run.admost.com/adx/get.ashx?z=*&accptck=true&nojs=1
uol.com.br/html.ng/*&affiliate=
vk.com/ads?act=
google.com/uds/modules/elements/newsshow/iframe.html?*=300x250&
maps.googleapis.com/maps/api/*=300x250&
weatherbug.com/desktop-weather/*=728x90&
ads.affiliate-cruise-mail.com/redirect.aspx?pid=*&bid=
ads.affiliates-spinit.com/redirect.aspx?pid=*&bid=
ads.annapartners.com/redirect.aspx?pid=*&bid=
ads.cherrycasino.com/tracking.php?tracking_code&aid=
ads.comeon.com/redirect.aspx?pid=*&bid=
ads.ellmountgaming.com/redirect.aspx?pid=*&bid=
ads.euroslots.com/tracking.php?tracking_code&aid=
ads.leovegas.com/redirect.aspx?pid=*&bid=
ads.mrgreen.com/redirect.aspx?pid=*&bid=
ads.mrringoaffiliates.com/redirect.aspx?pid=*&bid=
ads.o-networkaffiliates.com/redirect.aspx?pid=*&bid=
ads.yakocasinoaffiliates.com/redirect.aspx?pid=*&bid=
adserving.unibet.com/redirect.aspx?pid=*&bid=
adsrv.eacdn.com/C.ashx?btag=a_
adsrv.eacdn.com/wl/clk?btag=a_
gsmarena.com/adclick.php?bannerid=
hostedadsp.realitykings.com/hosted/flash/rk_player_1.5_300x250.swf$object
kuntfutube.com/go.php?ad=
panicporn.com/Bannerads/player/player_flv_multi.swf$object
pornteengirl.com/temporaire/image.php?*/virtuagirl/
img.pornhub.com/gif/*.gif|
redtube.com/htmllogin|
submityourflicks.com/player/player-ads.swf$object
abclocal.go.com/combiner/c?js=*/visitorAPI.js
adblockanalytics.com/ads.js|
link.theplatform.com/*?affiliate=
metrics.howstuffworks.com/b/ss/*&ot=
ping.hellobar.com/?*&_e=click&
pixel.facebook.com/ajax/notifications/mark_read.php?*&alert_ids%
tags.w55c.net/rs?*&t=marketing
ups.com/*/WebTracking/track&dcs`;
var good_da_regex_flag = 122 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 8455 rules:
var bad_da_host_JSON = { "a.ads.": null,
"104.154.237.93": null,
"10pipsaffiliates.com": null,
"152media.com": null,
"174.142.194.177": null,
"18clicks.com": null,
"194.71.107.25": null,
"1ccbt.com": null,
"1clickdownloads.com": null,
"1e0y.xyz": null,
"1phads.com": null,
"1rx.io": null,
"1rxntv.io": null,
"206ads.com": null,
"20dollars2surf.com": null,
"213.163.70.183": null,
"247realmedia.com": null,
"33across.com": null,
"35.184.98.90": null,
"350media.com": null,
"360ads.com": null,
"360adstrack.com": null,
"360installer.com": null,
"360popads.com": null,
"365sbaffiliates.com": null,
"3cnce854.com": null,
"3rdads.com": null,
"46.165.197.153": null,
"46.165.197.231": null,
"4affiliate.net": null,
"4dsply.com": null,
"50.7.243.123": null,
"5advertise.com": null,
"5clickcashsoftware.com": null,
"63.225.61.4": null,
"64.20.60.123": null,
"74.117.182.77": null,
"78.138.126.253": null,
"78.140.131.214": null,
"888media.net": null,
"888medianetwork.com": null,
"a-ads.com": null,
"a-static.com": null,
"a.adroll.com": null,
"a.raasnet.com": null,
"abasourdir.tech": null,
"abnad.net": null,
"aboutads.quantcast.com": null,
"abtracker.us": null,
"accelacomm.com": null,
"access-mc.com": null,
"accmgr.com": null,
"accounts.pkr.com": null,
"accumulatork.com": null,
"accuserveadsystem.com": null,
"activedancer.com": null,
"ad-back.net": null,
"ad-balancer.net": null,
"ad-bay.com": null,
"ad-clicks.com": null,
"ad-delivery.net": null,
"ad-flow.com": null,
"ad-gbn.com": null,
"ad-goi.com": null,
"ad-indicator.com": null,
"ad-m.asia": null,
"ad-maven.com": null,
"ad-media.org": null,
"ad-recommend.com": null,
"ad-server.co.za": null,
"ad-serverparc.nl": null,
"ad-sponsor.com": null,
"ad-srv.net": null,
"ad-stir.com": null,
"ad-vice.biz": null,
"ad.doubleclick.net": null,
"ad.linksynergy.com": null,
"ad.pxlad.io": null,
"ad.yieldpartners.com": null,
"ad2adnetwork.biz": null,
"ad4game.com": null,
"ad6media.fr": null,
"adadvisor.net": null,
"adaos-ads.net": null,
"adap.tv": null,
"adblockerkillswebsites.pw": null,
"adbull.com": null,
"adbutler.com": null,
"adcash.com": null,
"adcdnx.com": null,
"adcfrthyo.tk": null,
"adchoice.co.za": null,
"adclick.lv": null,
"adclick.pk": null,
"adclickafrica.com": null,
"adclickmedia.com": null,
"adclickservice.com": null,
"adcloud.net": null,
"adcru.com": null,
"addelive.com": null,
"addynamics.eu": null,
"addynamix.com": null,
"addynamo.net": null,
"adecn.com": null,
"ademails.com": null,
"adengage.com": null,
"adexchange.io": null,
"adexchangeprediction.com": null,
"adexcite.com": null,
"adexprt.com": null,
"adexprts.com": null,
"adextent.com": null,
"adfeedstrk.com": null,
"adfootprints.com": null,
"adforgames.com": null,
"adforgeinc.com": null,
"adform.net": null,
"adframesrc.com": null,
"adfusion.com": null,
"adgatemedia.com": null,
"adgitize.com": null,
"adglamour.net": null,
"adgroups.com": null,
"adgrx.com": null,
"adhese.be": null,
"adhese.com": null,
"adhese.net": null,
"adhitzads.com": null,
"adhostingsolutions.com": null,
"adikteev.com": null,
"adimpact.com": null,
"adimpression.net": null,
"adindigo.com": null,
"adintend.com": null,
"adinterax.com": null,
"adinvigorate.com": null,
"adit-media.com": null,
"adition.com": null,
"adjector.com": null,
"adjourne.com": null,
"adjs.net": null,
"adjungle.com": null,
"adk2.com": null,
"adkick.net": null,
"adklip.com": null,
"adknowledge.com": null,
"adkonekt.com": null,
"adlegend.com": null,
"adlink.net": null,
"adlisher.com": null,
"adloaded.com": null,
"adlooxtracking.com": null,
"adlpartner.com": null,
"adlure.biz": null,
"adman.gr": null,
"admanage.com": null,
"admanmedia.com": null,
"admarketplace.net": null,
"admedia.com": null,
"admedias.net": null,
"admngronline.com": null,
"admpads.com": null,
"admulti.com": null,
"adne.tv": null,
"adnectar.com": null,
"adnet-media.net": null,
"adnet.biz": null,
"adnet.ru": null,
"adnxs.com": null,
"adocean.pl": null,
"adonnews.com": null,
"adonweb.ru": null,
"adotube.com": null,
"adowner.net": null,
"adparlor.com": null,
"adperium.com": null,
"adphreak.com": null,
"adpinion.com": null,
"adplex.media": null,
"adpoper.com": null,
"adpredictive.com": null,
"adprofit2share.com": null,
"adpushup.com": null,
"adquantix.com": null,
"adrcdn.com": null,
"adreadytractions.com": null,
"adrevolver.com": null,
"adrich.cash": null,
"adrocket.com": null,
"adrunnr.com": null,
"ads-4u.com": null,
"ads-elsevier.net": null,
"ads-stats.com": null,
"ads-twitter.com": null,
"ads.cc": null,
"ads.rd.linksynergy.com": null,
"ads01.com": null,
"ads2ads.net": null,
"ads2srv.com": null,
"ads4cheap.com": null,
"adsafeprotected.com": null,
"adsafety.net": null,
"adsalvo.com": null,
"adsame.com": null,
"adsbookie.com": null,
"adsbrook.com": null,
"adscale.de": null,
"adscampaign.net": null,
"adscendmedia.com": null,
"adsclickingnetwork.com": null,
"adscope.co.kr": null,
"adscpm.net": null,
"adsdk.com": null,
"adsdot.ph": null,
"adsearcher.ru": null,
"adsensecamp.com": null,
"adserv8.com": null,
"adserve.com": null,
"adserve.ph": null,
"adserver-fx.com": null,
"adserverplus.com": null,
"adserverpub.com": null,
"adservhere.com": null,
"adservingfactory.com": null,
"adservinginternational.com": null,
"adservpi.com": null,
"adservr.de": null,
"adsfac.eu": null,
"adsfac.net": null,
"adsfac.us": null,
"adsfactor.net": null,
"adsfan.net": null,
"adsfast.com": null,
"adsforallmedia.com": null,
"adsforindians.com": null,
"adsfundi.com": null,
"adsfundi.net": null,
"adsfuse.com": null,
"adshack.com": null,
"adshexa.com": null,
"adshopping.com": null,
"adshost1.com": null,
"adshost2.com": null,
"adshot.de": null,
"adshuffle.com": null,
"adsiduous.com": null,
"adsignals.com": null,
"adsimilis.com": null,
"adsinimages.com": null,
"adsjudo.com.": null,
"adsjudo.com": null,
"adskeeper.co.uk": null,
"adslidango.com": null,
"adslingers.com": null,
"adslot.com": null,
"adslvr.com": null,
"adsmarket.com": null,
"adsmarket.es": null,
"adsmedia.cc": null,
"adsmile.biz": null,
"adsmoon.com": null,
"adsmws.cloudapp.net": null,
"adsnative.com": null,
"adsnetworkserver.com": null,
"adsnext.net": null,
"adsniper.ru": null,
"adsomi.com": null,
"adsonar.com": null,
"adsoptimal.com": null,
"adsopx.com": null,
"adsovo.com": null,
"adsp.com": null,
"adspaper.org": null,
"adsparc.net": null,
"adspdbl.com": null,
"adspeed.com": null,
"adspirit.de": null,
"adspring.to": null,
"adspruce.com": null,
"adspynet.com": null,
"adsrevenue.net": null,
"adsring.com": null,
"adsrv.us": null,
"adsrvmedia.com": null,
"adsrvmedia.net": null,
"adsrvr.org": null,
"adssend.net": null,
"adssites.net": null,
"adstargeting.com": null,
"adstatic.com": null,
"adsterra.com": null,
"adstuna.com": null,
"adsummos.net": null,
"adsupermarket.com": null,
"adsupply.com": null,
"adsupplyssl.com": null,
"adsurve.com": null,
"adsvcs.com": null,
"adsvert.com": null,
"adsvids.com": null,
"adsxgm.com": null,
"adszom.com": null,
"adtecc.com": null,
"adtech.de": null,
"adtechus.com": null,
"adthrive.com": null,
"adtomafusion.com": null,
"adtrue.com": null,
"adtruism.com": null,
"aduacni.com": null,
"adult-adv.com": null,
"adultadworld.com": null,
"adultimate.net": null,
"adulttds.com": null,
"adv-adserver.com": null,
"advanseads.com": null,
"advarkads.com": null,
"adverigo.com": null,
"adverpub.com": null,
"adversal.com": null,
"advertarium.com.ua": null,
"advertbox.us": null,
"adverteerdirect.nl": null,
"adverticum.net": null,
"advertise.com": null,
"advertiseforfree.co.za": null,
"advertisegame.com": null,
"advertisespace.com": null,
"advertiseworld.com": null,
"advertiseyourgame.com": null,
"advertising-department.com": null,
"advertising.com": null,
"advertising365.com": null,
"advertisingiq.com": null,
"advertisingpath.net": null,
"advertisingvalue.info": null,
"advertjunction.com": null,
"advertlane.com": null,
"advertlead.net": null,
"advertlets.com": null,
"advertmarketing.com": null,
"advertmedias.com": null,
"advertnetworks.com": null,
"advertone.ru": null,
"advertpay.net": null,
"advertrev.com": null,
"advertserve.com": null,
"advertstatic.com": null,
"advertstream.com": null,
"advertur.ru": null,
"advertxi.com": null,
"advgoogle.com": null,
"advideum.com": null,
"advmedialtd.com": null,
"advombat.ru": null,
"advrtice.com": null,
"advserver.xyz": null,
"adworkmedia.com": null,
"adworldmedia.com": null,
"adworldmedia.net": null,
"adxpower.com": null,
"adyoulike.com": null,
"adzbazar.com": null,
"adzerk.net": null,
"adzmedia.com": null,
"adzpower.com": null,
"aerobins.com": null,
"afdads.com": null,
"aff.biz": null,
"affbuzzads.com": null,
"affec.tv": null,
"affiliate-b.com": null,
"affiliate-gate.com": null,
"affiliate-robot.com": null,
"affiliate.com": null,
"affiliate.cx": null,
"affiliatebannerfarm.com": null,
"affiliateedge.com": null,
"affiliateer.com": null,
"affiliatefuel.com": null,
"affiliatefuture.com": null,
"affiliategateways.co": null,
"affiliategroove.com": null,
"affiliatelounge.com": null,
"affiliatemembership.com": null,
"affiliatesensor.com": null,
"affiliation-france.com": null,
"affiliationcash.com": null,
"affiliationworld.com": null,
"affiliationzone.com": null,
"affilijack.de": null,
"affiliproducts.com": null,
"affiliserve.com": null,
"affinitad.com": null,
"affinity.com": null,
"afftrack.com": null,
"afovelsa.com": null,
"afterdownload.com": null,
"afterdownloads.com": null,
"afy11.net": null,
"againscan.com": null,
"agcdn.com": null,
"agentcenters.com": null,
"aggregateknowledge.com": null,
"aglocobanners.com": null,
"agomwefq.com": null,
"agvzvwof.com": null,
"aim4media.com": null,
"aimatch.com": null,
"aio.media": null,
"alchemysocial.com": null,
"alipromo.com": null,
"alleliteads.com": null,
"allopenclose.click": null,
"alloydigital.com": null,
"alphagodaddy.com": null,
"alternads.info": null,
"alternativeadverts.com": null,
"altpubli.com": null,
"am10.ru": null,
"am11.ru": null,
"amazon-adsystem.com": null,
"amertazy.com": null,
"amgdgt.com": null,
"amp.rd.linksynergy.com": null,
"ampxchange.com": null,
"anastasiasaffiliate.com": null,
"andbeyond.media": null,
"andomedia.com": null,
"andomediagroup.com": null,
"anonymousads.com": null,
"anyclip-media.com": null,
"anymedia.lv": null,
"apex-ad.com": null,
"apmebf.com": null,
"appendad.com": null,
"apprupt.com": null,
"april29-disp-download.com": null,
"apsmediaagency.com": null,
"arabweb.biz": null,
"arcadebannerexchange.net": null,
"arcadebannerexchange.org": null,
"arcadebanners.com": null,
"arcadebe.com": null,
"areasins.com": null,
"areasnap.com": null,
"arti-mediagroup.com": null,
"asafesite.com": null,
"aseadnet.com": null,
"assetize.com": null,
"assoc-amazon.com": null,
"asterpix.com": null,
"atadserver.com": null,
"atmalinks.com": null,
"atomex.net": null,
"atrinsic.com": null,
"atwola.com": null,
"auctionnudge.com": null,
"audience2media.com": null,
"audiencefuel.com": null,
"audienceprofiler.com": null,
"auditude.com": null,
"augmentad.net": null,
"august15download.com": null,
"automatedtraffic.com": null,
"automateyourlist.com": null,
"avads.co.uk": null,
"avazutracking.net": null,
"awempire.com": null,
"awltovhc.com": null,
"awstaticdn.net": null,
"awsurveys.com": null,
"azads.com": null,
"azoogleads.com": null,
"b4banner.in": null,
"backbeatmedia.com": null,
"backlinks.com": null,
"badjocks.com": null,
"bananaflippy.com": null,
"banner-clix.com": null,
"banner-rotation.com": null,
"bannerbank.ru": null,
"bannerblasters.com": null,
"bannerbridge.net": null,
"bannercde.com": null,
"bannerconnect.com": null,
"bannerconnect.net": null,
"bannerdealer.com": null,
"bannerexchange.com.au": null,
"bannerflow.com": null,
"bannerflux.com": null,
"bannerignition.co.za": null,
"bannerjammers.com": null,
"bannerlot.com": null,
"bannerperformance.net": null,
"bannerrage.com": null,
"bannersmania.com": null,
"bannersnack.com": null,
"bannersnack.net": null,
"bannersurvey.biz": null,
"bannertgt.com": null,
"bannertracker-script.com": null,
"bannerweb.com": null,
"baronsoffers.com": null,
"basebanner.com": null,
"bbelements.com": null,
"beaconads.com": null,
"become.successfultogether.co.uk": null,
"beead.co.uk": null,
"beead.net": null,
"beforescence.com": null,
"begun.ru": null,
"bentdownload.com": null,
"beringmedia.com": null,
"bestcasinopartner.com": null,
"bestdeals.ws": null,
"bestfindsite.com": null,
"bestforexpartners.com": null,
"bestforexplmdb.com": null,
"bestgameads.com": null,
"bet3000partners.com": null,
"bet365affiliates.com": null,
"betpartners.it": null,
"betrad.com": null,
"bettingpartners.com": null,
"bf-ad.net": null,
"bfast.com": null,
"bidsystem.com": null,
"bidvertiser.com": null,
"biemedia.com": null,
"bigfineads.com": null,
"bijscode.com": null,
"billypub.com": null,
"bimlocal.com": null,
"bin-layer.ru": null,
"bingo4affiliates.com": null,
"binlayer.com": null,
"bitads.net": null,
"bitcoinadvertisers.com": null,
"bitfalcon.tv": null,
"bittads.com": null,
"bitx.tv": null,
"bizographics.com": null,
"bizzclick.com": null,
"bjjingda.com": null,
"blamads.com": null,
"blamcity.com": null,
"blinkadr.com": null,
"blogads.com": null,
"blogbannerexchange.com": null,
"bloggerex.com": null,
"blogherads.com": null,
"blueadvertise.com": null,
"bluetoad.com": null,
"bnetworx.com": null,
"bogads.com": null,
"bookelement.biz": null,
"boostads.net": null,
"bormoni.ru": null,
"boydadvertising.co.uk": null,
"bptracking.com": null,
"brand-display.com": null,
"brand.net": null,
"brandads.net": null,
"brandaffinity.net": null,
"brandclik.com": null,
"brandreachsys.com": null,
"braside.ru": null,
"bravenetmedianetwork.com": null,
"breadpro.com": null,
"bridgetrack.com": null,
"brightshare.com": null,
"broadstreetads.com": null,
"brokeloy.com": null,
"brucelead.com": null,
"bruceleadx.com": null,
"bruceleadx1.com": null,
"bruceleadx2.com": null,
"bruceleadx3.com": null,
"bruceleadx4.com": null,
"btrll.com": null,
"bttrack.com": null,
"bubblesmedia.ru": null,
"bucketsofbanners.com": null,
"buildtrafficx.com": null,
"bunchofads.com": null,
"burstnet.com": null,
"businesscare.com": null,
"businessclick.com": null,
"buyflood.com": null,
"buysellads.com": null,
"buzzparadise.com": null,
"bwinpartypartners.com": null,
"bznclicks.com": null,
"camleyads.info": null,
"campanja.com": null,
"capacitygrid.com": null,
"captainad.com": null,
"captifymedia.com": null,
"carbonads.com": null,
"casalemedia.com": null,
"cash-duck.com": null,
"cash4members.com": null,
"cashatgsc.com": null,
"cashmylinks.com": null,
"cashonvisit.com": null,
"cashtrafic.com": null,
"cashtrafic.info": null,
"cashworld.biz": null,
"casino-zilla.com": null,
"casterpretic.com": null,
"castplatform.com": null,
"cb-content.com": null,
"cbaazars.com": null,
"cbclickbank.com": null,
"cbclicks.com": null,
"cbleads.com": null,
"cbn.tbn.ru": null,
"cc-dt.com": null,
"cdn.mobicow.com": null,
"cdna.tremormedia.com": null,
"cdnads.com": null,
"cdnapi.net": null,
"cdnload.top": null,
"cdnrl.com": null,
"cdnservr.com": null,
"cdntrip.com": null,
"cfasync.tk": null,
"chango.com": null,
"chanitet.ru": null,
"chargeplatform.com": null,
"charltonmedia.com": null,
"checkapi.xyz": null,
"checkm8.com": null,
"checkmystats.com.au": null,
"checkoutfree.com": null,
"cherytso.com": null,
"chiliadv.com": null,
"chinagrad.ru": null,
"chronicads.com": null,
"cibleclick.com": null,
"city-ads.de": null,
"cityadspix.com": null,
"citysite.net": null,
"clash-media.com": null,
"class64deal.com": null,
"claxonmedia.com": null,
"clevernt.com": null,
"click.scour.com": null,
"click2jump.com": null,
"click4free.info": null,
"clickable.com": null,
"clickad.pl": null,
"clickagy.com": null,
"clickbet88.com": null,
"clickbooth.com": null,
"clickboothlnk.com": null,
"clickbubbles.net": null,
"clickcash.com": null,
"clickcertain.com": null,
"clickequations.net": null,
"clickexa.com": null,
"clickexperts.net": null,
"clickfuse.com": null,
"clickinc.com": null,
"clickintext.com": null,
"clickintext.net": null,
"clickiocdn.com": null,
"clickkingdom.net": null,
"clickly.co": null,
"clickmngr.com": null,
"clickmon.co.kr": null,
"clickmyads.info": null,
"clicknano.com": null,
"clickosmedia.com": null,
"clicks2count.com": null,
"clicks4ads.com": null,
"clicksor.com": null,
"clicksor.net": null,
"clicksurvey.mobi": null,
"clickterra.net": null,
"clickthrucash.com": null,
"clicktripz.co": null,
"clicktripz.com": null,
"clickupto.com": null,
"clickwinks.com": null,
"clickxchange.com": null,
"clickzxc.com": null,
"clixtrac.com": null,
"clkdown.info": null,
"clmbtech.com": null,
"cloudiiv.com": null,
"cloudioo.net": null,
"cloudset.xyz": null,
"cltomedia.info": null,
"cmfads.com": null,
"cnt.my": null,
"cntdy.mobi": null,
"coadvertise.com": null,
"codeonclick.com": null,
"coedmediagroup.com": null,
"coinad.com": null,
"coinadvert.net": null,
"coinmedia.co": null,
"cointraffic.in": null,
"cointraffic.io": null,
"collective-media.net": null,
"colliersads.com": null,
"combotag.com": null,
"comclick.com": null,
"comeadvertisewithus.com": null,
"complive.link": null,
"comscore.com": null,
"conduit-banners.com": null,
"connatix.com": null,
"connectedads.net": null,
"connectionads.com": null,
"connexplace.com": null,
"construment.com": null,
"content-ad.net": null,
"content-cooperation.com": null,
"contentclick.co.uk": null,
"contentdigital.info": null,
"contentjs.com": null,
"contenture.com": null,
"contentwidgets.net": null,
"contexlink.se": null,
"contextads.net": null,
"contextuads.com": null,
"contextweb.com": null,
"coolerads.com": null,
"coolmirage.com": null,
"coolyeti.info": null,
"cornflip.com": null,
"corruptcy.com": null,
"corwrite.com": null,
"cpaclicks.com": null,
"cpaclickz.com": null,
"cpalead.com": null,
"cpcadnet.com": null,
"cpm.biz": null,
"cpmaffiliation.com": null,
"cpmmedia.net": null,
"cpmtree.com": null,
"cpvads.com": null,
"cpvadvertise.com": null,
"cpxinteractive.com": null,
"crakmedia.com": null,
"crazylead.com": null,
"crazyvideosempire.com": null,
"creative-serving.com": null,
"creativecdn.com": null,
"creditcards15x.tk": null,
"crispads.com": null,
"crowdgatheradnetwork.com": null,
"crowdgravity.com": null,
"cruftexcision.xyz": null,
"cruiseworldinc.com": null,
"ctasnet.com": null,
"ctm-media.com": null,
"cuelinks.com": null,
"cwtrackit.com": null,
"czechose.com": null,
"d.adroll.com": null,
"d03x2011.com": null,
"da-ads.com": null,
"dadegid.ru": null,
"dapper.net": null,
"dashad.io": null,
"dashbida.com": null,
"dashboardad.net": null,
"dashgreen.online": null,
"data.adroll.com": null,
"datacratic-px.com": null,
"datawrkz.com": null,
"dating-banners.com": null,
"datinggold.com": null,
"dbbsrv.com": null,
"dealcurrent.com": null,
"decisionmark.com": null,
"decisionnews.com": null,
"dedicatedmedia.com": null,
"deepmetrix.com": null,
"defaultimg.com": null,
"deguiste.com": null,
"dehtale.ru": null,
"deletemer.online": null,
"deliberatelyvirtuallyshared.xyz": null,
"deployads.com": null,
"depresis.com": null,
"derlatas.com": null,
"developermedia.com": null,
"deximedia.com": null,
"dexplatform.com": null,
"dgmaustralia.com": null,
"dhundora.com": null,
"diamondtraff.com": null,
"digipathmedia.com": null,
"digitrevenue.com": null,
"dinclinx.com": null,
"dipads.net": null,
"directaclick.com": null,
"directclicksonly.com": null,
"directleads.com": null,
"directrev.com": null,
"directtrack.com": null,
"dispop.com": null,
"disqusads.com": null,
"dl-rms.com": null,
"dnbizcdn.com": null,
"dollarade.com": null,
"dollarsponsor.com": null,
"domainadvertising.com": null,
"domainsponsor.com": null,
"domdex.com": null,
"dominoad.com": null,
"doogleonduty.com": null,
"dotandad.com": null,
"dotandads.com": null,
"doubleclick.com": null,
"doubleclickbygoogle.com": null,
"doubleclicks.me": null,
"doublepimp.com": null,
"doublerads.com": null,
"doublerecall.com": null,
"doubleverify.com": null,
"down1oads.com": null,
"downloadboutique.com": null,
"downloatransfer.com": null,
"downsonglyrics.com": null,
"dpsrexor.com": null,
"dropzenad.com": null,
"dsnr-affiliates.com": null,
"dtzads.com": null,
"duetads.com": null,
"duggiads.com": null,
"dumedia.ru": null,
"durnowar.com": null,
"durokuro.com": null,
"dveribo.ru": null,
"dynad.net": null,
"dynamicdn.com": null,
"dynamitedata.com": null,
"e2yth.tv": null,
"eads-adserving.com": null,
"eads.to": null,
"easy-adserver.com": null,
"easyad.com": null,
"easydownload4you.com": null,
"easyflirt-partners.biz": null,
"ebannertraffic.com": null,
"ebayobjects.com.au": null,
"ebayobjects.com": null,
"eblastengine.com": null,
"ebuzzing.com": null,
"eclick.vn": null,
"edgeads.org": null,
"effectivemeasure.net": null,
"ektezis.ru": null,
"elasticad.net": null,
"elefantsearch.com": null,
"emberads.com": null,
"embraceablemidpointcinnabar.com": null,
"emediate.ch": null,
"emediate.dk": null,
"emediate.eu": null,
"emediate.se": null,
"empiremoney.com": null,
"emptyspaceads.com": null,
"engineseeker.com": null,
"enterads.com": null,
"entrecard.s3.amazonaws.com": null,
"eosads.com": null,
"ep7kpqn8.online": null,
"epicgameads.com": null,
"epnredirect.ru": null,
"eqads.com": null,
"ergodob.ru": null,
"ergoledo.com": null,
"ero-advertising.com": null,
"erovinmo.com": null,
"escokuro.com": null,
"essayads.com": null,
"essaycoupons.com": null,
"et-code.ru": null,
"etargetnet.com": null,
"etmanly.ru": null,
"euroclick.com": null,
"europacash.com": null,
"euros4click.de": null,
"evolvemediallc.com": null,
"evolvenation.com": null,
"excellenceads.com": null,
"exchange4media.com": null,
"exdynsrv.com": null,
"exitexplosion.com": null,
"exitjunction.com": null,
"exoclick.com": null,
"explainidentifycoding.info": null,
"expocrack.com": null,
"expogrim.com": null,
"exponential.com": null,
"expresswebtraffic.com": null,
"extend.tv": null,
"eyereturn.com": null,
"eyeviewads.com": null,
"eyewonder.com": null,
"ezadserver.net": null,
"facebooker.top": null,
"fairadsnetwork.com": null,
"fandelcot.com": null,
"fast2earn.com": null,
"fastapi.net": null,
"fastates.net": null,
"fastclick.net": null,
"fasttracktech.biz": null,
"featence.com": null,
"featurelink.com": null,
"feed-ads.com": null,
"fiberpairjo.link": null,
"filadmir.site": null,
"filetarget.com": null,
"fimserve.com": null,
"finalanypar.link": null,
"find-cheap-hotels.org": null,
"firegetbook4u.biz": null,
"firmharborlinked.com": null,
"firstadsolution.com": null,
"firstimpression.io": null,
"fixionmedia.com": null,
"fl-ads.com": null,
"flagads.net": null,
"flashclicks.com": null,
"flashtalking.com": null,
"flexlinks.com": null,
"flodonas.com": null,
"fluidads.co": null,
"fluxads.com": null,
"flymyads.com": null,
"flytomars.online": null,
"fmpub.net": null,
"fmsads.com": null,
"fnro4yu0.loan": null,
"fogzyads.com": null,
"foonad.com": null,
"footerslideupad.com": null,
"footnote.com": null,
"forcepprofile.com": null,
"forex-affiliate.com": null,
"forex-affiliate.net": null,
"forifiha.com": null,
"forrestersurveys.com": null,
"frameptp.com": null,
"free-domain.net": null,
"freebannerswap.co.uk": null,
"freebiesurveys.com": null,
"freecouponbiz.com": null,
"freedownloadsoft.net": null,
"freepaidsurveyz.com": null,
"freerotator.com": null,
"freeskreen.com": null,
"freesoftwarelive.com": null,
"freestar.io": null,
"friendlyduck.com": null,
"fromfriendswithlove.com": null,
"fruitkings.com": null,
"fulltraffic.net": null,
"fungus.online": null,
"fusionads.net": null,
"futureus.com": null,
"g-cash.biz": null,
"g17media.com": null,
"g4whisperermedia.com": null,
"gainmoneyfast.com": null,
"gambling-affiliation.com": null,
"game-advertising-online.com": null,
"game-clicks.com": null,
"gameads.com": null,
"gamecetera.com": null,
"gamehotus.com": null,
"gamersad.com": null,
"gamersbanner.com": null,
"gamesbannerexchange.com": null,
"gamesrevenue.com": null,
"gan.doubleclick.net": null,
"gandrad.org": null,
"garristo.com": null,
"garvmedia.com": null,
"gate-ru.com": null,
"gayadnetwork.com": null,
"gctwh9xc.site": null,
"gefhasio.com": null,
"genericlink.com": null,
"genericsteps.com": null,
"genesismedia.com": null,
"geniad.net": null,
"genotba.online": null,
"geoipads.com": null,
"geovisite.com": null,
"getgamers.eu": null,
"getgscfree.com": null,
"getpopunder.com": null,
"getscorecash.com": null,
"getthislistbuildingvideo.biz": null,
"giantaffiliates.com": null,
"gigamega.su": null,
"gimiclub.com": null,
"gitcdn.pw": null,
"gitcdn.site": null,
"gitload.site": null,
"gklmedia.com": null,
"glaswall.online": null,
"global-success-club.net": null,
"globaladsales.com": null,
"globaladv.net": null,
"globalsuccessclub.com": null,
"globaltraffico.com": null,
"gmads.net": null,
"go2jump.org": null,
"go2media.org": null,
"goclickon.us": null,
"gojoingscnow.com": null,
"gold-file.com": null,
"goodadvert.ru": null,
"goodadvertising.info": null,
"goodluckblockingthis.com": null,
"googleadservicepixel.com": null,
"googlesyndicatiion.com": null,
"gourmetads.com": null,
"governmenttrainingexchange.com": null,
"goviral-content.com": null,
"gpacalculatorhighschoolfree.com": null,
"grabmyads.com": null,
"granodiorite.com": null,
"grapeshot.co.uk": null,
"greenads.org": null,
"grenstia.com": null,
"gretzalz.com": null,
"gripdownload.co": null,
"groovinads.com": null,
"grumpyadzen.com": null,
"gumgum.com": null,
"gunpartners.com": null,
"gururevenue.com": null,
"gwallet.com": null,
"h-images.net": null,
"h12-media.com": null,
"hanaprop.com": null,
"harrenmedianetwork.com": null,
"havamedia.net": null,
"hdplayer-download.com": null,
"healthaffiliatesnetwork.com": null,
"hexagram.com": null,
"hijacksystem.com": null,
"hilltopads.net": null,
"himediads.com": null,
"himediadx.com": null,
"hipersushiads.com": null,
"histians.com": null,
"hlads.com": null,
"hmongcash.com": null,
"hola-shopping.com": null,
"honestlypopularvary.xyz": null,
"hoomezip.biz": null,
"horse-racing-affiliate-program.co.uk": null,
"horsered.com": null,
"horyzon-media.com": null,
"hostgit.net": null,
"hosticanaffiliate.com": null,
"hot-hits.us": null,
"hotfeed.net": null,
"hotkeys.com": null,
"hotptp.com": null,
"hotwords.com.br": null,
"hotwords.com.mx": null,
"hotwords.com": null,
"houstion.com": null,
"hoverr.media": null,
"htmlhubing.xyz": null,
"hulahooprect.com": null,
"huzonico.com": null,
"hype-ads.com": null,
"hypeads.org": null,
"hyperbanner.net": null,
"hyperlinksecure.com": null,
"hyperpromote.com": null,
"hypertrackeraff.com": null,
"hypervre.com": null,
"hyperwebads.com": null,
"i-media.co.nz": null,
"i.skimresources.com": null,
"iamediaserve.com": null,
"iasbetaffiliates.com": null,
"ibannerexchange.com": null,
"icdirect.com": null,
"idealmedia.com": null,
"identads.com": null,
"idownloadgalore.com": null,
"idreammedia.com": null,
"iframe.mediaplazza.com": null,
"igameunion.com": null,
"ignitioninstaller.com": null,
"iicheewi.com": null,
"imageadnet.com": null,
"imasdk.googleapis.com": null,
"imedia.co.il": null,
"imediaaudiences.com": null,
"imediarevenue.com": null,
"img-giganto.net": null,
"imgfeedget.com": null,
"imglt.com": null,
"imgsniper.com": null,
"imgtty.com": null,
"imgwebfeed.com": null,
"imho.ru": null,
"imiclk.com": null,
"impact-ad.jp": null,
"impactradius.com": null,
"impresionesweb.com": null,
"impressionaffiliate.com": null,
"impressionaffiliate.mobi": null,
"impressioncontent.info": null,
"impressiondesk.com": null,
"impressionperformance.biz": null,
"impressionvalue.mobi": null,
"in-appadvertising.com": null,
"incentaclick.com": null,
"incloak.com": null,
"indiabanner.com": null,
"indiads.com": null,
"indianbannerexchange.com": null,
"indianlinkexchange.com": null,
"indieclick.com": null,
"indofad.com": null,
"industrybrains.com": null,
"infectiousmedia.com": null,
"infinite-ads.com": null,
"infinityads.com": null,
"influads.com": null,
"infolinks.com": null,
"infra-ad.com": null,
"ingame.ad": null,
"inktad.com": null,
"inplaybricks.com": null,
"insightexpress.com": null,
"insightexpressai.com": null,
"insitepromotion.com": null,
"insitesystems.com": null,
"inskinad.com": null,
"inspiringsweater.xyz": null,
"insta-cash.net": null,
"instantbannercreator.com": null,
"instantdollarz.com": null,
"instinctiveads.com": null,
"instraffic.com": null,
"instreamvideo.ru": null,
"intellibanners.com": null,
"intellitxt.com": null,
"intenthq.com": null,
"intentmedia.net": null,
"interclick.com": null,
"interestably.com": null,
"interesting.cc": null,
"intermarkets.net": null,
"interpolls.com": null,
"interworksmedia.co.kr": null,
"intextad.net": null,
"intextdirect.com": null,
"intextscript.com": null,
"intopicmedia.com": null,
"intuneads.com": null,
"inuxu.biz": null,
"investingchannel.com": null,
"inviziads.com": null,
"ipowercdn.com": null,
"ipromote.com": null,
"isparkmedia.com": null,
"itempana.site": null,
"itrengia.com": null,
"iv.doubleclick.net": null,
"izeads.com": null,
"jangonetwork.com": null,
"jarvinzo.com": null,
"javacript.cf": null,
"javacript.ga": null,
"javacript.gq": null,
"javacript.ml": null,
"javacript.tk": null,
"jcnqc.us": null,
"jeetyetmedia.com": null,
"jewishcontentnetwork.com": null,
"jfx61qca.site": null,
"jobsyndicate.com": null,
"joytocash.com": null,
"js.cdn.ac": null,
"jscloud.org": null,
"jsfeedadsget.com": null,
"juiceadv.com": null,
"juiceadv.net": null,
"juicyads.com": null,
"jujuads.com": null,
"jumboaffiliates.com": null,
"jumbolt.ru": null,
"jumpelead.com": null,
"jumptap.com": null,
"justrelevant.com": null,
"jwaavsze.com": null,
"jyvtidkx.com": null,
"k9anf8bc.webcam": null,
"kanoodle.com": null,
"kantarmedia.com": null,
"kavanga.ru": null,
"ketads.com": null,
"keyrunmodel.com": null,
"keywordblocks.com": null,
"keywordlink.co.kr": null,
"keywordpop.com": null,
"kikuzip.com": null,
"kintokup.com": null,
"kitnmedia.com": null,
"klikadvertising.com": null,
"kliksaya.com": null,
"klikvip.com": null,
"klipmart.com": null,
"klixfeed.com": null,
"kloapers.com": null,
"kolition.com": null,
"komoona.com": null,
"koocash.com": null,
"korrelate.net": null,
"kromeleta.ru": null,
"kumpulblogger.com": null,
"ladbrokesaffiliates.com.au": null,
"laim.tv": null,
"langosh.biz": null,
"layer-ad.org": null,
"lcl2adserver.com": null,
"lduhtrp.net": null,
"leadacceptor.com": null,
"leadad.mobi": null,
"leadadvert.info": null,
"leadcola.com": null,
"leadmediapartners.com": null,
"leetmedia.com": null,
"leohd59.ru": null,
"lepinsar.com": null,
"lepintor.com": null,
"letadnew.com": null,
"letsadvertisetogether.com": null,
"letsgoshopping.tk": null,
"letysheeps.ru": null,
"lfstmedia.com": null,
"licantrum.com": null,
"liftdna.com": null,
"lightad.co.kr": null,
"linkbuddies.com": null,
"linkclicks.com": null,
"linkelevator.com": null,
"linkexchange.com": null,
"linkexchangers.net": null,
"linkgrand.com": null,
"linkmads.com": null,
"linkoffers.net": null,
"linkreferral.com": null,
"links.io": null,
"links2revenue.com": null,
"linkshowoff.com": null,
"linksmart.com": null,
"linkstorm.net": null,
"linkwash.de": null,
"linkworth.com": null,
"linkybank.com": null,
"linkz.net": null,
"lionsads.com": null,
"liveadexchanger.com": null,
"liveadserver.net": null,
"liverail.com": null,
"local-chicks-here3.top": null,
"localedgemedia.com": null,
"lockhosts.com": null,
"looneyads.com": null,
"loopmaze.com": null,
"lose-ads.de": null,
"loseads.eu": null,
"lotteryaffiliates.com": null,
"love-banner.com": null,
"loxtk.com": null,
"lqcdn.com": null,
"ltassrv.com.s3.amazonaws.com": null,
"lucidmedia.com": null,
"lushcrush.com": null,
"luxadv.com": null,
"luxbetaffiliates.com.au": null,
"luxup.ru": null,
"machings.com": null,
"madadsmedia.com": null,
"madserving.com": null,
"madsone.com": null,
"magnetisemedia.com": null,
"mainadv.com": null,
"mainroll.com": null,
"makecashtakingsurveys.biz": null,
"makemoneymakemoney.net": null,
"marimedia.com": null,
"markboil.online": null,
"marketbanker.com": null,
"markethealth.com": null,
"marsads.com": null,
"martiniadnetwork.com": null,
"masterads.org": null,
"mastertraffic.cn": null,
"mathads.com": null,
"mcdomainalot.com": null,
"mdadvertising.net": null,
"measurelyapp.com": null,
"media-general.com": null,
"media-ks.net": null,
"media-networks.ru": null,
"media-servers.net": null,
"media.net": null,
"media303.com": null,
"media6degrees.com": null,
"media970.com": null,
"mediaadserver.org": null,
"mediaclick.com": null,
"mediacpm.com": null,
"mediaessence.net": null,
"mediaffiliation.com": null,
"mediafilesdownload.com": null,
"mediaflire.com": null,
"mediaforce.com": null,
"mediaforge.com": null,
"mediag4.com": null,
"mediagridwork.com": null,
"mediakeywords.com": null,
"medialand.ru": null,
"medialation.net": null,
"mediaonenetwork.net": null,
"mediaonpro.com": null,
"mediapeo.com": null,
"mediaraily.com": null,
"mediatarget.com": null,
"mediative.ca": null,
"mediative.com": null,
"mediatraffic.com": null,
"mediatraks.com": null,
"mediaver.com": null,
"medleyads.com": null,
"medrx.sensis.com.au": null,
"medyanetads.com": null,
"meendocash.com": null,
"meetic-partners.com": null,
"megaad.nz": null,
"megapopads.com": null,
"meinlist.com": null,
"mellowads.com": null,
"mentad.com": null,
"mentalks.ru": null,
"merchenta.com": null,
"mercuras.com": null,
"messagespaceads.com": null,
"metavertizer.com": null,
"metrics.io": null,
"meviodisplayads.com": null,
"mezimedia.com": null,
"mftracking.com": null,
"mgcash.com": null,
"mgcashgate.com": null,
"mgplatform.com": null,
"microad.jp": null,
"microsoftaffiliates.net": null,
"minodazi.com": null,
"mistands.com": null,
"mixmarket.biz": null,
"mixpo.com": null,
"mlnadvertising.com": null,
"mmadsgadget.com": null,
"mmgads.com": null,
"mmotraffic.com": null,
"mnetads.com": null,
"moatads.com": null,
"mobatori.com": null,
"mobatory.com": null,
"mobday.com": null,
"mobfox.com": null,
"mobicont.com": null,
"mobidevdom.com": null,
"mobifobi.com": null,
"mobikano.com": null,
"mobile-10.com": null,
"mobiright.com": null,
"mobisla.com": null,
"mobitracker.info": null,
"mobiyield.com": null,
"moborobot.com": null,
"mobsterbird.info": null,
"mobstitialtag.com": null,
"mobstrks.com": null,
"mobtrks.com": null,
"mobytrks.com": null,
"modelegating.com": null,
"moffsets.com": null,
"mojoaffiliates.com": null,
"mokonocdn.com": null,
"money-cpm.fr": null,
"money4ads.com": null,
"moneycosmos.com": null,
"moneywhisper.com": null,
"monkeybroker.net": null,
"monsoonads.com": null,
"mookie1.com": null,
"mootermedia.com": null,
"moregamers.com": null,
"morgdm.ru": null,
"moritava.com": null,
"moselats.com": null,
"movad.net": null,
"mozcloud.net": null,
"mp3toavi.xyz": null,
"mprezchc.com": null,
"mpuls.ru": null,
"msads.net": null,
"mukwonagoacampo.com": null,
"multiadserv.com": null,
"munically.com": null,
"musicnote.info": null,
"mxf.dfp.host": null,
"mxtads.com": null,
"myaffiliates.com": null,
"mycasinoaccounts.com": null,
"myclickbankads.com": null,
"mycooliframe.net": null,
"mydreamads.com": null,
"mylinkbox.com": null,
"mynativeads.com": null,
"mystaticfiles.com": null,
"mythings.com": null,
"myuniques.ru": null,
"myvads.com": null,
"mywidget.mobi": null,
"n130adserv.com": null,
"n161adserv.com": null,
"n4403ad.doubleclick.net": null,
"nagrande.com": null,
"nanigans.com": null,
"native-adserver.com": null,
"nativead.co": null,
"nativead.tech": null,
"nativeads.com": null,
"nativeadsfeed.com": null,
"nativeleads.net": null,
"nativeroll.tv": null,
"navaxudoru.com": null,
"nbstatic.com": null,
"negolist.com": null,
"neodatagroup.com": null,
"net-ad-vantage.com": null,
"net3media.com": null,
"netliker.com": null,
"netloader.cc": null,
"netpondads.com": null,
"netseer.com": null,
"netshelter.net": null,
"netsolads.com": null,
"networldmedia.net": null,
"neudesicmediagroup.com": null,
"newgentraffic.com": null,
"newideasdaily.com": null,
"newsadstream.com": null,
"newstogram.com": null,
"nexac.com": null,
"nextlandingads.com": null,
"nextmobilecash.com": null,
"nglmedia.com": null,
"nicheads.com": null,
"nm7xq628.click": null,
"nmcdn.us": null,
"nobleppc.com": null,
"nobsetfinvestor.com": null,
"nonstoppartner.de": null,
"normkela.com": null,
"northmay.com": null,
"nowspots.com": null,
"nplexmedia.com": null,
"nsmartad.com": null,
"nsstatic.net": null,
"nui.media": null,
"nxtck.com": null,
"nyadmcncserve-05y06a.com": null,
"nzads.net.nz": null,
"oads.co": null,
"obeisantcloddishprocrustes.com": null,
"obibanners.com": null,
"objects.tremormedia.com": null,
"oclsasrv.com": null,
"oehposan.com": null,
"offeradvertising.biz": null,
"offerpalads.com": null,
"offersquared.com": null,
"ofino.ru": null,
"ogercron.com": null,
"ohmwrite.com": null,
"omclick.com": null,
"omni-ads.com": null,
"onad.eu": null,
"onads.com": null,
"onclasrv.com": null,
"onclickads.net": null,
"onclickmax.com": null,
"oneopenclose.click": null,
"online-adnetwork.com": null,
"online-media24.de": null,
"onlineadtracker.co.uk": null,
"onlyalad.net": null,
"onrampadvertising.com": null,
"onscroll.com": null,
"onsitemarketplace.net": null,
"openclose.click": null,
"opensourceadvertisementnetwork.info": null,
"openx.net": null,
"openxadexchange.com": null,
"optiad.net": null,
"optimizeadvert.biz": null,
"optimizesocial.com": null,
"optinmonster.com": null,
"orangeads.fr": null,
"ordingly.com": null,
"osiaffiliate.com": null,
"oskale.ru": null,
"ospreymedialp.com": null,
"othersonline.com": null,
"ourunlimitedleads.com": null,
"ov8pc.tv": null,
"overhaps.com": null,
"overture.com": null,
"overturs.com": null,
"ovtopli.ru": null,
"owlads.io": null,
"owtezan.ru": null,
"oxtracking.com": null,
"ozertesa.com": null,
"ozonemedia.com": null,
"p2ads.com": null,
"paads.dk": null,
"paclitor.com": null,
"padsdelivery.com": null,
"padstm.com": null,
"paid4ad.de": null,
"paidsearchexperts.com": null,
"pakbanners.com": null,
"pantherads.com": null,
"paperg.com": null,
"paradocs.ru": null,
"parkingcrew.net": null,
"partner-ads.com": null,
"partner.googleadservices.com": null,
"partner.video.syndication.msn.com": null,
"partnerearning.com": null,
"partnermax.de": null,
"partycasino.com": null,
"partypartners.com": null,
"partypoker.com": null,
"passionfruitads.com": null,
"pautaspr.com": null,
"pay-click.ru": null,
"pc-ads.com": null,
"peakclick.com": null,
"pebblemedia.be": null,
"peer39.net": null,
"perfcreatives.com": null,
"perfectmarket.com": null,
"performanceadvertising.mobi": null,
"performancetrack.info": null,
"performancingads.com": null,
"pezrphjl.com": null,
"pgmediaserve.com": null,
"pgpartner.com": null,
"pharmcash.com": null,
"philosophere.com": null,
"pianobuyerdeals.com": null,
"picadmedia.com": null,
"picbucks.com": null,
"piercial.com": null,
"pioneeringad.com": null,
"pip-pip-pop.com": null,
"pipeaota.com": null,
"piticlik.com": null,
"pivotalmedialabs.com": null,
"pivotrunner.com": null,
"pixeltrack66.com": null,
"pixtrack.in": null,
"platinumadvertisement.com": null,
"playertraffic.com": null,
"pleasesavemyimages.com": null,
"plenomedia.com": null,
"plushlikegarnier.com": null,
"plxserve.com": null,
"pmpubs.com": null,
"pointclicktrack.com": null,
"pointroll.com": null,
"points2shop.com": null,
"polyad.net": null,
"popads.net": null,
"popadscdn.net": null,
"popcash.net": null,
"popcpm.com": null,
"popcpv.com": null,
"popearn.com": null,
"popmajor.com": null,
"popmarker.com": null,
"popmyad.com": null,
"popmyads.com": null,
"poponclick.com": null,
"poppysol.com": null,
"poprev.net": null,
"poprevenue.net": null,
"popsads.com": null,
"popshow.info": null,
"poptarts.me": null,
"poptm.com": null,
"popularitish.com": null,
"popularmedia.net": null,
"populis.com": null,
"populisengage.com": null,
"popunder.ru": null,
"popundertotal.com": null,
"popunderz.com": null,
"popunderzone.com": null,
"popuptraffic.com": null,
"popupvia.com": null,
"popwin.net": null,
"pornv.org": null,
"portkingric.net": null,
"potcityzip.com": null,
"poundaccordexecute.info": null,
"poweradvertising.co.uk": null,
"powerlinks.com": null,
"ppclinking.com": null,
"ppsearcher.ru": null,
"precisionclick.com": null,
"predictad.com": null,
"predictivadnetwork.com": null,
"prestadsng.com": null,
"prexista.com": null,
"primaryads.com": null,
"pritesol.com": null,
"privilegebedroomlate.xyz": null,
"pro-advert.de": null,
"pro-advertising.com": null,
"pro-market.net": null,
"proadsdirect.com": null,
"probannerswap.com": null,
"proffigurufast.com": null,
"promenadd.ru": null,
"promo-reklama.ru": null,
"promoted.com": null,
"promotiontrack.mobi": null,
"propellerads.com": null,
"propellerpops.com": null,
"propelllerads.com": null,
"proximic.com": null,
"prre.ru": null,
"prxio.github.io": null,
"prxio.pw": null,
"prxio.site": null,
"psclicks.com": null,
"ptmopenclose.click": null,
"pubgears.com": null,
"publicidad.net": null,
"publicsunrise.link": null,
"publisheradnetwork.com": null,
"publited.com": null,
"pubmatic.com": null,
"puhtml.com": null,
"pullcdn.top": null,
"pulpyads.com": null,
"pulse360.com": null,
"pulsemgr.com": null,
"pwrads.net": null,
"q1media.com": null,
"q1mediahydraplatform.com": null,
"qadserve.com": null,
"qadservice.com": null,
"qertewrt.com": null,
"qnrzmapdcc.com": null,
"qnsr.com": null,
"quantumads.com": null,
"queenmult.link": null,
"quickcash500.com": null,
"quicktask.xyz": null,
"radiatorial.online": null,
"rateaccept.net": null,
"rcads.net": null,
"reachjunction.com": null,
"readserver.net": null,
"realclick.co.kr": null,
"realmatch.com": null,
"realmedia.com": null,
"recomendedsite.com": null,
"redcourtside.com": null,
"redirectpopads.com": null,
"redstick.online": null,
"reduxmediagroup.com": null,
"relestar.com": null,
"repaynik.com": null,
"replacescript.in": null,
"replase.tk": null,
"requiredcollectfilm.info": null,
"respond-adserver.cloudapp.net": null,
"resultlinks.com": null,
"resultsz.com": null,
"retrayan.com": null,
"revcontent.com": null,
"revresda.com": null,
"revsci.net": null,
"rewardsaffiliates.com": null,
"rfihub.net": null,
"rhythmcontent.com": null,
"rhythmxchange.com": null,
"ric-ric-rum.com": null,
"ricead.com": null,
"richmedia247.com": null,
"richwebmedia.com": null,
"ringtonematcher.com": null,
"ringtonepartner.com": null,
"riowrite.com": null,
"ripplead.com": null,
"rmxads.com": null,
"rogueaffiliatesystem.com": null,
"rotaban.ru": null,
"rotatingad.com": null,
"rotorads.com": null,
"roughted.com": null,
"rovion.com": null,
"roxyaffiliates.com": null,
"rtb-media.me": null,
"rtbmedia.org": null,
"rtbpop.com": null,
"rtbpops.com": null,
"rtk.io": null,
"rubiconproject.com": null,
"ruckusschroederraspberry.com": null,
"rue1mi4.bid": null,
"rummyaffiliates.com": null,
"runadtag.com": null,
"runreproducerow.com": null,
"rvttrack.com": null,
"rwpads.com": null,
"rxthdr.com": null,
"s.adroll.com": null,
"s2d6.com": null,
"safeadnetworkdata.net": null,
"safecllc.com": null,
"sakura-traffic.com": null,
"salesnleads.com": null,
"saltamendors.com": null,
"sape.ru": null,
"saveads.net": null,
"saveads.org": null,
"saymedia.com": null,
"sbaffiliates.com": null,
"sbcpower.com": null,
"scanscout.com": null,
"sceno.ru": null,
"scriptall.cf": null,
"scriptall.ga": null,
"scriptall.gq": null,
"scriptall.tk": null,
"seccoads.com": null,
"secondstreetmedia.com": null,
"securewebsiteaccess.com": null,
"seekads.net": null,
"selectablemedia.com": null,
"seriousfiles.com": null,
"servebom.com": null,
"servedby-buysellads.com": null,
"servedbyopenx.com": null,
"servemeads.com": null,
"sethads.info": null,
"sevenads.net": null,
"sexmoney.com": null,
"share-server.com": null,
"sharecash.org": null,
"sharegods.com": null,
"shareresults.com": null,
"sharethrough.com": null,
"shopalyst.com": null,
"shoppingads.com": null,
"shopzyapp.com": null,
"showyoursite.com": null,
"shqads.com": null,
"siamzone.com": null,
"silence-ads.com": null,
"silstavo.com": null,
"silverads.net": null,
"simvinvo.com": null,
"sirfad.com": null,
"sitebrand.com": null,
"siteencore.com": null,
"sitescout.com": null,
"sitescoutadserver.com": null,
"sitesense-oo.com": null,
"sitethree.com": null,
"sittiad.com": null,
"skimlinks.com": null,
"skoovyads.com": null,
"skyscrpr.com": null,
"skytemjo.link": null,
"skywarts.ru": null,
"slikslik.com": null,
"smaclick.com": null,
"smartad.ee": null,
"smartadserver.com": null,
"smartadtags.com": null,
"smartdevicemedia.com": null,
"smarterdownloads.net": null,
"smartmediarep.com": null,
"smarttds.ru": null,
"smartyads.com": null,
"smilered.com": null,
"smileycentral.com": null,
"smowtion.com": null,
"sms-mmm.com": null,
"snack-media.com": null,
"socialbirth.com": null,
"socialelective.com": null,
"sociallypublish.com": null,
"socialmedia.com": null,
"socialreach.com": null,
"socialspark.com": null,
"softonicads.com": null,
"softpopads.com": null,
"sokitosa.com": null,
"solapoka.com": null,
"solutionzip.info": null,
"sonobi.com": null,
"soosooka.com": null,
"sophiasearch.com": null,
"sotuktraffic.com": null,
"sparkstudios.com": null,
"specificclick.net": null,
"specificmedia.com": null,
"spectato.com": null,
"speedshiftmedia.com": null,
"speedsuccess.net": null,
"spinbox.freedom.com": null,
"splinky.com": null,
"spongecell.com": null,
"spotx.tv": null,
"spotxcdn.com": null,
"spotxchange.com": null,
"sprawley.com": null,
"srtk.net": null,
"srx.com.sg": null,
"sslboost.com": null,
"sta-ads.com": null,
"stabilityappointdaily.xyz": null,
"stackattacka.com": null,
"standartads.com": null,
"star-advertising.com": null,
"stargamesaffiliate.com": null,
"statcamp.net": null,
"statecannoticed.com": null,
"statelead.com": null,
"statesol.net": null,
"staticswind.club": null,
"statsmobi.com": null,
"stealthlockers.com": null,
"stickcoinad.com": null,
"stickyadstv.com": null,
"stirshakead.com": null,
"streamdownloadonline.com": null,
"strikead.com": null,
"struq.com": null,
"sublimemedia.net": null,
"submitexpress.co.uk": null,
"sunmedia.net": null,
"sunrisewebjo.link": null,
"super-links.net": null,
"superadexchange.com": null,
"supersitetime.com": null,
"supprent.com": null,
"supremeadsonline.com": null,
"surf-bar-traffic.com": null,
"surfboarddigital.com.au": null,
"survey-poll.com": null,
"surveyvalue.mobi": null,
"surveyvalue.net": null,
"surveywidget.biz": null,
"sw1block.com": null,
"swadvertising.org": null,
"synerpattern.com": null,
"tacastas.com": null,
"tacoda.net": null,
"tacrater.com": null,
"tagshost.com": null,
"tailsweep.com": null,
"talaropa.com": null,
"tapad.com": null,
"targetadverts.com": null,
"targetnet.com": null,
"tataget.ru": null,
"tattomedia.com": null,
"tbaffiliate.com": null,
"teads.tv": null,
"teambetaffiliates.com": null,
"techclicks.net": null,
"technoratimedia.com": null,
"telemetryverification.net": null,
"telwrite.com": null,
"teracreative.com": null,
"teraxhif.com": null,
"terraclicks.com": null,
"text-link-ads.com": null,
"textonlyads.com": null,
"tgtmedia.com": null,
"thangasoline.com": null,
"thankyouforadvertising.com": null,
"theadgateway.com": null,
"theads.me": null,
"thebannerexchange.com": null,
"thefoxes.ru": null,
"theloungenet.com": null,
"thoseads.com": null,
"thoughtleadr.com": null,
"tidaltv.com": null,
"tinbuadserv.com": null,
"tisadama.com": null,
"tldadserv.com": null,
"tlvmedia.com": null,
"tmpopenclose.click": null,
"tnyzin.ru": null,
"toboads.com": null,
"todich.ru": null,
"tokenads.com": null,
"tollfreeforwarding.com": null,
"tonefuse.com": null,
"tool-site.com": null,
"topad.mobi": null,
"topbananaad.com": null,
"topcasino10.com": null,
"topeuro.biz": null,
"tophotoffers.com": null,
"topqualitylink.com": null,
"torads.me": null,
"torads.xyz": null,
"toroadvertising.com": null,
"toroadvertisingmedia.com": null,
"torrpedoads.net": null,
"tostickad.com": null,
"total-media.net": null,
"totemcash.com": null,
"tpnads.com": null,
"traceadmanager.com": null,
"trackadvertising.net": null,
"trackaffpix.com": null,
"trackcorner.com": null,
"tracking.to": null,
"tracking101.com": null,
"tracking11.com": null,
"trackingoffer.info": null,
"trackingoffer.net": null,
"trackpath.biz": null,
"trackpromotion.net": null,
"trackstarsengland.net": null,
"trackthatad.com": null,
"tracktor.co.uk": null,
"trackword.net": null,
"trackyourlinks.com": null,
"tradeadexchange.com": null,
"tradeexpert.net": null,
"tradepopups.com": null,
"traff-advertazer.com": null,
"traffads.su": null,
"traffic-supremacy.com": null,
"trafficbarads.com": null,
"trafficbee.com": null,
"trafficbroker.com": null,
"trafficfactory.biz": null,
"trafficforce.com": null,
"trafficformoney.com": null,
"traffichaus.com": null,
"trafficjunky.net": null,
"trafficmasterz.net": null,
"trafficmp.com": null,
"trafficposse.com": null,
"trafficrevenue.net": null,
"trafficspaces.net": null,
"trafficswarm.com": null,
"trafficsway.com": null,
"trafficsynergy.com": null,
"traffictrader.net": null,
"trafficular.com": null,
"trafficvance.com": null,
"trafficwave.net": null,
"trafficz.com": null,
"trafficzap.com": null,
"trahic.ru": null,
"trapasol.com": null,
"traveladvertising.com": null,
"travelscream.com": null,
"travidia.com": null,
"trenpyle.com": null,
"triadmedianetwork.com": null,
"tribalfusion.com": null,
"trk4.com": null,
"trombocrack.com": null,
"trtrccl.com": null,
"truesecurejump.com": null,
"truex.com": null,
"ttzmedia.com": null,
"tubberlo.com": null,
"tubemogul.com": null,
"tubereplay.com": null,
"turboadv.com": null,
"turn.com": null,
"tvprocessing.com": null,
"twistads.com": null,
"twittad.com": null,
"twtad.com": null,
"u-ad.info": null,
"ufyvdps3.webcam": null,
"uiadserver.com": null,
"ukbanners.com": null,
"ukulelead.com": null,
"underclick.ru": null,
"underdog.media": null,
"undertone.com": null,
"unicast.com": null,
"unitethecows.com": null,
"unlockr.com": null,
"unrulymedia.com": null,
"unterary.com": null,
"uonj2o6i.loan": null,
"upads.info": null,
"upliftsearch.com": null,
"urlads.net": null,
"urlcash.net": null,
"usbanners.com": null,
"usercash.com": null,
"usswrite.com": null,
"utarget.ru": null,
"utubeconverter.com": null,
"v.movad.de": null,
"v11media.com": null,
"v2mlblack.biz": null,
"validclick.com": null,
"valuead.com": null,
"valueaffiliate.net": null,
"valueclick.com": null,
"valueclick.net": null,
"valueclickmedia.com": null,
"valuecontent.net": null,
"vcmedia.com": null,
"velmedia.net": null,
"venusbux.com": null,
"verata.xyz": null,
"vertamedia.com": null,
"verymuchad.com": null,
"vianadserver.com": null,
"vibrantmedia.com": null,
"video-loader.com": null,
"video1404.info": null,
"videoadex.com": null,
"videoclick.ru": null,
"videodeals.com": null,
"videoegg.com": null,
"videohub.com": null,
"videohube.eu": null,
"videolansoftware.com": null,
"videoliver.com": null,
"videologygroup.com": null,
"videoplaza.com": null,
"videoplaza.tv": null,
"videoroll.net": null,
"videovfr.com": null,
"viedeo2k.tv": null,
"view-ads.de": null,
"viewablemedia.net": null,
"vihub.ru": null,
"vindicosuite.com": null,
"viralmediatech.com": null,
"visiads.com": null,
"visiblegains.com": null,
"visiblemeasures.com": null,
"visitdetails.com": null,
"visitweb.com": null,
"vitalads.net": null,
"vivadgo.ru": null,
"vkoad.com": null,
"vogosita.com": null,
"vogozaw.ru": null,
"vuiads.de": null,
"vuiads.info": null,
"vuiads.net": null,
"w00tads.com": null,
"w00tmedia.net": null,
"w5statistics.info": null,
"w9statistics.info": null,
"wafmedia3.com": null,
"wafmedia5.com": null,
"wafmedia6.com": null,
"waframedia3.com": null,
"waframedia5.com": null,
"waframedia7.com": null,
"waframedia8.com": null,
"wagershare.com": null,
"waploft.cc": null,
"warezlayer.to": null,
"warfacco.com": null,
"wat.freesubdom.com": null,
"watchfree.flv.in": null,
"watchnowlive.eu": null,
"wbptqzmv.com": null,
"wcpanalytics.com": null,
"weadrevenue.com": null,
"web-adservice.com": null,
"webads.co.nz": null,
"webads.nl": null,
"webadvertise123.com": null,
"webeatyouradblocker.com": null,
"webmedia.co.il": null,
"weborama.fr": null,
"webseeds.com": null,
"webtraffic.ttinet.com": null,
"webusersurvey.com": null,
"wegotmedia.com": null,
"whiteboardnez.com": null,
"whoads.net": null,
"widget.yavli.com": null,
"widgetadvertising.biz": null,
"widgetbanner.mobi": null,
"widgetbucks.com": null,
"widgetlead.net": null,
"widgets.fccinteractive.com": null,
"widgetsurvey.biz": null,
"widgetvalue.net": null,
"widgetwidget.mobi": null,
"wigetmedia.com": null,
"wigetstudios.com": null,
"winbuyer.com": null,
"wingads.com": null,
"wmeter.ru": null,
"wmmediacorp.com": null,
"wonclick.com": null,
"wootmedia.net": null,
"wordbankads.com": null,
"worlddatinghere.com": null,
"worthyadvertising.com": null,
"wwwadcntr.com": null,
"wwwp.link": null,
"x.mochiads.com": null,
"xad.com": null,
"xcelsiusadserver.com": null,
"xchangebanners.com": null,
"xdirectx.com": null,
"xeontopa.com": null,
"xfileload.com": null,
"xs.mochiads.com": null,
"xtendadvert.com": null,
"xtendmedia.com": null,
"xxlink.net": null,
"yadomedia.com": null,
"yambotan.ru": null,
"yathmoth.com": null,
"yellads.com": null,
"yesadsrv.com": null,
"yesnexus.com": null,
"yieldads.com": null,
"yieldadvert.com": null,
"yieldkit.com": null,
"yieldmanager.com": null,
"yieldmanager.net": null,
"yieldoptimizer.com": null,
"yldmgrimg.net": null,
"ymads.com": null,
"yoc-adserver.com": null,
"yottacash.com": null,
"youcandoitwithroi.com": null,
"youlamedia.com": null,
"youlouk.com": null,
"your-tornado-file.com": null,
"your-tornado-file.org": null,
"youradexchange.com": null,
"yourfastpaydayloans.com": null,
"yourlegacy.club": null,
"youroffers.win": null,
"yourquickads.com": null,
"youwatchtools.com": null,
"yucce.com": null,
"yuhuads.com": null,
"yumenetworks.com": null,
"yupfiles.club": null,
"yupfiles.net": null,
"yupfiles.org": null,
"z5x.net": null,
"zangocash.com": null,
"zaparena.com": null,
"zeads.com": null,
"zedo.com": null,
"zenoviaexchange.com": null,
"zenoviagroup.com": null,
"zercstas.com": null,
"zeropark.com": null,
"zipropyl.com": null,
"zompmedia.com": null,
"zonealta.com": null,
"zorwrite.com": null,
"04xdqcfz.faith": null,
"098c0f90ca673716316.site": null,
"0mzot44w.site": null,
"107e470d2ace7d8ecc2.stream": null,
"130hc0ja.site": null,
"164f9d1bd2933.party": null,
"1788f63a9a2e67d.date": null,
"1bc169ca9feb0f6a.xyz": null,
"1j7740kd.website": null,
"1ocy2p4n.website": null,
"1wzfew7a.site": null,
"2aahvjeq.website": null,
"2ujo8ayw.racing": null,
"321hlnsb.webcam": null,
"3472ccbc21c3f567.xyz": null,
"39o9mcr2.party": null,
"3ef0cfe35714f932c.trade": null,
"3jsbf5.xyz": null,
"3k4hppja.stream": null,
"3wr110.xyz": null,
"4d28ae0e559c1ba.webcam": null,
"4e9wpp17.stream": null,
"4oz2rj6t.site": null,
"4vaj4jn4.download": null,
"56fh8x.xyz": null,
"57cdb5e39630.racing": null,
"5tcgu99n.loan": null,
"6191bbf7f50444eccca.site": null,
"647a4323fe432956c.trade": null,
"65e107c5ea9e0573.website": null,
"69wnz64h.xyz": null,
"6g3am6pr.website": null,
"6xfcmiy0.science": null,
"707e63f068175.party": null,
"70b008710ae8.racing": null,
"73qbgex1.cricket": null,
"79ebttm6.cricket": null,
"7t69dbtn.science": null,
"7y3bcefa.stream": null,
"80d43327c1673.win": null,
"8hykthze.cricket": null,
"95g804up.download": null,
"970215366f5649.download": null,
"9icmzvn6.website": null,
"9l7y8nel.stream": null,
"a80zha8c.webcam": null,
"aafb1cd4450aa247.website": null,
"ab1eo0rx.stream": null,
"ap76rmx3.accountant": null,
"as1a6nl8.win": null,
"asermtawlfs.xyz": null,
"ayabreya.xyz": null,
"b2530db8a16eaa.download": null,
"b2ce5ba15afd9.party": null,
"b2s1uqa6.download": null,
"b6508157d.website": null,
"b80077a4be3ec4763.trade": null,
"backlogtop.xyz": null,
"brakefluid.website": null,
"busyd5s0.faith": null,
"bw94.xyz": null,
"c03jij5q.website": null,
"c4p69ovw.science": null,
"c50ba364a21f.online": null,
"c9snorwj.website": null,
"cd8iw9mh.cricket": null,
"cdnmedia.xyz": null,
"cg1bz6tf.loan": null,
"ckdegfi5.faith": null,
"clotraiam.website": null,
"cytk85wu.top": null,
"d0z4gwv7.webcam": null,
"dascasdw.xyz": null,
"de56aa68299cfdb.webcam": null,
"dromorama.xyz": null,
"duscb12r.loan": null,
"e0e0e4195bb7.racing": null,
"fg18kvv7.date": null,
"ficusoid.xyz": null,
"flac2flac.xyz": null,
"fugggk3i.accountant": null,
"gjol8ib0.website": null,
"gk25qeyc.xyz": null,
"gkol15n1.stream": null,
"gotjs.xyz": null,
"h166g9ej.download": null,
"havingo.xyz": null,
"i1pnovju.site": null,
"iocawy99.science": null,
"is3eho4w.download": null,
"j2ef76da3.website": null,
"j4y01i3o.win": null,
"j7gvaliq.cricket": null,
"j880iceh.party": null,
"jnrzox5e.website": null,
"jzeu6qlk.accountant": null,
"k9pdlefk.website": null,
"kge1ru01.science": null,
"kgrfw2mp.date": null,
"kkddlt2f.site": null,
"klnrew.site": null,
"ku984o6u.accountant": null,
"kzkjewg7.stream": null,
"lamiflor.xyz": null,
"lostelephants.xyz": null,
"lr48oe5c.website": null,
"lslpv80k.download": null,
"lxpl6t0t.cricket": null,
"mansiontheologysoon.xyz": null,
"mb8e17f12.website": null,
"mc09j2u5.loan": null,
"mosaicolor.website": null,
"oilchange.website": null,
"or3f3xmk.xyz": null,
"panatran.xyz": null,
"pdm8kxw7.website": null,
"peremoga.xyz": null,
"pullapi.site": null,
"q45nsj9d.accountant": null,
"qzgoecv5.win": null,
"r91c6tvs.science": null,
"rkgnmwre.site": null,
"rxlex.faith": null,
"ry0brv6w.science": null,
"s997tc81.loan": null,
"sbsdjgk0.accountant": null,
"sn5wcs89.science": null,
"t2y16t3g.download": null,
"tde2wkyv.stream": null,
"te2e12nd.website": null,
"tpp1ede2.accountant": null,
"txjdgm53.win": null,
"vcxzv.website": null,
"wbkaidsc.webcam": null,
"wmrdwhv3.faith": null,
"wpzka4t6.site": null,
"wshp1rbq.website": null,
"x5qa0pxy.science": null,
"xlw5e582.date": null,
"xmr6v4yg.faith": null,
"y1xjgfhp.racing": null,
"belwrite.com": null,
"cap-cap-pop.com": null,
"catwrite.com": null,
"cold-cold-freezing.com": null,
"data-data-vac.com": null,
"ditwrite.com": null,
"dogwrite.com": null,
"erniphiq.com": null,
"newsadst.com": null,
"parwrite.com": null,
"vacwrite.com": null,
"adbuddiz.com": null,
"adcolony.com": null,
"adiquity.com": null,
"appads.com": null,
"kuad.kusogi.com": null,
"mad-adz.com": null,
"millennialmedia.com": null,
"mobgold.com": null,
"mobizme.net": null,
"mobpartner.mobi": null,
"sascdn.com": null,
"startappexchange.com": null,
"tapjoyads.com": null,
"wapdollar.in": null,
"waptrick.com": null,
"beamkite.com": null,
"brassrule.com": null,
"chiefcurrent.com": null,
"commoncannon.com": null,
"copyrightaccesscontrols.com": null,
"fanaticalfly.com": null,
"foamybox.com": null,
"illustriousoatmeal.com": null,
"loudloss.com": null,
"matchcows.com": null,
"mythimna.com": null,
"ovalpigs.com": null,
"puzzlingfall.com": null,
"roastedvoice.com": null,
"structuresofa.com": null,
"succeedscene.com": null,
"truthfulhead.com": null,
"atresadvertising.com": null,
"acamar.xyz": null,
"achird.xyz": null,
"acubens.xyz": null,
"adhafera.xyz": null,
"aladfar.xyz": null,
"alamak.xyz": null,
"alaraph.xyz": null,
"albaldah.xyz": null,
"albali.xyz": null,
"albireo.xyz": null,
"ads-codes.net": null,
"terraadstools.com": null,
"aadbobwqgmzi.com": null,
"aanvxbvkdxph.com": null,
"aaqpajztftqw.com": null,
"aasopqgmzywa.com": null,
"aatmytrykqhi.com": null,
"acjmkenepeyn.com": null,
"aclsqdpgeaik.com": null,
"acnsavlosahs.com": null,
"acxujxzdluum.com": null,
"adfpkxvaqeyj.com": null,
"adtbomthnsyz.com": null,
"adudzlhdjgof.com": null,
"afbfoxmwzlqa.com": null,
"afdyfxfrwbfy.com": null,
"afedispdljgb.com": null,
"afqwfxkjmgwv.com": null,
"aggntknflhal.com": null,
"agpnzrmptmos.com": null,
"agwsneccrbda.com": null,
"ahkpdnrtjwat.com": null,
"ahwjxktemuyz.com": null,
"ahzybvwdwrhi.com": null,
"aiiaqehoqgrj.com": null,
"aiypulgy.com": null,
"ajaeihzlcwvn.com": null,
"ajgffcat.com": null,
"ajmggjgrardn.com": null,
"ajxftwwmlinv.com": null,
"akoeurmzrqjg.com": null,
"akrzgxzjynpi.com": null,
"akviqfqbwqqj.com": null,
"alasdzdnfvtj.com": null,
"algkebjdgafa.com": null,
"alvivigqrogq.com": null,
"ambqphwf.com": null,
"amhpbhyxfgvd.com": null,
"amnpmitevuxx.com": null,
"amqtbshegbqg.com": null,
"anasjdzutdmv.com": null,
"anluecyopslm.com": null,
"anoufpjmkled.com": null,
"antrtrtyzkhw.com": null,
"anypbbervqig.com": null,
"anyuwksovtwv.com": null,
"aominpzhzhwj.com": null,
"aomvdhxvblfp.com": null,
"aoqviogrwckf.com": null,
"apgjczhgjrka.com": null,
"aqdrzqsuxxvd.com": null,
"aqlvpnfxrkyf.com": null,
"aqornnfwxmua.com": null,
"aqryyhyzjveh.com": null,
"aragvjeosjdx.com": null,
"arawegnvvufy.com": null,
"aryufuxbmwnb.com": null,
"asecxggulyrf.com": null,
"ashwlrtiazee.com": null,
"asqamasz.com": null,
"ataufekxogxr.com": null,
"atcyboopajyp.com": null,
"autkmgrbdlbj.com": null,
"avdfcctzwfdk.com": null,
"avrdpbiwvwyt.com": null,
"avzkjvbaxgqk.com": null,
"awfjqdhcuftd.com": null,
"awgyhiupjzvu.com": null,
"awsatstb.com": null,
"awvrvqxq.com": null,
"axfkfstrbacx.com": null,
"ayjebauqdrys.com": null,
"ayozhcgcsyun.com": null,
"azbdbtsmdocl.com": null,
"azditojzcdkc.com": null,
"azeozrjk.com": null,
"azgyzdjexcxg.com": null,
"azkvcgzjsrmk.com": null,
"azroydhgqcfv.com": null,
"azzvkcavtgwp.com": null,
"bagoojzsqygg.com": null,
"baiaclwdpztd.com": null,
"bajofdblygev.com": null,
"batigfkcbwpb.com": null,
"bayvlsmaahou.com": null,
"bbheuxcancwj.com": null,
"bbjlsdqhpbuqaspgjyxaobmpmzunjnvqmahejnwwvaqbzzqodu.com": null,
"bblznptpffqc.com": null,
"bboemhlddgju.com": null,
"bbopkapcgonb.com": null,
"bdafhnltyxlw.com": null,
"bdozkocgkljj.com": null,
"bdyzewccsqpw.com": null,
"bebufuspldzh.com": null,
"beghfkrygvxp.com": null,
"behjgnhniasz.com": null,
"behybmunweid.com": null,
"bewovdhiubnk.com": null,
"bfhavmgufvhn.com": null,
"bfidvcsuazwy.com": null,
"bgarilrzlgez.com": null,
"bgcsojmtgdrv.com": null,
"bgitczbd.com": null,
"bgpxrwjrbsjb.com": null,
"bguaeoakgmrw.com": null,
"bhejerqgrtlq.com": null,
"bhjhijisulwl.com": null,
"bhmqoolzgxnp.com": null,
"bhyqllgtzjee.com": null,
"bijfzvbtwhvf.com": null,
"bircgizd.com": null,
"bjkfmvhygpub.com": null,
"bjpktmjdxqpl.com": null,
"bjzcyqezwksznxxhscsfcogugkyiupgjhikadadgoiruasxpxo.com": null,
"bkgesylgvrgf.com": null,
"bkmmlcbertdbselmdxpzcuyuilaolxqfhtyukmjkklxphbwsae.com": null,
"bkmtspywevsk.com": null,
"blprkaomvazv.com": null,
"bmjccqfxlabturkmpzzokhsahleqqrysudwpuzqjbxbqeakgnf.com": null,
"bmqnguru.com": null,
"bmubqabepbcb.com": null,
"bmyepmehjzhz.com": null,
"bnkgacehxxmx.com": null,
"bocksnabswdq.com": null,
"bogkmogzrvzf.com": null,
"boguaokxhdsa.com": null,
"bolgooltxygp.com": null,
"bpprksdgogtw.com": null,
"bqptlqmtroto.com": null,
"bqqjowpigdnx.com": null,
"bqytfutmwulr.com": null,
"brqrtgjklary.com": null,
"brtcmjchfyel.com": null,
"brygxppyaugt.com": null,
"bsaixnxcpaai.com": null,
"bsnbfufjgxrb.com": null,
"bspjagxietut.com": null,
"bsupflnjmuzn.com": null,
"btbapoifsphl.com": null,
"btcwkbqojiyg.com": null,
"btkcdqrzmqca.com": null,
"btxoeiisonxh.com": null,
"budyxjttmjkf.com": null,
"bufqrxzyrecf.com": null,
"buitxcrnucyi.com": null,
"bujntrmh.com": null,
"bvezznurwekr.com": null,
"bvobtmbziccr.com": null,
"bvzjhnqrypiv.com": null,
"bwyckpmsolzk.com": null,
"bxoixzbtllwx.com": null,
"byqmzodcdhhu.com": null,
"bzbaizntfrhl.com": null,
"bzfguipyjops.com": null,
"bzgwkxnjqjdz.com": null,
"bzjtjfjteazqzmukjwhyzsaqdtouiopcmtmgdiytfdzboxdann.com": null,
"bzyrhqbdldds.com": null,
"carsxardivaf.com": null,
"cawcwpvmpcje.com": null,
"cbwrwcjdctrj.com": null,
"cbxqceuuwnaz.com": null,
"cbxtnudkklwh.com": null,
"ccbaobjyprxh.com": null,
"ccdkyvyw.com": null,
"ccefzhxgobjm.com": null,
"ccwinenmbnso.com": null,
"cdbkxcnfmehf.com": null,
"cdbxuzzlgfhh.com": null,
"cdhzxcwuibzk.com": null,
"cdicyazp.com": null,
"cdqmeyhqrwinofutpcepbahedusocxqyfokvehqlqpusttfwve.com": null,
"cdrjblrhsuxljwesjholugzxwukkerpobmonocjygnautvzjjm.com": null,
"cdveeechegws.com": null,
"ceseyitsikzs.com": null,
"cewdbisyrzdv.com": null,
"cfdmkifknsjt.com": null,
"cfsdtzggpcmr.com": null,
"cgmkpdqjnedb.com": null,
"chqulqxfghdz.com": null,
"chtpcjezorlo.com": null,
"chvjfriqlvnt.com": null,
"chxfeymgmwbo.com": null,
"chytrrvwvabg.com": null,
"cihnrhqwbcsq.com": null,
"cikzhemgwchl.com": null,
"cixjmaxkemzknxxuyvkbzlhvvgeqmzgopppvefpfkqdraonoez.com": null,
"cjnoeafncyzb.com": null,
"cjnwobsladbq.com": null,
"cjvgnswapbqo.com": null,
"cjxdbmxtnqmy.com": null,
"cjxkzkzmdomd.com": null,
"ckqkwhampiyb.com": null,
"ckqpusmxvilv.com": null,
"ckryzlnafwyd.com": null,
"ckwpsghi.com": null,
"cledghtdrjtb.com": null,
"cmdjujqlfbts.com": null,
"cmdotgwjhpqf.com": null,
"cmpsuzvr.com": null,
"cmqyhtqkhduy.com": null,
"cmrxvyjyaerf.com": null,
"cnfiukuediuy.com": null,
"cnntsmnymvnp.com": null,
"cogxsnvqesph.com": null,
"comgnnyx.com": null,
"cortxphssdvc.com": null,
"cpamnizzierk.com": null,
"cpdoalzgwnwf.com": null,
"cphxwpicozlatvnsospudjhswfxwmykgbihjzvckxvtxzfsgtx.com": null,
"cpkbdmkguggh.com": null,
"cqbabfsyfqse.com": null,
"cqoyvpldkmqt.com": null,
"crkgtnad.com": null,
"croxdfrdjfnt.com": null,
"csbsyukodmga.com": null,
"cscactmkbfvn.com": null,
"csmqorveetie.com": null,
"cstdfxkxbqbc.com": null,
"csyngxtkifrh.com": null,
"ctimfrfrmqip.com": null,
"ctjwmzryhcoj.com": null,
"ctplyvuuzdcv.com": null,
"ctzvtevpcssx.com": null,
"cuguwxkasghy.com": null,
"cwliihvsjckn.com": null,
"cwofongvtbsi.com": null,
"cwtekghutpaq.com": null,
"cwxblalyyvbj.com": null,
"cxgwwsapihlo.com": null,
"cxnxognwkuxm.com": null,
"cxoxruotepqgcvgqxdlwwucgyazmbkhdojqzihljdwwfeylovh.com": null,
"cxrmgoybhyrk.com": null,
"cymuxbcnhinm.com": null,
"cywegkfcrhup.com": null,
"czcbkaptwfmv.com": null,
"czcyppdffuhh.com": null,
"czgeitdowtlv.com": null,
"czoivochvduv.com": null,
"dacqmkmsjajm.com": null,
"daxzupqivdoj.com": null,
"dbjcbnlwchgu.com": null,
"dbojgaxhxalh.com": null,
"dbtaclpoahri.com": null,
"dbwawnzkjniz.com": null,
"dcdalkgtbmip.com": null,
"dcgbswcvywyl.com": null,
"dcmatjqifoim.com": null,
"dcneohtx.com": null,
"dcznhkojghrl.com": null,
"ddprxzxnhzbq.com": null,
"deqrdwsjlpjz.com": null,
"dfcwecvmjtdj.com": null,
"dfujqyjifvoe.com": null,
"dgmlubjidcxc.com": null,
"dgwrxyucxpizivncznkpmdhtrdzyyylpoeitiannqfxmdzpmwx.com": null,
"dhlnlwxspczc.com": null,
"dhmhdiozqbnq.com": null,
"dhomixidnkas.com": null,
"dhsztvyjwcmk.com": null,
"disbkzufvqhk.com": null,
"ditouyldfqgt.com": null,
"diysqcbfyuru.com": null,
"djbnmqdawodm.com": null,
"djntmaplqzbi.com": null,
"djxvususwvso.com": null,
"djzmpsingsrtfsnbnkphyagxdemeagsiabguuqbiqvpupamgej.com": null,
"dkrhsftochvzqryurlptloayhlpftkogvzptcmjlwjgymcfrmv.com": null,
"dmatquyckwtu.com": null,
"dmbjbgiifpfo.com": null,
"dmdcpvgu.com": null,
"dmjcabavsraf.com": null,
"dmojscqlwewu.com": null,
"dmwubqhtuvls.com": null,
"dmyypseympjf.com": null,
"dnqejgrbtlxe.com": null,
"dntlpwpjwcfu.com": null,
"dnxpseduuehm.com": null,
"dobgfkflsnmpaeetycphmcloiijxbvxeyfxgjdlczcuuaxmdzz.com": null,
"dobjgpqzygow.com": null,
"dodwnkpzaned.com": null,
"dohhehsgnxfl.com": null,
"dovltuzibsfs.com": null,
"dpallyihgtgu.com": null,
"dppcevxbshdl.com": null,
"dqpamcouthqv.com": null,
"dqpywdubbxih.com": null,
"drbwugautcgh.com": null,
"drqjihcfdrqj.com": null,
"drtqfejznjnl.com": null,
"dsevjzklcjjb.com": null,
"dsmysdzjhxot.com": null,
"dsnjsdrbqwdu.com": null,
"dswwghrlwwcm.com": null,
"dtmwwpykiqng.com": null,
"dubijsirwtwq.com": null,
"dubzmzpdkddi.com": null,
"duchmcmpmqqu.com": null,
"dulcetcgvcxr.com": null,
"dulpsxaznlwr.com": null,
"dumoyqzxluou.com": null,
"dusgihujnthv.com": null,
"duvyjbofwfqh.com": null,
"duxyrxhfwilv.com": null,
"dvsrlrnpyxwv.com": null,
"dwentymgplvrizqhieugzkozmqjxrxcyxeqdjvcbjmrhnkguwk.com": null,
"dxcqavshmvst.com": null,
"dxfsbkmaydtt.com": null,
"dxigubtmyllj.com": null,
"dxiixnrumvni.com": null,
"dxurtngzawwe.com": null,
"dyazeqpeoykf.com": null,
"dyerbegytfkj.com": null,
"dyjifezeyagm.com": null,
"dyunhvev.com": null,
"dyzstwcqbgjk.com": null,
"dzdfmwaztrrm.com": null,
"eaidabmuxbqy.com": null,
"easnviytengk.com": null,
"ebfjbrlcvjlv.com": null,
"ebspiewapcta.com": null,
"ebyakgowemds.com": null,
"ecmeqhxevxgmtoxubrjstrrlyfgrrtqhvafyagettmwnwkwltn.com": null,
"ectbduztanog.com": null,
"edgsscofljhc.com": null,
"ednnpxhjsqyd.com": null,
"edvbyybaviln.com": null,
"edwywpsufuda.com": null,
"eefbzuwvnnab.com": null,
"eejcqlenlsko.com": null,
"eepuawuevovi.com": null,
"eeqabqioietkquydwxfgvtvpxpzkuilfcpzkplhcckoghwgacb.com": null,
"eerdckbwujcx.com": null,
"efcnevmojvfs.com": null,
"efukznkfmrck.com": null,
"egkkeahdzjqy.com": null,
"egtkhpkkfswf.com": null,
"ehnjtmqchrub.com": null,
"eidzaqzygtvq.com": null,
"eifbewnmtgpi.com": null,
"eiibdnjlautz.com": null,
"eiwcqowbowqo.com": null,
"ejgxyfzciwyi.com": null,
"ejjrckrhigez.com": null,
"ejwmxjttljbe.com": null,
"ekgmjxjyfzzd.com": null,
"ekhgvpsfrwqm.com": null,
"elbeobjhnsvh.com": null,
"elkpxsfzrubq.com": null,
"elxxkpaeudxu.com": null,
"elzlogcphhka.com": null,
"elzmazpsbnwn.com": null,
"emdbszgmxggo.com": null,
"emirdzzvhviv.com": null,
"emrumkgmdmdq.com": null,
"enfhddbnariw.com": null,
"enhwftpkwvnb.com": null,
"eniaypwywduf.com": null,
"enzyxtdcacde.com": null,
"eovkzcueutgf.com": null,
"epernepojkle.com": null,
"epesogtigole.com": null,
"epgooipixbbo.com": null,
"epoxtzgddiwp.com": null,
"epzxtposabej.com": null,
"eqszmuwnozvx.com": null,
"erbsqnmglmnv.com": null,
"erkwkjfompvt.com": null,
"erszwzaidmlc.com": null,
"ervpgpxr.com": null,
"esgwceckxumg.com": null,
"eslgydoqbedo.com": null,
"eslydbnukkme.com": null,
"esnirgskobfj.com": null,
"espnrlezwzvd.com": null,
"etbrjgpsadke.com": null,
"etggiddfdaqd.com": null,
"evhvoeqfrlsb.com": null,
"evlvaulglzpu.com": null,
"ewgtanybkkch.com": null,
"exioptyxiyoo.com": null,
"exnyzdboihvi.com": null,
"eylyitpslpqu.com": null,
"ezbtpdjeimlv.com": null,
"ezemyudhkzvx.com": null,
"ezjrnbpjthir.com": null,
"ezknqsblzmsl.com": null,
"ezuosstmbcle.com": null,
"facsowlaufzk.com": null,
"faoxietqwbmu.com": null,
"farkkbndawtxczozilrrrunxflspkyowishacdueiqzeddsnuu.com": null,
"fbbjlubvwmwd.com": null,
"fcjhxlybaiab.com": null,
"fcjnqpkrdglw.com": null,
"fdepobamndfn.com": null,
"fdogfuqpgeub.com": null,
"fegyacmbobil.com": null,
"fembsflungod.com": null,
"ffanszicnoqs.com": null,
"ffhwzaenzoue.com": null,
"ffpkqjyvvneg.com": null,
"ffwbpadvkcyi.com": null,
"fgkvpyrmkbap.com": null,
"fgmucsiirrsq.com": null,
"fgwsjwiaqtjc.com": null,
"fgzaxilcgxum.com": null,
"fhawywadfjlo.com": null,
"fhylnqzxwsbo.com": null,
"firugsivsqot.com": null,
"fjcvncxrmmru.com": null,
"fjfxpykp.com": null,
"fjvolzrojowa.com": null,
"fkdqrjnoxhch.com": null,
"fkekipafwlqd.com": null,
"fkianrxjfumm.com": null,
"fkjyzxnoxusg.com": null,
"fkrrvhoierty.com": null,
"fluohbiy.com": null,
"flzelfqolfnf.com": null,
"fmuxugcqucuu.com": null,
"fmzxzkgmpmrx.com": null,
"fnaolgfubmlc.com": null,
"fneheruhxqtv.com": null,
"fnjcriccyuna.com": null,
"fokisduu.com": null,
"fpbmjwoebzby.com": null,
"fppupmqbydpk.com": null,
"fpslcnjecewd.com": null,
"fpvfeyjrwlio.com": null,
"fqazjwxovxlu.com": null,
"fqkcdhptlqma.com": null,
"fqmxwckinopg.com": null,
"fqovfxpsytxf.com": null,
"fqpteozo.com": null,
"frczfzikturw.com": null,
"frddujheozns.com": null,
"frdhsmerubfg.com": null,
"frlvfzybstsa.com": null,
"frlzxwxictmg.com": null,
"fsddidfmmzvw.com": null,
"fsvcrapnmmvj.com": null,
"ftgfmbxqkjda.com": null,
"ftjrekbpjkwe.com": null,
"ftodxdoolvdm.com": null,
"ftvkgkkmthed.com": null,
"ftytssqazcqx.com": null,
"fuurqgbfhvqx.com": null,
"fvbeyduylvgy.com": null,
"fvrbloxygbrv.com": null,
"fvwcwbdrprdt.com": null,
"fwcrhzvfxoyi.com": null,
"fwlkncckwcop.com": null,
"fxjgprpozntk.com": null,
"fxjyultd.com": null,
"fxrgikipxnlq.com": null,
"fxtgrttlarkl.com": null,
"fxvxgwqcddvm.com": null,
"fxwkhwcmsqne.com": null,
"fzsiwzxnqadb.com": null,
"fzzudxglrnrr.com": null,
"gaxmdcfkxygs.com": null,
"gazogsjsoxty.com": null,
"gbiwxmjw.com": null,
"gbltotkythfh.com": null,
"gbsxcyukuuex.com": null,
"gbwrjyntqsvr.com": null,
"gcboyhlfqxhc.com": null,
"gdixpvfqbhun.com": null,
"gdpuknsngvps.com": null,
"geazikjazoid.com": null,
"gedmodsxbebd.com": null,
"gefaqjwdgzbo.com": null,
"geqcqduubhll.com": null,
"gerpkshe.com": null,
"ggbfbseakyqv.com": null,
"gggemaop.com": null,
"ggnabmvnwphu.com": null,
"ggngbgccubvf.com": null,
"ggzuksudqktn.com": null,
"ghtroafchzrt.com": null,
"giojhiimnvwr.com": null,
"givmuvbacwui.com": null,
"giyjhogjmfmc.com": null,
"giyupoeynkfx.com": null,
"gjeyqtunbnap.com": null,
"gjxdibyzvczd.com": null,
"gkblyvnioxpd.com": null,
"gkeahnmvduys.com": null,
"gkgdqahkcbmykurmngzrrolrecfqvsjgqdyujvgdrgoezkcobq.com": null,
"gkiryieltcbg.com": null,
"gllkdkxygckb.com": null,
"glnqvqbedbmvtcdzcokrfczopbddhopygrvrnlgmalgvhnsfsc.com": null,
"glslciwwvtxn.com": null,
"gmpdixdh.com": null,
"gmpmuqniggyz.com": null,
"gnadhzstittd.com": null,
"gnipadiiodpa.com": null,
"goacestnzgrd.com": null,
"gofgfsvnfnfw.com": null,
"gojwyansqmcl.com": null,
"gpbznagpormpyusuxbvlpbuejqzwvspcyqjcxbqtbdtlixcgzp.com": null,
"gpgsxlmjnfid.com": null,
"gphfgyrkpumn.com": null,
"gpltrrdffobf.com": null,
"gpnduywxhgme.com": null,
"gqnmautydwky.com": null,
"gqorytmpkjdq.com": null,
"gqthfroeirol.com": null,
"gqulrzprheth.com": null,
"grceweaxhbpvclyxhwuozrbtvqzjgbnzklvxdezzficwjnmfil.com": null,
"grfqrhqlzvjl.com": null,
"gsiqerorqkxu.com": null,
"gtaouarrwypu.com": null,
"gtbfhyprjhqz.com": null,
"gtcpsbvtwaqw.com": null,
"gtevyaeeiged.com": null,
"gtmonytxxglu.com": null,
"gtqfsxrrerzu.com": null,
"gtxfafvoohbc.com": null,
"gubdadtxwqow.com": null,
"guhtjoqtobac.com": null,
"gurrfwsscwda.com": null,
"gverjfuapaag.com": null,
"gvgakxvukmrm.com": null,
"gvoszbzfzmtl.com": null,
"gvrqquiotcyr.com": null,
"gvxobjcxcbkb.com": null,
"gwaatiev.com": null,
"gwcujaprdsen.com": null,
"gwsomeiyywaz.com": null,
"gxdyluyqciac.com": null,
"gxgnvickedxpuiavkgpisnlsphrcyyvkgtordatszlrspkgppe.com": null,
"gxvbogvbcivs.com": null,
"gxxsqeqlepva.com": null,
"gydlzimosfnz.com": null,
"gyinmxpztbgf.com": null,
"gypxbcrmxsmikqbmnlwtezmjotrrdxpqtafumympsdtsfvkkza.com": null,
"gzkoehgbpozz.com": null,
"gzmofmqddajr.com": null,
"gzpqlbqyerpb.com": null,
"gzumjmvqjkki.com": null,
"hafbezbemwwd.com": null,
"haqlmmii.com": null,
"hbbwlhxfnbpq.com": null,
"hbedvoyluzmq.com": null,
"hbrbtmjyvdsy.com": null,
"hbzzkwsuaooc.com": null,
"hcggkyhzxzsv.com": null,
"hclccadfmkpw.com": null,
"hcyxksgsxnzb.com": null,
"hdwlzheftpin.com": null,
"heefwozhlxgz.com": null,
"heracgjcuqmk.com": null,
"hevdxhsfbwud.com": null,
"hffmxndinqyo.com": null,
"hffmzplu.com": null,
"hfgevdzcoocs.com": null,
"hfjuehls.com": null,
"hfmtqgiqscvg.com": null,
"hgbmwkklwittcdkjapnpeikxojivfhgszbxmrjfrvajzhzhuks.com": null,
"hgzopbyhidre.com": null,
"hgztvnjbsrki.com": null,
"hhwqfmqyqoks.com": null,
"higygtvnzxad.com": null,
"hilkfxdqxzac.com": null,
"hjukmfdbryln.com": null,
"hjvdkrjmxngg.com": null,
"hkacgxlpfurb.com": null,
"hkdjrnkjwtqo.com": null,
"hklyzmspvqjh.com": null,
"hkoxlirf.com": null,
"hlekbinpgsuk.com": null,
"hljiofrtqenc.com": null,
"hlotiwnz.com": null,
"hmcjupvbxxyx.com": null,
"hndesrzcgjmprqbbropdulvkfroonnrlbpqxhvprsavhwrfxtv.com": null,
"hnoajsaivjsg.com": null,
"hnqnftzzytjl.com": null,
"hntpbpeiuajc.com": null,
"howjkpaynzwf.com": null,
"hpdmnmehzcor.com": null,
"hpkwirncwvxo.com": null,
"hplgpoicsnea.com": null,
"hpmgdwvvqulp.com": null,
"hpxxzfzdocinivvulcujuhypyrniicjfauortalmjerubjgaja.com": null,
"hqaajpaedpux.com": null,
"hqnyahlpmehp.com": null,
"hqxtsqwpvort.com": null,
"hrkshoveizfo.com": null,
"hrvxpinmdyjx.com": null,
"hsvqfvjidloc.com": null,
"hszyozoawqnk.com": null,
"htllanmhrnjrbestmyabzhyweaccazvuslvadtvutfiqnjyavg.com": null,
"htonrwegnifw.com": null,
"htrprrrtrwrc.com": null,
"huayucnblhgy.com": null,
"hueenmivecmx.com": null,
"huejizictcgd.com": null,
"hutkuzwropgf.com": null,
"huynrscfbulr.com": null,
"huzmweoxlwanzvstlgygbrnfrmodaodqaczzibeplcezmyjnlv.com": null,
"hvfzacisynoq.com": null,
"hvfzshrpfueb.com": null,
"hvukouhckryjudrawwylpboxdsonxhacpodmxvbonqipalsprb.com": null,
"hwfcdqnvovij.com": null,
"hwsbehjaxebh.com": null,
"hwvwuoxsosfp.com": null,
"hxbvbmxv.com": null,
"hxkanryhktub.com": null,
"hxlojjtpqtlk.com": null,
"hxuvwqsecumg.com": null,
"hytkatubjuln.com": null,
"hyubowucvkch.com": null,
"hyvsquazvafrmmmcfpqkabocwpjuabojycniphsmwyhizxgebu.com": null,
"hyzncftkveum.com": null,
"hzskbnafzwsu.com": null,
"hztkbjdkaiwt.com": null,
"hzwxkqnqrdfv.com": null,
"iagsqudxpcfr.com": null,
"iagvkdeienla.com": null,
"ibqmccuuhjqc.com": null,
"icafyriewzzrwxlxhtoeakmwroueywnwhmqmaxsqdntasgfvhc.com": null,
"icjeqbqdzhyx.com": null,
"icpfrrffsenr.com": null,
"iczhhiiowapd.com": null,
"idkyfrsbzesx.com": null,
"idpukwmp.com": null,
"idvuakamkzmx.com": null,
"iectshrhpgsl.com": null,
"ieoexdjxrwtq.com": null,
"ieqprskfariw.com": null,
"ifaklabnhplb.com": null,
"ifvetqzfiawg.com": null,
"igawfxfnupeb.com": null,
"igdfzixkdzxe.com": null,
"iglwibwbjxuoflrczfvpibhihwuqneyvmhzeqbmdmujmirdkae.com": null,
"igupodzh.com": null,
"igyzmhqbihoi.com": null,
"ihdrozswbekx.com": null,
"ihflwxrsptqz.com": null,
"ihgkmgwfhjam.com": null,
"ihqxhokndcfq.com": null,
"ihriduffgkel.com": null,
"iibcejrrfhxh.com": null,
"iijmodcvlwfk.com": null,
"iitfqholnpud.com": null,
"ikealcmavhpk.com": null,
"iknctklddhoh.com": null,
"ikvltjooosqh.com": null,
"ilrxikdjozlk.com": null,
"ilsivrexvpyv.com": null,
"ilvibsabwuza.com": null,
"imbbjywwahev.com": null,
"imgoatxhxior.com": null,
"imqkdsdgfygm.com": null,
"imrwxmau.com": null,
"imtdtaloqwcz.com": null,
"imyqdbxq.com": null,
"inmrjokdxmkh.com": null,
"insbrvwfrcgb.com": null,
"inxhtjrwictg.com": null,
"ioatyggwaypq.com": null,
"iohaqrkjddeq.com": null,
"ioighavxylne.com": null,
"ionbpysfukdh.com": null,
"iqmjedevvojm.com": null,
"iqrqmhrfkyuu.com": null,
"irbkobqlrbtt.com": null,
"irjaeupzarkvwmxonaeslgicvjvgdruvdywmdvuaoyfsjgdzhk.com": null,
"irrttzthsxot.com": null,
"irxpndjg.com": null,
"irzdishtggyo.com": null,
"isbzjaedbdjr.com": null,
"iscaebizkzyd.com": null,
"isdlyvhegxxz.com": null,
"isggimkjabpa.com": null,
"isqgobsgtqsh.com": null,
"itbiwlsxtigx.com": null,
"itevcsjvtcmb.com": null,
"iupqelechcmj.com": null,
"iuymaolvzery.com": null,
"ivkasohqerzl.com": null,
"ivktdwmjhkqy.com": null,
"ivqoqtozlmjp.com": null,
"ivsqnmridfxn.com": null,
"iweacndqhiht.com": null,
"iwmonrwpeeku.com": null,
"iwqugvxozbkd.com": null,
"iwrjczthkkla.com": null,
"ixlsylapsdtr.com": null,
"ixsxgaegvplo.com": null,
"ixzhwyuxxvxb.com": null,
"iydghotpzofn.com": null,
"izhvnderudte.com": null,
"iziwhlafxitn.com": null,
"izixtxrvogaq.com": null,
"iznhvszyizwd.com": null,
"iztsbnkxphnj.com": null,
"izwsvyqv.com": null,
"jahsrhlp.com": null,
"jakzxxzrymhz.com": null,
"jamkkydyiyhx.com": null,
"janrlobmiroi.com": null,
"jatkcmpxhbba.com": null,
"jauftivogtho.com": null,
"jbbgczjipjvb.com": null,
"jbgehhqvfppf.com": null,
"jboovenoenkh.com": null,
"jbvisobwrlcv.com": null,
"jbyksmjmbmku.com": null,
"jcctggmdccmt.com": null,
"jcnoeyqsdfrc.com": null,
"jdlnquri.com": null,
"jdtufqcyumvb.com": null,
"jertwakjcaym.com": null,
"jevijshpvnwm.com": null,
"jeyoxmhhnofdhaalzlfbrsfmezfxqxgwqjkxthzptjdizuyojh.com": null,
"jfaqiomgvajb.com": null,
"jffwwuyychxw.com": null,
"jfribvstvcqy.com": null,
"jgqkrvjtuapt.com": null,
"jgrcggutsilp.com": null,
"jhrmgusalkdu.com": null,
"jhupypvmcsqfqpbxbvumiaatlilzjrzbembarnhyoochsedzvi.com": null,
"jijcetagjfzo.com": null,
"jiyairvjgfqk.com": null,
"jjdrwkistgfh.com": null,
"jjipgxjf.com": null,
"jjpoxurorlsb.com": null,
"jjxsdkphpcwu.com": null,
"jkjoxlhkwnxd.com": null,
"jkkernvkrwdr.com": null,
"jlarmqbypyku.com": null,
"jlflzjdt.com": null,
"jlymmwnkxhph.com": null,
"jmbhyqijqhxk.com": null,
"jmvjmgofvxnu.com": null,
"jmzaqwcmcbui.com": null,
"jncjzdohkgic.com": null,
"jndclagxkvpn.com": null,
"jnercechoqjb.com": null,
"jnxqlltlnezn.com": null,
"jnylpjlnjfsp.com": null,
"jobveibsozms.com": null,
"jogpsoiyngua.com": null,
"joqpatxugyug.com": null,
"jorndvyzchaq.com": null,
"jovepjufhmmw.com": null,
"jpncpftyxliq.com": null,
"jpuiucicqwan.com": null,
"jpwvdpvsmhow.com": null,
"jqibqqxghcfk.com": null,
"jqmcbepfjgks.com": null,
"jqqrcwwd.com": null,
"jrmyhchnfawh.com": null,
"jrtawlpbusyg.com": null,
"jseewggtkfrs.com": null,
"jshjrozmwmyj.com": null,
"jtzlsdmbmfms.com": null,
"juqmlmoclnhe.com": null,
"jusrlkubhjnr.com": null,
"juyfhwxcvzft.com": null,
"jvnvvuveozfi.com": null,
"jvodizomnxtg.com": null,
"jwfdyujffrzt.com": null,
"jwwlyiicjkuh.com": null,
"jwzegfmsgyba.com": null,
"jxvhdyguseaf.com": null,
"jyauuwrrigim.com": null,
"jydbctzvbqrh.com": null,
"jypmcknqvnfd.com": null,
"jzbarlrhbicg.com": null,
"jzbskhgpivyl.com": null,
"jzekquhmaxrk.com": null,
"jzlzdnvvktcf.com": null,
"jzqharwtwqei.com": null,
"kadjwdpzxdxd.com": null,
"karcvrpwayal.com": null,
"karownxatpbd.com": null,
"kayfdraimewk.com": null,
"kayophjgzqdq.com": null,
"kbjddmnkallz.com": null,
"kbrnfzgglehh.com": null,
"kbrwlgzazfnv.com": null,
"kbsceyleonkq.com": null,
"kceikbfhsnet.com": null,
"kdaskxrcgxhp.com": null,
"kdtictjmofbl.com": null,
"kdtstmiptmvk.com": null,
"kdvcvkwwtbwn.com": null,
"kecldktirqzk.com": null,
"keeedoleeroe.com": null,
"keellcvwpzgj.com": null,
"keqnebfovnhl.com": null,
"kfdwywhuissy.com": null,
"kfpwayrztgjj.com": null,
"kfwpyyctzmpk.com": null,
"kgkjlivo.com": null,
"kgvgtudoridc.com": null,
"kgzuerzjysxw.com": null,
"kihhgldtpuho.com": null,
"kjbqzbiteubt.com": null,
"kjjlucebvxtu.com": null,
"kjmddlhlejeh.com": null,
"kjplmlvtdoaf.com": null,
"kjqyvgvvazii.com": null,
"kknvwhcmqoet.com": null,
"kknwvfdzyqzj.com": null,
"klakcdiqmgxq.com": null,
"kldwitfrqwal.com": null,
"klmvharqoxdq.com": null,
"klrdsagmuepg.com": null,
"kmtubsbmwdep.com": null,
"kmveerigfvyy.com": null,
"kmvupiadkzdn.com": null,
"knkxnwscphdk.com": null,
"knslxwqgatnd.com": null,
"konbwfktusra.com": null,
"kovglrrlpqum.com": null,
"kplzvizvsqrh.com": null,
"kpnuqvpevotn.com": null,
"kpsdnlprwclz.com": null,
"kqcflzvunhew.com": null,
"kqgfcumsbtyy.com": null,
"kqmjmrzjhmdn.com": null,
"kqsipdhvcejx.com": null,
"krmuxxubtkrg.com": null,
"krovrhmqgupd.com": null,
"krsdoqvsmgld.com": null,
"krxexwfnghfu.com": null,
"krxpudrzyvko.com": null,
"krziyrrnvjai.com": null,
"ksbklucaxgbf.com": null,
"ktcltsgjcbjdcyrcdaspmwqwscxgbqhscmkpsxarejfsfpohkk.com": null,
"kthdreplfmil.com": null,
"ktjqfqadgmxh.com": null,
"ktrmzzrlkbet.com": null,
"kuavzcushxyd.com": null,
"kuaygqohsbeg.com": null,
"kumekqeccmob.com": null,
"kurtgcwrdakv.com": null,
"kutlvuitevgw.com": null,
"kvadaiwjwxdp.com": null,
"kvpofpkxmlpb.com": null,
"kvrozyibdkkt.com": null,
"kvsyksorguja.com": null,
"kvvvdfimdxnu.com": null,
"kvzvtiswjroe.com": null,
"kwgpddeduvje.com": null,
"kwipnlppnybc.com": null,
"kwjglwybtlhm.com": null,
"kwystoaqjvml.com": null,
"kxareafqwjop.com": null,
"kxdprqrrfhhn.com": null,
"kxtepdregiuo.com": null,
"kyhkyreweusn.com": null,
"kylqpeevrkgh.com": null,
"kyowarob.com": null,
"kyveduvdkbro.com": null,
"kyzhecmvpiaw.com": null,
"kzqrjfulybvv.com": null,
"kzujizavnlxf.com": null,
"kzwddxlpcqww.com": null,
"lazkslkkmtpy.com": null,
"lbfryfttoihl.com": null,
"lbpndcvhuqlm.com": null,
"lbypppwfvagq.com": null,
"lckpubqq.com": null,
"lcpqoewrzuxh.com": null,
"lctpaemybjkv.com": null,
"lcuprkufusba.com": null,
"lcxrhcqouqtw.com": null,
"lcyxmuhxroyo.com": null,
"ldaiuhkayqtu.com": null,
"ldkyzudgbksh.com": null,
"ldyiuvdoahxz.com": null,
"leuojmgbkpcl.com": null,
"lexwdqnzmkdr.com": null,
"lfcnzhcnzded.com": null,
"lfvrjrdrgazl.com": null,
"lgnjcntegeqf.com": null,
"lgthvsytzwtc.com": null,
"lgtnwgfqkyyf.com": null,
"lhaqzqjbafcu.com": null,
"lhekiqlzatfv.com": null,
"lhuqalcxjmtq.com": null,
"liosawitskzd.com": null,
"liqbipkfbafq.com": null,
"lixzmpxjilqp.com": null,
"ljhuvzutnpza.com": null,
"ljngencgbdbn.com": null,
"ljngjrwkyovx.com": null,
"ljzhxfurwibo.com": null,
"lkaarvdprhzx.com": null,
"lkbvfdgqvvpk.com": null,
"lkjmcevfgoxfbyhhmzambtzydolhmeelgkotdllwtfshrkhrev.com": null,
"lkktkgcpqzwd.com": null,
"lkrcapch.com": null,
"lljtgiwhqtue.com": null,
"lmejuamdbtwc.com": null,
"lmjjenhdubpu.com": null,
"lnjpyxvbpyvj.com": null,
"lnnwwxpeodmw.com": null,
"lnzcmgguxlac.com": null,
"loxmetwdjrmh.com": null,
"lpiqwtsuduhh.com": null,
"lplqyocxmify.com": null,
"lppoblhorbrf.com": null,
"lpwvdgfo.com": null,
"lqhnrsfkgcfe.com": null,
"lqlksxbltzxw.com": null,
"lqpkjasgqjve.com": null,
"lrjltdosshhd.com": null,
"lroywnhohfrj.com": null,
"lsegvhvzrpqc.com": null,
"lshwezesshks.com": null,
"lskzcjgerhzn.com": null,
"lsslotuojpud.com": null,
"lstkfdmmxbmv.com": null,
"lttsvesujmry.com": null,
"luhqeqaypvmc.com": null,
"luraclhaunxv.com": null,
"lvlvpdztdnro.com": null,
"lvrvufurxhgp.com": null,
"lwasxldakmhx.com": null,
"lwenrqtarmdx.com": null,
"lwocvazxfnuj.com": null,
"lwqwsptepdxy.com": null,
"lwysswaxnutn.com": null,
"lxkqybzanzug.com": null,
"lyifwfhdizcc.com": null,
"lytpdzqyiygthvxlmgblonknzrctcwsjycmlcczifxbkquknsr.com": null,
"lyzskjigkxwy.com": null,
"lzawbiclvehu.com": null,
"lzbzwpmozwfy.com": null,
"lzmovatu.com": null,
"lzrfxzvfbkay.com": null,
"lzvnaaozpqyb.com": null,
"maboflgkaxqn.com": null,
"mafndqbvdgkm.com": null,
"magwfymjhils.com": null,
"maxgirlgames.com": null,
"maziynjxjdoe.com": null,
"mbajaazbqdzc.com": null,
"mbfvfdkawpoi.com": null,
"mbgvhfotcqsj.com": null,
"mbvmecdlwlts.com": null,
"mcagbtdcwklf.com": null,
"mdeaoowvqxma.com": null,
"mdrkqbsirbry.com": null,
"meagjivconqt.com": null,
"melqdjqiekcv.com": null,
"mepchnbjsrik.com": null,
"mflkgrgxadij.com": null,
"mfmikwfdopmiusbveskwmouxvafvzurvklwyfamxlddexgrtci.com": null,
"mfryftaguwuv.com": null,
"mftbfgcusnzl.com": null,
"mfuebmooizdr.com": null,
"mgrxsztbcfeg.com": null,
"mhaafkoekzax.com": null,
"mhfvtafbraql.com": null,
"mhghzpotwnoh.com": null,
"mhrfhwlqsnzf.com": null,
"mhwxckevqdkx.com": null,
"miadbbnreara.com": null,
"mictxtwtjigs.com": null,
"mizmhwicqhprznhflygfnymqbmvwokewzlmymmvjodqlizwlrf.com": null,
"mjujcjfrgslf.com": null,
"mkceizyfjmmq.com": null,
"mkmxovjaijti.com": null,
"mkpdquuxcnhl.com": null,
"mkyzqyfschwd.com": null,
"mkzynqxqlcxk.com": null,
"mlaxgqosoawc.com": null,
"mlbzafthbtsl.com": null,
"mlgrrqymdsyk.com": null,
"mlkqusrmsfib.com": null,
"mlmjxddzdazr.com": null,
"mlstoxplovkj.com": null,
"mmaigzevcfws.com": null,
"mmcltttqfkbh.com": null,
"mmdcibihoimt.com": null,
"mmdifgneivng.com": null,
"mmeddgjhplqy.com": null,
"mmesheltljyi.com": null,
"mmknsfgqxxsg.com": null,
"mmnridsrreyh.com": null,
"mmojdtejhgeg.com": null,
"mmvcmovwegkz.com": null,
"mnjgoxmx.com": null,
"mnusvlgl.com": null,
"mnyavixcddgx.com": null,
"mnzimonbovqs.com": null,
"moadlbgojatn.com": null,
"mohcafpwpldi.com": null,
"molqvpnnlmnb.com": null,
"mopvkjodhcwscyudzfqtjuwvpzpgzuwndtofzftbtpdfszeido.com": null,
"mosdqxsgjhes.com": null,
"mpoboqvqhjqv.com": null,
"mpytdykvcdsg.com": null,
"mpzuzvqyuvbh.com": null,
"mqcnrhxdsbwr.com": null,
"mqphkzwlartq.com": null,
"mqwkqapsrgnt.com": null,
"mrfveznetjtp.com": null,
"mrkzgpbaapif.com": null,
"mrnbzzwjkusv.com": null,
"mrqsuedzvrrt.com": null,
"msiegurhgfyl.com": null,
"msrwoxdkffcl.com": null,
"mszfmpseoqbu.com": null,
"mtlieuvyoikf.com": null,
"mttyfwtvyumc.com": null,
"mueqzsdabscd.com": null,
"mukxblrkoaaa.com": null,
"munpprwlhric.com": null,
"mvjuhdjuwqtk.com": null,
"mvqinxgp.com": null,
"mwqkpxsrlrus.com": null,
"mxsuikhqaggf.com": null,
"mxtcafifuufp.com": null,
"mzbetmhucxih.com": null,
"mzguykhxnuap.com": null,
"mzkhhjueazkn.com": null,
"nahvyfyfpffm.com": null,
"nawdwtocxqru.com": null,
"nbbljlzbbpck.com": null,
"nbbvpxfxnamb.com": null,
"nbkwnsonadrb.com": null,
"nbmffortfyyg.com": null,
"nbrwtboukesx.com": null,
"nbzionsmbgrt.com": null,
"ncdxfwxijazn.com": null,
"ncspvnslmmbv.com": null,
"ndemlviibdyc.com": null,
"ndgmwuxzxppa.com": null,
"ndkvzncsuxgx.com": null,
"ndndptjtonhh.com": null,
"ndpegjgxzbbv.com": null,
"ndtlcaudedxz.com": null,
"ndxidnvvyvwx.com": null,
"nedmppiilnld.com": null,
"nefczemmdcqi.com": null,
"nefxtwxk.com": null,
"negdrvgo.com": null,
"nfdntqlqrgwc.com": null,
"nfniziqm.com": null,
"nfsqrijauncb.com": null,
"nfxusyviqsnh.com": null,
"ngmckvucrjbnyybvgesxozxcwpgnaljhpedttelavqmpgvfsxg.com": null,
"nguooqblyjrz.com": null,
"nhbklvpswckx.com": null,
"nheanvabodkw.com": null,
"nifyalnngdhb.com": null,
"njcdmsgjbbbz.com": null,
"njjybqyiuotl.com": null,
"nkkreqvurtoh.com": null,
"nklivofyjkbt.com": null,
"nkyngrtleloc.com": null,
"nlfqbfwbfovt.com": null,
"nlljrfvbnisi.com": null,
"nmaafswoiecv.com": null,
"nmayxdwzhaus.com": null,
"nmhhnyqmxgku.com": null,
"nnbestmblotl.com": null,
"nnigsvoorscmgnyobwuhrgnbcgtiicyflrtpwxsekldubasizg.com": null,
"nnjiluslnwli.com": null,
"nnvjigagpwsh.com": null,
"nokswnfvghee.com": null,
"nomlxyhfgeny.com": null,
"noolablkcuyu.com": null,
"npauffnlpgzw.com": null,
"npeanaixbjptsemxrcivetuusaagofdeahtrxofqpxoshduhri.com": null,
"npgdqwtrprfq.com": null,
"npikrbynhuzi.com": null,
"nqlkwyyzzgtn.com": null,
"nrectoqhwdhi.com": null,
"nrgpugas.com": null,
"nryvxfosuiju.com": null,
"nsazelqlavtc.com": null,
"ntndubuzxyfz.com": null,
"ntnlawgchgds.com": null,
"nuayfpthqlkq.com": null,
"nubtjnopbjup.com": null,
"nucqkjkvppgs.com": null,
"nunsbvlzuhyi.com": null,
"nuscutsdqqcc.com": null,
"nushflxucofk.com": null,
"nvajxoahenwe.com": null,
"nvmjtxnlcdqo.com": null,
"nwdufyamroaf.com": null,
"nwfdrxktftep.com": null,
"nwirvhxxcsft.com": null,
"nxcxithvcoeh.com": null,
"nybpurpgexoe.com": null,
"nyqogyaflmln.com": null,
"nzcpdaboaayv.com": null,
"nzxriltfmrpl.com": null,
"oaadkiypttok.com": null,
"oalicqudnfhf.com": null,
"oawleebf.com": null,
"oaxwtgfhsxod.com": null,
"oazojnwqtsaj.com": null,
"obqtccxcfjmd.com": null,
"obthqxbm.com": null,
"obuuyneuhfwf.com": null,
"obvbubmzdvom.com": null,
"obxwnnheaixf.com": null,
"ocipbbphfszy.com": null,
"ocydwjnqasrn.com": null,
"ocyhpouojiss.com": null,
"odomcrqlxulb.com": null,
"odpjcjreznno.com": null,
"odplbueosuzw.com": null,
"odsljzffiixm.com": null,
"odtcspsrhbko.com": null,
"oehjxqhiasrk.com": null,
"oewscpwrvoca.com": null,
"ofajzowbwzzi.com": null,
"ofbqjpaamioq.com": null,
"ofgapiydisrw.com": null,
"ofghrodsrqkg.com": null,
"ofjampfenbwv.com": null,
"ofmuojegzbxo.com": null,
"ogqeedybsojr.com": null,
"ogulzxfxrmow.com": null,
"oguorftbvegb.com": null,
"ohecnqpldvuw.com": null,
"ohmvrqomsitr.com": null,
"oiffrtkdgoef.com": null,
"oipsyfnmrwir.com": null,
"oiramtfxzqfc.com": null,
"ojngisbfwwyp.com": null,
"ojvwpiqnmecd.com": null,
"okasfshomqmg.com": null,
"okbiafbcvoqo.com": null,
"okgfvcourjeb.com": null,
"okmuxdbq.com": null,
"oknmanswftcd.com": null,
"okvmsjyrremu.com": null,
"olctpejrnnfh.com": null,
"olthlikechgq.com": null,
"olwopczjfkng.com": null,
"ompzowzfwwfc.com": null,
"ongkidcasarv.com": null,
"onkcjpgmshqx.com": null,
"oofophdrkjoh.com": null,
"oonenbygymsl.com": null,
"oosdjdhqayjm.com": null,
"oouggjayokzx.com": null,
"ooyhetoodapmrjvffzpmjdqubnpevefsofghrfsvixxcbwtmrj.com": null,
"ophpbseelohv.com": null,
"oppcgcqytazs.com": null,
"opyisszzoyhc.com": null,
"oqmjxcqgdghq.com": null,
"orddiltnmmlu.com": null,
"ormnduxoewtl.com": null,
"orszajhynaqr.com": null,
"orzsaxuicrmr.com": null,
"osbblnlmwzcr.com": null,
"oslzqjnh.com": null,
"ossdqciz.com": null,
"otpyldlrygga.com": null,
"otrfmbluvrde.com": null,
"oubibahphzsz.com": null,
"oubriojtpnps.com": null,
"ougfkbyllars.com": null,
"oulxdvvpmfcd.com": null,
"ovfbwavekglf.com": null,
"ovgzbnjj.com": null,
"ovoczhahelca.com": null,
"ovrdkhamiljt.com": null,
"ovzmelkxgtgf.com": null,
"owihjchxgydd.com": null,
"owlmjcogunzx.com": null,
"owodfrquhqui.com": null,
"owqobhxvaack.com": null,
"owrqvyeyrzhy.com": null,
"owwewfaxvpch.com": null,
"oxanehlscsry.com": null,
"oyrgxjuvsedi.com": null,
"oytrrdlrovcn.com": null,
"oyzsverimywg.com": null,
"ozhwenyohtpb.com": null,
"ozwtmmcdglos.com": null,
"ozymwqsycimr.com": null,
"palzblimzpdk.com": null,
"payrfnvfofeq.com": null,
"pbbutsvpzqza.com": null,
"pbnnsras.com": null,
"pcebrrqydcox.com": null,
"pceqybrdyncq.com": null,
"pdbaewqjyvux.com": null,
"pdzqwzrxlltz.com": null,
"peewuranpdwo.com": null,
"peewuvgdcian.com": null,
"peqdwnztlzjp.com": null,
"pguxoochezkc.com": null,
"pgxciwvwcfof.com": null,
"pifaojvaiofw.com": null,
"piwwplvxvqqi.com": null,
"pixjqfvlsqvu.com": null,
"pjffrqroudcp.com": null,
"pjnrwznmzguc.com": null,
"pjzabhzetdmt.com": null,
"pkklpazhqqda.com": null,
"pkmzxzfazpst.com": null,
"pkougirndckw.com": null,
"pkoyiqjjxhsy.com": null,
"pkqbgjuinhgpizxifssrtqsyxnzjxwozacnxsrxnvkrokysnhb.com": null,
"pktgargbhjmo.com": null,
"plcsedkinoul.com": null,
"plgdhrvzsvxp.com": null,
"plmuxaeyapbqxszavtsljaqvmlsuuvifznvttuuqfcxcbgqdnn.com": null,
"plquutxxewil.com": null,
"plwvwvhudkuv.com": null,
"plyftjxmrxrk.com": null,
"pmgmbpuiblak.com": null,
"pmlcuxqbngrl.com": null,
"pnjeolgxsimj.com": null,
"pnmkuqkonlzj.com": null,
"pnunijdm.com": null,
"pnuymnyhbbuf.com": null,
"poazvacfzbed.com": null,
"popzkvfimbox.com": null,
"ppjjbzcxripw.com": null,
"ppqfteducvts.com": null,
"ppuuwencqopa.com": null,
"ppxrlfhsouac.com": null,
"ppzfvypsurty.com": null,
"pqoznetbeeza.com": null,
"pqwaaocbzrob.com": null,
"praeicwgzapf.com": null,
"prenvifxzjuo.com": null,
"prggimadscvm.com": null,
"prqivgpcjxpp.com": null,
"prwlzpyschwi.com": null,
"pserhnmbbwexmbjderezswultfqlamugbqzsmyxwumgqwxuerl.com": null,
"pshcqtizgdlm.com": null,
"psmlgjalddqu.com": null,
"psrbrytujuxv.com": null,
"ptiqsfrnkmmtvtpucwzsaqonmvaprjafeerwlyhabobuvuazun.com": null,
"ptoflpqqqkdk.com": null,
"ptvjsyfayezb.com": null,
"pugklldkhrfg.com": null,
"punlkhusprgw.com": null,
"puogotzrsvtg.com": null,
"pusbamejpkxq.com": null,
"pvoplkodbxra.com": null,
"pvptwhhkfmog.com": null,
"pvtcntdlcdsb.com": null,
"pwizshlkrpyh.com": null,
"pwynoympqwgg.com": null,
"pxarwmerpavfmomfyjwuuinxaipktnanwlkvbmuldgimposwzm.com": null,
"pxgkuwybzuqz.com": null,
"pxktkwmrribg.com": null,
"pydpcqjenhjx.com": null,
"pzcpotzdkfyn.com": null,
"pzgchrjikhfyueumavkqiccvsdqhdjpljgwhbcobsnjrjfidpq.com": null,
"pzkpyzgqvofi.com": null,
"qadtkdlqlemf.com": null,
"qahajvkyfjpg.com": null,
"qajaohrcbpkd.com": null,
"qarqyhfwient.com": null,
"qazzzxwynmot.com": null,
"qbfvwovkuewm.com": null,
"qclxheddcepf.com": null,
"qdlhprdtwhvgxuzklovisrdbkhptpfarrbcmtrxbzlvhygqisv.com": null,
"qeembhyfvjtq.com": null,
"qekmxaimxkok.com": null,
"qenafbvgmoci.com": null,
"qerlbvqwsqtb.com": null,
"qevivcixnngf.com": null,
"qfhjthejwvgm.com": null,
"qfmbgvgvauvt.com": null,
"qfmcpclzunze.com": null,
"qfrpehkvqtyj.com": null,
"qgraprebabxo.com": null,
"qhqofqeivtno.com": null,
"qijffgqsbkii.com": null,
"qiktwikahncl.com": null,
"qinsmmxvacuh.com": null,
"qiqrguvdhcux.com": null,
"qiremmtynkae.com": null,
"qiurgfxexsmp.com": null,
"qixlpaaeaspr.com": null,
"qjmearsroiyn.com": null,
"qjskosdsxanp.com": null,
"qklhtphiphni.com": null,
"qknuubmfneib.com": null,
"qkpwdakgxynv.com": null,
"qkuprxbmkeqp.com": null,
"qljczwei.com": null,
"qlugrmjsncbe.com": null,
"qmamdjtoykgl.com": null,
"qndqwtrwguhv.com": null,
"qnpolbme.com": null,
"qnqrmqwehcpa.com": null,
"qoiowocphgjm.com": null,
"qolnnepubuyz.com": null,
"qotwtnckqrke.com": null,
"qoxsriddwmqx.com": null,
"qpcyafunjtir.com": null,
"qpiyjprptazz.com": null,
"qqapezviufsh.com": null,
"qqbyfhlctzty.com": null,
"qqvatwaqtzgp.com": null,
"qqylzyrqnewl.com": null,
"qrcsppwzjryh.com": null,
"qregqtqtuisj.com": null,
"qrksjrjppkam.com": null,
"qrozsnmc.com": null,
"qsgiqllpfthg.com": null,
"qtjafpcpmcri.com": null,
"qtsmzrnccnwz.com": null,
"quaizzywzluk.com": null,
"qudpdpkxffzt.com": null,
"qveuxmbhbhmg.com": null,
"qvsbroqoaggw.com": null,
"qwbnzilogwdc.com": null,
"qwhkndqqxxbq.com": null,
"qwqqliynxufj.com": null,
"qwrkigqtgygc.com": null,
"qxbnmdjmymqa.com": null,
"qxnniyuuaxhv.com": null,
"qxxyzmukttyp.com": null,
"qyvpgddwqynp.com": null,
"qzcpotzdkfyn.com": null,
"qzxtbsnaebfw.com": null,
"rbdmtydtobai.com": null,
"rbfxurlfctsz.com": null,
"rbgrlqsepeds.com": null,
"rbppnzuxoatx.com": null,
"rbrbvedkazkr.com": null,
"rbsfglbipyfs.com": null,
"rbuowrinsjsx.com": null,
"rbvfibdsouqz.com": null,
"rbyjirwjbibz.com": null,
"rcjthosmxldl.com": null,
"rcnkflgtxspr.com": null,
"rdikvendxamg.com": null,
"rdlynbosndvx.com": null,
"rdzxpvbveezdkcyustcomuhczsbvteccejkdkfepouuhxpxtmy.com": null,
"reebinbxhlva.com": null,
"rertazmgduxp.com": null,
"rffjopgiuhsx.com": null,
"rffqzbqqmuhaomjpwatukocrykmesssfdhpjuoptovsthbsswd.com": null,
"rfvicvayyfsp.com": null,
"rfyphhvcczyq.com": null,
"rgmgocplioed.com": null,
"rgztepyoefvm.com": null,
"rhfntvnbxfxu.com": null,
"rhfvzboqkjfmabakkxggqdmulrsxmisvuzqijzvysbcgyycwfk.com": null,
"riaetcuycxjz.com": null,
"rifwhwdsqvgw.com": null,
"rihzsedipaqq.com": null,
"rjncckyoyvtu.com": null,
"rjnkpqax.com": null,
"rjpqbishujeu.com": null,
"rjyihkorkewq.com": null,
"rkelvtnnhofl.com": null,
"rklluqchluxg.com": null,
"rkrpvzgzdwqaynyzxkuviotbvibnpqaktcioaaukckhbvkognu.com": null,
"rkvpcjiuumbk.com": null,
"rllvjujeyeuy.com": null,
"rlqvyqgjkxgx.com": null,
"rlypbeouoxxw.com": null,
"rmbilhzcytee.com": null,
"rmdzbqggjskv.com": null,
"rmetgarrpiouttmwqtuajcnzgesgozrihrzwmjlpxvcnmdqath.com": null,
"rmgxhpflxhmd.com": null,
"rmjxcosbfgyl.com": null,
"rmlzgvnuqxlp.com": null,
"rnrbvhaoqzcksxbhgqtrucinodprlsmuvwmaxqhxngkqlsiwwp.com": null,
"rnyuhkbucgun.com": null,
"rpczohkv.com": null,
"rpspeqqiddjm.com": null,
"rpulxcwmnuxi.com": null,
"rqtdnrhjktzr.com": null,
"rrrdddbtofnf.com": null,
"rrscdnsfunoe.com": null,
"rscgfvsximqdpowcmruwitolouncrmnribnfobxzfhrpdmahqe.com": null,
"rsvxipjqyvfs.com": null,
"rtufxsncbegz.com": null,
"rtusxaoxemxy.com": null,
"rtxunghyiwiq.com": null,
"ruovcruc.com": null,
"ruoypiedfpov.com": null,
"ruzttiecdedv.com": null,
"rvoxndszxwmo.com": null,
"rvzudtgpvwxz.com": null,
"rweqvydtzyre.com": null,
"rwtvvdspsbll.com": null,
"rxicrihobtkf.com": null,
"rxisfwvggzot.com": null,
"rxsazdeoypma.com": null,
"rxuqpktyqixa.com": null,
"rylnirfbokjd.com": null,
"rzcmcqljwxyy.com": null,
"sagulzuyvybu.com": null,
"sailznsgbygz.com": null,
"saipuciruuja.com": null,
"sajhiqlcsugy.com": null,
"samlmqljptbd.com": null,
"sapvummffiay.com": null,
"sauispjbeisl.com": null,
"sbftffngpzwt.com": null,
"sbhnftwdlpbo.com": null,
"scbnvzfscfmn.com": null,
"scbywuiojqvh.com": null,
"sceuexzmiwrf.com": null,
"scgyndrujhzf.com": null,
"scmffjmashzc.com": null,
"scuwbelujeeu.com": null,
"scxxbyqjslyp.com": null,
"sdemctwaiazt.com": null,
"sdqspuyipbof.com": null,
"seiqobwpbofg.com": null,
"sfcckxdgfgzo.com": null,
"sfmziexfvvru.com": null,
"sfpkwhncpllt.com": null,
"sfzcbcrwxhic.com": null,
"sgfcsnwegazn.com": null,
"sgzsviqlvcxc.com": null,
"shnmhrlcredd.com": null,
"shnoadlvpylf.com": null,
"silrfbopbobw.com": null,
"siogczwibswm.com": null,
"siwtuvvgraum.com": null,
"sjgklyyyraghhrgimsepycygdqvezppyfjkqddhlzbimoabjae.com": null,
"sjpexaylsfjnopulpgkbqtkzieizcdtslnofpkafsqweztufpa.com": null,
"sjtevvoviqhe.com": null,
"skknyxzaixws.com": null,
"skzhfyqozkic.com": null,
"slmmjkkvbkyp.com": null,
"sloaltbyucrg.com": null,
"smrqvdpgkbvz.com": null,
"sncpizczabhhafkzeifklgonzzkpqgogmnhyeggikzloelmfmd.com": null,
"snetddbbbgbp.com": null,
"snfqpqyecdrb.com": null,
"sngjaetjozyr.com": null,
"snjhhcnr.com": null,
"snpevihwaepwxapnevcpiqxrsewuuonzuslrzrcxqwltupzbwu.com": null,
"sockjgaabayf.com": null,
"soiegibhwvti.com": null,
"sokanffuyinr.com": null,
"sovqylkbucid.com": null,
"spbflxvnheih.com": null,
"spfrlpjmvkmq.com": null,
"sqnezuqjdbhe.com": null,
"sqtsuzrfefwy.com": null,
"srfizvugkheq.com": null,
"sriaqmzx.com": null,
"srizwhcdjruf.com": null,
"srksyzqzcetq.com": null,
"srppykbedhqp.com": null,
"ssdphmfduwcl.com": null,
"ssjhkvwjoovf.com": null,
"ssloemwiszaz.com": null,
"sssjohomoapt.com": null,
"ssvolkkihcyp.com": null,
"stnvgvtwzzrh.com": null,
"sualzmze.com": null,
"sufzmohljbgw.com": null,
"suonvyzivnfy.com": null,
"suwadesdshrg.com": null,
"svapqzplbwjx.com": null,
"svjloaomrher.com": null,
"svnhdfqvhjzn.com": null,
"svrsqqtj.com": null,
"swckuwtoyrklhtccjuuvcstyesxpbmycjogrqkivmmcqqdezld.com": null,
"swgvpkwmojcv.com": null,
"swtwtbiwbjvq.com": null,
"sxlzcvqfeacy.com": null,
"sxprcyzcpqil.com": null,
"sxtzhwvbuflt.com": null,
"sydnkqqscbxc.com": null,
"syorlvhuzgmdqbuxgiulsrusnkgkpvbwmxeqqcboeamyqmyexv.com": null,
"syrnujjldljl.com": null,
"szjgylwamcxo.com": null,
"sznxdqqvjgam.com": null,
"szvzzuffxatb.com": null,
"szyejlnlvnmy.com": null,
"szynlslqxerx.com": null,
"tabeduhsdhlkalelecelxbcwvsfyspwictbszchbbratpojhlb.com": null,
"taelsfdgtmka.com": null,
"tailpdulprkp.com": null,
"tammfmhtfhut.com": null,
"tamqqjgbvbps.com": null,
"taodggarfrmd.com": null,
"tapihmxemcksuvleuzpodsdfubceomxfqayamnsoswxzkijjmw.com": null,
"taqyljgaqsaz.com": null,
"tawgiuioeaovaozwassucoydtrsellartytpikvcjpuwpagwfv.com": null,
"tazvowjqekha.com": null,
"tcdikyjqdmsb.com": null,
"tcgojxmwkkgm.com": null,
"tcyeyccspxod.com": null,
"tedlrouwixqq.com": null,
"tevrhhgzzutw.com": null,
"teyuzyrjmrdi.com": null,
"tfbzzigqzbax.com": null,
"tfqzkesrzttj.com": null,
"tftsbqbeuthh.com": null,
"tgdlekikqbdc.com": null,
"tgijoezvmvvl.com": null,
"tgjdebebaama.com": null,
"tgrmzphjmvem.com": null,
"thnqemehtyfe.com": null,
"thvdzghlvfoh.com": null,
"thxdbyracswy.com": null,
"tienribwjswv.com": null,
"tigzuaivmtgo.com": null,
"tijosnqojfmv.com": null,
"tikwglketskr.com": null,
"tiouqzubepuy.com": null,
"tivlvdeuokwy.com": null,
"tjbgiyek.com": null,
"tjkckpytpnje.com": null,
"tjkenzfnjpfd.com": null,
"tjpzulhghqai.com": null,
"tkarkbzkirlw.com": null,
"tkeeebdseixv.com": null,
"tkfsmiyiozuo.com": null,
"tkoatkkdwyky.com": null,
"tksljtdqkqxh.com": null,
"tljikqcijttf.com": null,
"tlnoffpocjud.com": null,
"tlzhxxfeteeimoonsegagetpulbygiqyfvulvemqnfqnoazccg.com": null,
"tmdcfkxcckvqbqbixszbdyfjgusfzyguvtvvisojtswwvoduhi.com": null,
"tmexywfvjoei.com": null,
"tmfkuesmlpto.com": null,
"tmkbpnkruped.com": null,
"tmmpbkwnzilv.com": null,
"tmwhazsjnhip.com": null,
"tnpbbdrvwwip.com": null,
"totvsaexihbe.com": null,
"tovkhtekzrlu.com": null,
"toyhxqjgqcjo.com": null,
"tpueomljcrvy.com": null,
"tpvprtdclnym.com": null,
"tqdarrhactqc.com": null,
"trcbxjusetvc.com": null,
"trqbzsxnzxmf.com": null,
"tskctmvpwjdb.com": null,
"tsuitufixxlf.com": null,
"tswhwnkcjvxf.com": null,
"ttdaxwrryiou.com": null,
"ttgwyqmuhfhx.com": null,
"tujbidamlfrn.com": null,
"tumfvfvyxusz.com": null,
"turyvfzreolc.com": null,
"tvammzkprvuv.com": null,
"twdksbsyipqa.com": null,
"twjgylzydlhz.com": null,
"twnrkedqefhv.com": null,
"txbvzcyfyyoy.com": null,
"txwnwvhkbtzb.com": null,
"txwzdalmamma.com": null,
"txyxoktogdcy.com": null,
"tyzfzrjaxxcg.com": null,
"tzjngascinro.com": null,
"uavqdzorwish.com": null,
"uaxdkesuxtvu.com": null,
"ubazpxeafwjr.com": null,
"ubhzahnzujqlvecihiyukradtnbmjyjsktsoeagcrbbsfzzrfi.com": null,
"ubopxbdwtnlf.com": null,
"ubxtoqsqusyx.com": null,
"uccgdtmmxota.com": null,
"uckxjsiy.com": null,
"ucptqdmerltn.com": null,
"udbwpgvnalth.com": null,
"udrwyjpwjfeg.com": null,
"udvbtgkxwnap.com": null,
"uebcqdgigsid.com": null,
"uebyotcdyshk.com": null,
"uecjpplzfjur.com": null,
"uerhhgezdrdi.com": null,
"uerladwdpkge.com": null,
"ufmnicckqyru.com": null,
"ufrzvzpympib.com": null,
"ugxyemavfvlolypdqcksmqzorlphjycckszifyknwlfcvxxihx.com": null,
"uhfqrxwlnszw.com": null,
"uilknldyynwm.com": null,
"uipjeyipoumf.com": null,
"ujdctbsbbimb.com": null,
"ujocmihdknwj.com": null,
"ujqafhcsrhyz.com": null,
"ujqbxbcqtbqt.com": null,
"ujtyosgemtnx.com": null,
"ujyyciaedxqr.com": null,
"ukbxppjxfgna.com": null,
"ukffjaqtxhor.com": null,
"ukjzdydnveuc.com": null,
"ukolwxqopahb.com": null,
"ukxeudykhgdi.com": null,
"ulffbcunqnpv.com": null,
"uloywtmpqskx.com": null,
"ulpxnhiugynh.com": null,
"umboffikfkoc.com": null,
"umnsvtykkptl.com": null,
"umqsrvdg.com": null,
"umwsjnsvfzuo.com": null,
"umxzhxfrrkmt.com": null,
"uncumlzowtkn.com": null,
"unffpgtoorpz.com": null,
"unztsvrjofqp.com": null,
"uqgloylf.com": null,
"uqhtuahgfmcx.com": null,
"uqoboyvqsqpy.com": null,
"uqpotqld.com": null,
"uqqgyniatjtf.com": null,
"urbanairship.com": null,
"urpscavikbyv.com": null,
"usoqghurirvz.com": null,
"usymycvrilyt.com": null,
"uszpxpcoflkl.com": null,
"utfffrxmzuvy.com": null,
"utzpjbrtyjuj.com": null,
"uupqrsjbxrstncicwcdlzrcgoycrgurvfbuiraklyimzzyimrq.com": null,
"uuproxhcbcsl.com": null,
"uvakjjlbjrmx.com": null,
"uvffdmlqwmha.com": null,
"uvmsfffedzzw.com": null,
"uvxaafcozjgh.com": null,
"uwnklfxurped.com": null,
"uwpmwpjlxblb.com": null,
"uwrzafoopcyr.com": null,
"uxyofgcf.com": null,
"uyfsqkwhpihm.com": null,
"uyqzlnmdtfpnqskyyvidmllmzauitvaijcgqjldwcwvewjgwfj.com": null,
"uyusewjlkadj.com": null,
"uzbboiydfzog.com": null,
"uzbciwrwzzhs.com": null,
"uzesptwcwwmt.com": null,
"uzqtaxiorsev.com": null,
"uzreuvnlizlz.com": null,
"vacnuuitxqot.com": null,
"vafmypxwomid.com": null,
"vaghwpbslvbu.com": null,
"vagttuyfeuij.com": null,
"vamuglchdpte.com": null,
"vaoajrwmjzxp.com": null,
"vbjvbjertwov.com": null,
"vblunqrovanf.com": null,
"vbupfouyymse.com": null,
"vbuqjdyrsrvi.com": null,
"vbyefnnrswpn.com": null,
"vcwdjbbughuy.com": null,
"vdhmatjdoyqt.com": null,
"vdlvaqsbaiok.com": null,
"vdpyueivvsuc.com": null,
"vdqarbfqauec.com": null,
"vduswjwfcexa.com": null,
"vdvylfkwjpvw.com": null,
"vdyqcdxqvebl.com": null,
"veeqneifeblh.com": null,
"vejlbuixnknc.com": null,
"vfasewomnmco.com": null,
"vfkfctmtgrtq.com": null,
"vfnvsvxlgxbvndhgqqohfgdcfprvxqisiqhclfhdpnjzloctny.com": null,
"vgckzqudqhfr.com": null,
"vgfeahkrzixa.com": null,
"vgmrqurgxlimcawbweuzbvbzxabsfuuxseldfapjmxoboaplmg.com": null,
"vgtnbvzkepbm.com": null,
"vhatpbmitwcn.com": null,
"vhctcywajcwv.com": null,
"vhiaxerjzbqi.com": null,
"vhpqxkhvjgwx.com": null,
"vhwuphctrfil.com": null,
"vicofhozbuaf.com": null,
"viqfxgmgacxv.com": null,
"vivcdctagoij.com": null,
"vivetivcuggz.com": null,
"vizsvhgfkcli.com": null,
"vjrpdagpjwyt.com": null,
"vjzttumdetao.com": null,
"vkarvfrrlhmv.com": null,
"vkdbvgcawubn.com": null,
"vkqfzlpowalv.com": null,
"vlnveqkifcpxdosizybusvjqkfmowoawoshlmcbittpoywblpe.com": null,
"vlrzhoueyoxw.com": null,
"vltvhssjbliy.com": null,
"vlvowhlxxibn.com": null,
"vmcpydzlqfcg.com": null,
"vmvhmwppcsvd.com": null,
"vnadjbcsxfyt.com": null,
"vnhcxditnodg.com": null,
"vnyginzinvmq.com": null,
"vodhaqaujopg.com": null,
"volleqgoafcb.com": null,
"vpfiiojohjch.com": null,
"vpklpmvzbogn.com": null,
"vpsotshujdguwijdiyzyacgwuxgnlucgsrhhhglezlkrpmdfiy.com": null,
"vpwwtzprrkcn.com": null,
"vqaprwkiwset.com": null,
"vqfksrwnxodc.com": null,
"vrqajyuu.com": null,
"vsgherxdcfon.com": null,
"vshsjxfjehju.com": null,
"vtcquvxsaosz.com": null,
"vtoygnkflehv.com": null,
"vtqdavdjsymt.com": null,
"vtqmlzprsunm.com": null,
"vucanmoywief.com": null,
"vulexmouotod.com": null,
"vunwzlxfsogj.com": null,
"vuysooqimdbt.com": null,
"vvgttgprssiy.com": null,
"vwgffbknpgxe.com": null,
"vwugfpktabed.com": null,
"vwxskpufgwww.com": null,
"vxbtrsqjnjpq.com": null,
"vxlpefsjnmws.com": null,
"vxqhchlyijwu.com": null,
"vxuhavco.com": null,
"vxvxsgut.com": null,
"vydlqaxchmij.com": null,
"vyozgtrtyoms.com": null,
"vyrwkkiuzgtu.com": null,
"vywycfxgxqlv.com": null,
"vzhbfwpo.com": null,
"vzmnvqiqgxqk.com": null,
"wabxsybclllz.com": null,
"waentchjzuwq.com": null,
"wafavwthigmc.com": null,
"wafrszmnbshq.com": null,
"watxeoifxbjo.com": null,
"wbqliddtojkf.com": null,
"wbtgtphzivet.com": null,
"wbvsgqtwyvjb.com": null,
"wcgquaaknuha.com": null,
"wcoloqvrhhcf.com": null,
"wdbddckjoguz.com": null,
"wdcxuezpxivqgmecukeirnsyhjpjoqdqfdtchquwyqatlwxtgq.com": null,
"wddtrsuqmqhw.com": null,
"weekwkbulvsy.com": null,
"wehtkuhlwsxy.com": null,
"wephuklsjobdxqllpeklcrvquyyifgkictuepzxxhzpjbclmcq.com": null,
"wepmmzpypfwq.com": null,
"wepzfylndtwu.com": null,
"wfbqjdwwunle.com": null,
"wfiejyjdlbsrkklvxxwkferadhbcwtxrotehopgqppsqwluboc.com": null,
"wgefjuno.com": null,
"wggmaxxawkxu.com": null,
"wggnmbmedlmo.com": null,
"wglbionuopeh.com": null,
"wgulihtuzssn.com": null,
"whgsyczcofwf.com": null,
"whinjxmkugky.com": null,
"whkwbllcctfm.com": null,
"whsjufifuwkw.com": null,
"whsldqctrvuk.com": null,
"whuvrlmzyvzy.com": null,
"whzbmdeypkrb.com": null,
"wicxfvlozsqz.com": null,
"wijczxvihjyu.com": null,
"wiorcewmylbe.com": null,
"wipjyzwavojq.com": null,
"wjdjovjrxsqx.com": null,
"wjnkvhlgvixx.com": null,
"wkexsfmw.com": null,
"wkgaqvvwvqjg.com": null,
"wkggjmkrkvot.com": null,
"wkhychiklhdglppaeynvntkublzecyyymosjkiofraxechigon.com": null,
"wkjcdukkwcvr.com": null,
"wklyhvfc.com": null,
"wljuxryvolwc.com": null,
"wmhksxycucxb.com": null,
"wmjdnluokizo.com": null,
"wmvcxgpdgdkz.com": null,
"wmwkwubufart.com": null,
"wnzxwgatxjuf.com": null,
"wotilhqoftvl.com": null,
"wpktjtwsidcz.com": null,
"wpsyjttctdnt.com": null,
"wpvvlwprfbtm.com": null,
"wqbvqmremvgp.com": null,
"wqgaevqpbwgx.com": null,
"wqnxcthitqpf.com": null,
"wqocynupmbad.com": null,
"wqpcxujvkvhr.com": null,
"wqrwopgkkohk.com": null,
"wqzaloayckal.com": null,
"wqzorzjhvzqf.com": null,
"wrhpnrkdkbqi.com": null,
"wrmcfyzl.com": null,
"wrmwikcnynbk.com": null,
"wrqjwrrpsnnm.com": null,
"wrtnetixxrmg.com": null,
"wsaijhlcnsqu.com": null,
"wscrsmuagezg.com": null,
"wscvmnvhanbr.com": null,
"wsfqmxdljrknkalwskqmefnonnyoqjmeapkmzqwghehedukmuj.com": null,
"wsscyuyclild.com": null,
"wtvyenir.com": null,
"wtxoicsjxbsj.com": null,
"wuldwvzqvqet.com": null,
"wvljugmqpfyd.com": null,
"wvqqugicfuac.com": null,
"wwgdpbvbrublvjfbeunqvkrnvggoeubcfxzdjrgcgbnvgcolbf.com": null,
"wwgjtcge.com": null,
"wwnlyzbedeum.com": null,
"wxdtvssnezam.com": null,
"wxjqyqvagefw.com": null,
"wxonmzkkldhu.com": null,
"wxxfcyoaymug.com": null,
"wydwkpjomckb.com": null,
"wylnauxhkerp.com": null,
"wzadmmddcmml.com": null,
"wzjbvbxldfrn.com": null,
"wzueqhwf.com": null,
"xakmsoaozjgm.com": null,
"xbbcwbsadlrn.com": null,
"xbdlsolradeh.com": null,
"xbynkkqi.com": null,
"xbyvexekkrnt.com": null,
"xcakezoqgkmj.com": null,
"xcjoqraqjwmk.com": null,
"xconeeitqrrq.com": null,
"xcrruqesggzc.com": null,
"xcukrfpchsxn.com": null,
"xdqlnidntqmz.com": null,
"xdurrrklybny.com": null,
"xdwqixeyhvqd.com": null,
"xegavyzkxowj.com": null,
"xewzazxkmzpc.com": null,
"xfgqvqoyzeiu.com": null,
"xgzybmbwfmjd.com": null,
"xhdzcofomosh.com": null,
"xhojlvfznietogsusdiflwvxpkfhixbgdxcnsdshxwdlnhtlih.com": null,
"xhqilhfrfkoecllmthusrpycaogrfivehyymyqkpmxbtomexwl.com": null,
"xhvhisywkvha.com": null,
"xhwqginopocs.com": null,
"xhwtilplkmvbxumaxwmpaqexnwxypcyndhjokwqkxcwbbsclqh.com": null,
"xicuxxferbnn.com": null,
"xihwtdncwtxc.com": null,
"ximeldnjuusl.com": null,
"xirtesuryeqk.com": null,
"xiwhhcyzhtem.com": null,
"xjompsubsozc.com": null,
"xjsqhlfscjxo.com": null,
"xkawgrrrpszb.com": null,
"xkwnadxakuqc.com": null,
"xkygmtrrjalx.com": null,
"xmmnwyxkfcavuqhsoxfrjplodnhzaafbpsojnqjeoofyqallmf.com": null,
"xnuuzwthzaol.com": null,
"xoqwirroygxv.com": null,
"xpkhmrdqhiux.com": null,
"xpnttdct.com": null,
"xqhgisklvxrh.com": null,
"xqopbyfjdqfs.com": null,
"xqzkpmrgcpsw.com": null,
"xrgqermbslvg.com": null,
"xrivpngzagpy.com": null,
"xrqkzdbnybod.com": null,
"xseczkcysdvc.com": null,
"xswnrjbzmdof.com": null,
"xswutjmmznesinsltpkefkjifvchyqiinnorwikatwbqzjelnp.com": null,
"xsztfrlkphqy.com": null,
"xteabvgwersq.com": null,
"xtobxolwcptm.com": null,
"xtqfguvsmroo.com": null,
"xttrofww.com": null,
"xuhktijdskah.com": null,
"xuwptpzdwyaw.com": null,
"xuwxbdafults.com": null,
"xwavjdqttkum.com": null,
"xwmbaxufcdxb.com": null,
"xwwkuacmqblu.com": null,
"xwwsojvluzsb.com": null,
"xxwpminhccoq.com": null,
"xxyafiswqcqz.com": null,
"xxzkqbdibdgq.com": null,
"xycbrnotvcat.com": null,
"xzmqokbeynlv.com": null,
"xztsmbznuwyo.com": null,
"xzwdhymrdxyp.com": null,
"xzzcasiospbn.com": null,
"yaifxxudxyns.com": null,
"yaizwjvnxctz.com": null,
"yamrxfbkpirt.com": null,
"yaoslgiweccw.com": null,
"yaqysxlohdyg.com": null,
"yasltdlichfd.com": null,
"yattprdmuybn.com": null,
"yaxdboxgsbgh.com": null,
"ybhaoglgbgdk.com": null,
"ybzfsppttoaz.com": null,
"ycjwgpkudmve.com": null,
"ycmejutxukkz.com": null,
"ycojhxdobkrd.com": null,
"yctquwjbbkfa.com": null,
"yehazsnxdevr.com": null,
"yepiafsrxffl.com": null,
"yesucplcylxg.com": null,
"yeyddgjqpwya.com": null,
"yfkwqoswbghk.com": null,
"yflpucjkuwvh.com": null,
"yfqlqjpdsckc.com": null,
"yfzcjqpxunsn.com": null,
"ygrtbssc.com": null,
"yhsxsjzyqfoq.com": null,
"yhzobwqqecaa.com": null,
"yiyycuqozjwc.com": null,
"yjjglyoytiew.com": null,
"yjjtxuhfglxa.com": null,
"ykacbmxeapwi.com": null,
"ykbcogkoiqdw.com": null,
"yktkodofnikf.com": null,
"ykuoujjvngtu.com": null,
"ykwdfjergthe.com": null,
"ylhjsrwqtqqb.com": null,
"yljrefexjymy.com": null,
"ylksuifuyryt.com": null,
"ylqezcnlzfsj.com": null,
"ymlbuooxppzt.com": null,
"ynlrfiwj.com": null,
"ynrbxyxmvihoydoduefogolpzgdlpnejalxldwjlnsolmismqd.com": null,
"ynxrrzgfkuih.com": null,
"yojxoefvnyrc.com": null,
"yoqvnnkdmqfk.com": null,
"yoywgmzjgtfl.com": null,
"ypbfrhlgquaj.com": null,
"ypyarwgh.com": null,
"yqjoqncxmufi.com": null,
"yqrsfisvrilz.com": null,
"yqtzhigbiame.com": null,
"yqutkbvrgvar.com": null,
"yrfrvrbmipzb.com": null,
"yrnzxgsjokuv.com": null,
"ysqdjkermxyt.com": null,
"ytapgckhhvou.com": null,
"ytaujxmxxxmm.com": null,
"ytiyuqfxjbke.com": null,
"ytwtqabrkfmu.com": null,
"yupwqyocvvnw.com": null,
"yvvafcqddpmd.com": null,
"ywbfhuofnvuk.com": null,
"ywbpprhlpins.com": null,
"yxahzybkggol.com": null,
"yxbtyzqcczra.com": null,
"yxhyxfyibqhd.com": null,
"yxlibrsxbycm.com": null,
"yxmkiqdvnxsk.com": null,
"yxngmwzubbaa.com": null,
"yyajvvjrcigf.com": null,
"yyuztnlcpiym.com": null,
"yzlwuuzzehjh.com": null,
"yzreywobobmw.com": null,
"yzsiwyvmgftjuqfoejhypwkmdawtwlpvawzewtrrrdfykqhccq.com": null,
"yzygkqjhedpw.com": null,
"zacbwfgqvxan.com": null,
"zamjzpwgekeo.com": null,
"zansceeifcmm.com": null,
"zawvukyxyfmi.com": null,
"zbfncjtaiwngdsrxvykupflpibvbrewhemghxlwsdoluaztwyi.com": null,
"zbrkywjutuxu.com": null,
"zbtqpkimkjcr.com": null,
"zbxzcrldzzgv.com": null,
"zclxwzegqslr.com": null,
"zezowfisdfyn.com": null,
"zfkkmayphqrw.com": null,
"zfmqywrpazlx.com": null,
"zfqpjxuycxdl.com": null,
"zfrzdepuaqebzlenihciadhdjzujnexvnksksqtazbaywgmzwl.com": null,
"zftgljkhrdze.com": null,
"zfwzdrzcasov.com": null,
"zgalejbegahc.com": null,
"zgdejlhmzjrd.com": null,
"zhabyesrdnvn.com": null,
"zhdmplptugiu.com": null,
"zhkziiaajuad.com": null,
"zijnobynjmcs.com": null,
"ziuxkdcgsjhq.com": null,
"zizmvnytmdto.com": null,
"zjgygpdfudfu.com": null,
"zkennongwozs.com": null,
"zkzpfpoazfgq.com": null,
"zlbdtqoayesloeazgxkueqhfzadqjqqduwrufqemhpbrjvwaar.com": null,
"zlvbqseyjdna.com": null,
"zmbrweqglexv.com": null,
"zmnqoymznwng.com": null,
"zmuyirmzujgk.com": null,
"zmxcefuntbgf.com": null,
"zmytwgfd.com": null,
"znmrgzozlohe.com": null,
"znvctmolksaj.com": null,
"zohaqnxwkvyt.com": null,
"zoileyozfexv.com": null,
"zoowknbw.com": null,
"zpctncydojjh.com": null,
"zpkebyxabtsh.com": null,
"zpkobplsfnxf.com": null,
"zpmbsivi.com": null,
"zpnbzxbiqann.com": null,
"zprlpkabqlth.com": null,
"zptncsir.com": null,
"zpxbdukjmcft.com": null,
"zpznbracwdai.com": null,
"zqaxaqqqutrx.com": null,
"zqjfpxcgivkv.com": null,
"zrufclmvlsct.com": null,
"zrxgdnxneslb.com": null,
"zsancthhfvqm.com": null,
"zsihqvjfwwlk.com": null,
"zslembevfypr.com": null,
"ztcysvupksjt.com": null,
"ztfrlktqtcnl.com": null,
"ztioesdyffrr.com": null,
"ztmwkxvvyoao.com": null,
"ztyrgxdelngf.com": null,
"zualhpolssus.com": null,
"zupeaoohmntp.com": null,
"zuuwfrphdgxk.com": null,
"zvqjjurhikku.com": null,
"zvrwttooqgeb.com": null,
"zvttlvbclihk.com": null,
"zvuespzsdgdq.com": null,
"zwcuvwssfydj.com": null,
"zwqfnizwcvbx.com": null,
"zxadziqqayup.com": null,
"zxavxgjcjmkh.com": null,
"zxbjgrxbcgrp.com": null,
"zxqeycvsetkh.com": null,
"zyaorkkdvcbl.com": null,
"zycvyudt.com": null,
"zyfuywrjbxyf.com": null,
"zyleqnzmvupg.com": null,
"zylokfmgrtzv.com": null,
"zyqlfplqdgxu.com": null,
"absilf.link": null,
"absquint.com": null,
"acceletor.net": null,
"accltr.com": null,
"accmndtion.org": null,
"anomiely.com": null,
"baordrid.com": null,
"batarsur.com": null,
"billaruze.net": null,
"blindury.com": null,
"blowwor.link": null,
"boafernd.com": null,
"bridlonz.com": null,
"bridlonz.link": null,
"briduend.com": null,
"bualtwif.com": null,
"buamingh.com": null,
"buandorw.com": null,
"buangkoj.com": null,
"buoalait.com": null,
"casiours.com": null,
"clicksifter.com": null,
"content-4-u.com": null,
"contentolyze.net": null,
"contentr.net": null,
"cuantroy.com": null,
"deuskex.link": null,
"doumantr.com": null,
"duading.link": null,
"duavindr.com": null,
"elepheny.com": null,
"entru.co": null,
"ershgrst.com": null,
"erwgerwt.com": null,
"exernala.com": null,
"fleawier.com": null,
"fruamens.com": null,
"frxle.com": null,
"frxrydv.com": null,
"gerengd.link": null,
"gruadhc.com": null,
"gruanchd.link": null,
"gruandors.net": null,
"holmgard.link": null,
"incotand.com": null,
"inomoang.com": null,
"insiruand.com": null,
"iunbrudy.net": null,
"juarinet.com": null,
"juruasikr.net": null,
"kidasfid.com": null,
"kuamanan.com": null,
"liksuad.com": null,
"liveclik.co": null,
"maningrs.com": null,
"monova.site": null,
"nualoghy.com": null,
"oiurtedh.com": null,
"ootloakr.com": null,
"pferetgf.com": null,
"poaurtor.com": null,
"polephen.com": null,
"puoplord.link": null,
"putkjter.com": null,
"quandrer.link": null,
"qulifiad.com": null,
"qzsccm.com": null,
"reaspans.com": null,
"ruamupr.com": null,
"ruandorg.com": null,
"ruandr.com": null,
"ruandr.link": null,
"ruap-oldr.net": null,
"rugistoto.net": null,
"rugistratuan.com": null,
"shoapinh.com": null,
"suavalds.com": null,
"swualyer.com": null,
"sxrrxa.net": null,
"tersur.link": null,
"thiscdn.com": null,
"thrutime.net": null,
"thsdfrgr.com": null,
"trjhhuhn.com": null,
"trualaid.com": null,
"turanasi.com": null,
"username1.link": null,
"v8bridge.link": null,
"virsualr.com": null,
"vpuoplord.link": null,
"wolopiar.com": null,
"yavli.link": null,
"yuasaghn.com": null,
"yvsystem.com": null,
"ziccardia.com": null,
"07zq44y2tmru.xyz": null,
"104.197.157.168": null,
"104.197.189.189": null,
"104.198.134.30": null,
"104.198.138.230": null,
"104.198.147.108": null,
"104.198.156.187": null,
"130.211.230.53": null,
"360adshost.net": null,
"83nsdjqqo1cau183xz.com": null,
"888games.com": null,
"888poker.com": null,
"ablogica.com": null,
"absoluteclickscom.com": null,
"ad-apac.doubleclick.net": null,
"ad-emea.doubleclick.net": null,
"ad-feeds.com": null,
"ad2games.com": null,
"adfarm.mediaplex.com": null,
"adfclick1.com": null,
"adhome.biz": null,
"ads.sexier.com": null,
"adshell.net": null,
"adshostnet.com": null,
"adsplex.com": null,
"adsupplyads.com": null,
"adtraffic.org": null,
"algocashmaster.com": null,
"algocashmaster.net": null,
"annualinternetsurvey.com": null,
"ar.voicefive.com": null,
"aussiemethod.biz": null,
"baypops.com": null,
"bcvcmedia.com": null,
"becoquin.com": null,
"bighot.ru": null,
"binaryoptionsgame.com": null,
"blinko.es": null,
"blinkogold.es": null,
"blockthis.es": null,
"blogscash.info": null,
"bongacams.com": null,
"casino.betsson.com": null,
"ccebba93.se": null,
"chupapo.ru": null,
"clicksgear.com": null,
"clicksvenue.com": null,
"clickter.net": null,
"clkads.com": null,
"cloudservepoint.com": null,
"cloudsrvtrk.com": null,
"cloudtracked.com": null,
"clpremdo.com": null,
"cm.g.doubleclick.net": null,
"com-online.website": null,
"console-domain.link": null,
"consolepprofile.com": null,
"content-offer-app.site": null,
"content.ad": null,
"contentabc.com": null,
"cpmterra.com": null,
"crazyad.net": null,
"distantstat.com": null,
"dntrx.com": null,
"dojerena.com": null,
"download-performance.com": null,
"downloadthesefile.com": null,
"easydownloadnow.com": null,
"elite-sex-finder.com": null,
"eroanalysis.com": null,
"explorads.com": null,
"ezdownloadpro.info": null,
"fabolele.com": null,
"fieldpprofile.com": null,
"filestube.com": null,
"finance-reporting.org": null,
"findonlinesurveysforcash.com": null,
"firmprotectedlinked.com": null,
"firstclass-download.com": null,
"firstmediahub.com": null,
"getmyads.com": null,
"gofindmedia.net": null,
"goodbookbook.com": null,
"googleads.g.doubleclick.net": null,
"googleme.eu": null,
"greatbranddeals.com": null,
"grouchyaccessoryrockefeller.com": null,
"highcpms.com": null,
"homecareerforyou1.info": null,
"hornygirlsexposed.com": null,
"hotchatdate.com": null,
"hotchatdirect.com": null,
"huluads.info": null,
"ifilez.org": null,
"ilividnewtab.com": null,
"installcdnfile.com": null,
"instanceyou.info": null,
"internalredirect.site": null,
"interner-magaziin.ru": null,
"iwanttodeliver.com": null,
"jdtracker.com": null,
"juiceads.net": null,
"junbi-tracker.com": null,
"landsraad.cc": null,
"letshareus.com": null,
"letzonke.com": null,
"linkmyc.com": null,
"livepromotools.com": null,
"liveyourdreamify.pw": null,
"lokvel.ru": null,
"lustigbanner.com": null,
"media-app.com": null,
"media-serving.com": null,
"mediaseeding.com": null,
"meetgoodgirls.com": null,
"meetsexygirls.org": null,
"millionairesurveys.com": null,
"mobileraffles.com": null,
"moneytec.com": null,
"mxsads.com": null,
"myawesomecash.com": null,
"myrdrcts.com": null,
"mysagagame.com": null,
"nturveev.com": null,
"onhitads.net": null,
"onlinecashmethod.com": null,
"onpato.ru": null,
"open-downloads.net": null,
"openadserving.com": null,
"padsdel.com": null,
"partypills.org": null,
"pixellitomedia.com": null,
"pomofon.ru": null,
"popped.biz": null,
"popsuperbbrands.com": null,
"popunderjs.com": null,
"potpourrichordataoscilloscope.com": null,
"prowlerz.com": null,
"pubads.g.doubleclick.net": null,
"pulseonclick.com": null,
"pureadexchange.com": null,
"quickcash-system.com": null,
"quierest.com": null,
"raoplenort.biz": null,
"ratari.ru": null,
"reallifecam.com": null,
"redirections.site": null,
"retkow.com": null,
"rgadvert.com": null,
"rikhov.ru": null,
"rm-tracker.com": null,
"ronetu.ru": null,
"rubikon6.if.ua": null,
"runslin.com": null,
"serving-sys.com": null,
"sexitnow.com": null,
"singleicejo.link": null,
"singlesexdates.com": null,
"smartwebads.com": null,
"srv-ad.com": null,
"statstrackeronline.com": null,
"surveyend.com": null,
"surveysforgifts.org": null,
"surveyspaid.com": null,
"surveystope.com": null,
"symkashop.ru": null,
"syncedvision.com": null,
"targetctracker.com": null,
"techcloudtrk.com": null,
"technicssurveys.info": null,
"the-binary-trader.biz": null,
"thecloudtrader.com": null,
"thepornsurvey.com": null,
"therewardsurvey.com": null,
"topshelftraffic.com": null,
"torrentcacher.info": null,
"totrack.ru": null,
"tracki112.com": null,
"tracking.sportsbet.": null,
"trafficinvest.com": null,
"trafficshop.com": null,
"traktrafficflow.com": null,
"trend-trader.cc": null,
"trkpointcloud.com": null,
"trw12.com": null,
"turbofileindir.com": null,
"unblocksite.info": null,
"venturead.com": null,
"vgsgaming-ads.com": null,
"voluumtrk.com": null,
"w4statistics.info": null,
"watchformytechstuff.com": null,
"wbsadsdel.com": null,
"wbsadsdel2.com": null,
"webtrackerplus.com": null,
"weliketofuckstrangers.com": null,
"wgpartner.com": null,
"winhugebonus.com": null,
"wonderlandads.com": null,
"xclicks.net": null,
"yieldtraffic.com": null,
"yupiromo.ru": null,
"zeroredirect1.com": null,
"zeroredirect10.com": null,
"zeroredirect9.com": null,
"zonearmour4u.link": null,
"123advertising.nl": null,
"18naked.com": null,
"195.228.74.26": null,
"206.217.206.137": null,
"212.150.34.117": null,
"21sexturycash.com": null,
"247teencash.net": null,
"24smile.org": null,
"24x7adservice.com": null,
"33traffic.com": null,
"4link.it": null,
"76.76.5.113": null,
"777-partner.com": null,
"777-partner.net": null,
"777-partners.com": null,
"777-partners.net": null,
"777partner.com": null,
"777partner.net": null,
"777partners.com": null,
"80.77.113.200": null,
"85.17.210.202": null,
"89.248.172.46": null,
"8ipztcc1.com": null,
"abakys.ru": null,
"abbp1.science": null,
"abbp1.website": null,
"abbp2.website": null,
"acceptableads.pw": null,
"acceptableads.space": null,
"acmexxx.com": null,
"acnescarsx.info": null,
"actionlocker.com": null,
"ad-411.com": null,
"ad-u.com": null,
"ad001.ru": null,
"ad4partners.com": null,
"adnetxchange.com": null,
"adparad.net": null,
"adperiun.com": null,
"adrent.net": null,
"adrevenuerescue.com": null,
"adsbr.info": null,
"adsgangsta.com": null,
"adshostview.com": null,
"adskape.ru": null,
"adspayformy.site": null,
"adspayformymortgage.win": null,
"adswam.com": null,
"adsyst.biz": null,
"adult3dcomics.com": null,
"adultaccessnow.com": null,
"adultadmedia.com": null,
"adultadvertising.net": null,
"adultcamchatfree.com": null,
"adultcamfree.com": null,
"adultcamliveweb.com": null,
"adultcommercial.net": null,
"adultdatingtraffic.com": null,
"adultforce.com": null,
"adultlinkexchange.com": null,
"adultmediabuying.com": null,
"adultmoviegroup.com": null,
"adultoafiliados.com.br": null,
"adultpopunders.com": null,
"adultsense.com": null,
"adultsense.org": null,
"adulttiz.com": null,
"adulttubetraffic.com": null,
"advertiserurl.com": null,
"advertisingsex.com": null,
"advertom.com": null,
"advertrtb.com": null,
"advmaker.ru": null,
"advmania.com": null,
"advprotraffic.com": null,
"advredir.com": null,
"adxregie.com": null,
"aemediatraffic.com": null,
"affiliatewindow.com": null,
"affiliation-int.com": null,
"affiliaxe.com": null,
"affiligay.net": null,
"aipbannerx.com": null,
"aipmedia.com": null,
"alfatraffic.com": null,
"alladultcash.com": null,
"allotraffic.com": null,
"alltheladyz.xyz": null,
"amateurcouplewebcam.com": null,
"amtracking01.com": null,
"amvotes.ru": null,
"antaraimedia.com": null,
"antoball.com": null,
"augrenso.com": null,
"awmpartners.com": null,
"aztecash.com": null,
"basesclick.ru": null,
"bavesinyourface.com": null,
"bcash4you.com": null,
"belamicash.com": null,
"bestcontentservice.top": null,
"bestcontentuse.top": null,
"bgmtracker.com": null,
"biksibo.ru": null,
"black6adv.com": null,
"blossoms.com": null,
"board-books.com": null,
"boinkcash.com": null,
"bookofsex.com": null,
"brothersincash.com": null,
"bumblecash.com": null,
"cam-lolita.net": null,
"cam4flat.com": null,
"camads.net": null,
"camcrush.com": null,
"camdough.com": null,
"camduty.com": null,
"campartner.com": null,
"camplacecash.com": null,
"camprime.com": null,
"campromos.nl": null,
"camsense.com": null,
"camsitecash.com": null,
"camzap.com": null,
"cash-program.com": null,
"cash4movie.com": null,
"cashlayer.com": null,
"cashthat.com": null,
"cashtraff.com": null,
"cdn7.network": null,
"cdn7.rocks": null,
"celeb-ads.com": null,
"celogera.com": null,
"cervicalknowledge.info": null,
"cfcloudcdn.com": null,
"chestyry.com": null,
"citysex.com": null,
"clickganic.com": null,
"clickpapa.com": null,
"clickthruserver.com": null,
"clicktrace.info": null,
"cntrafficpro.com": null,
"codelnet.com": null,
"coldhardcash.com": null,
"cpacoreg.com": null,
"cpl1.ru": null,
"crakbanner.com": null,
"crakcash.com": null,
"creoads.com": null,
"crocoads.com": null,
"crtracklink.com": null,
"cwgads.com": null,
"cyberbidhost.com": null,
"d0main.ru": null,
"d3b3e6340.website": null,
"daffaite.com": null,
"dallavel.com": null,
"danzabucks.com": null,
"darangi.ru": null,
"data-ero-advertising.com": null,
"data-eroadvertising.com": null,
"data.13dc235d.xyz": null,
"datexchanges.net": null,
"dating-adv.com": null,
"datingadnetwork.com": null,
"datingamateurs.com": null,
"datingcensored.com": null,
"datingidol.com": null,
"deecash.com": null,
"demanier.com": null,
"denotyro.com": null,
"depilflash.tv": null,
"desiad.net": null,
"digitaldesire.com": null,
"directadvert.ru": null,
"directchat.tv": null,
"discreetlocalgirls.com": null,
"divascam.com": null,
"dofolo.ru": null,
"dosugcz.biz": null,
"dro4icho.ru": null,
"dvdkinoteatr.com": null,
"eadulttraffic.com": null,
"easy-dating.org": null,
"easyaccess.mobi": null,
"eltepo.ru": null,
"emediawebs.com": null,
"enoratraffic.com": null,
"eragi.ru": null,
"eroadvertising.com": null,
"erosadv.com": null,
"erotikdating.com": null,
"erotizer.info": null,
"escortso.com": null,
"euro-rx.com": null,
"euro4ads.de": null,
"exchangecash.de": null,
"exclusivepussy.com": null,
"exoclickz.com": null,
"exoticads.com": null,
"exsifsi.ru": null,
"eyemedias.com": null,
"facebookofsex.com": null,
"faceporn.com": null,
"fanmalinin.ru": null,
"fapality.com": null,
"feeder.xxx": null,
"fickads.net": null,
"filthads.com": null,
"flashadtools.com": null,
"fleshcash.com": null,
"fleshlightgirls.com": null,
"flirt4free.com": null,
"flirtingsms.com": null,
"fmscash.com": null,
"fncash.com": null,
"fncnet1.com": null,
"freakads.com": null,
"free-porn-vidz.com": null,
"frestime.com": null,
"frivol-ads.com": null,
"frutrun.com": null,
"fuckbook.cm": null,
"fuckbookdating.com": null,
"fuckermedia.com": null,
"fuckyoucash.com": null,
"fuelbuck.com": null,
"funnypickuplinesforgirls.com": null,
"gamblespot.ru": null,
"gamevui24.com": null,
"gayadpros.com": null,
"gayxperience.com": null,
"geofamily.ru": null,
"geoinventory.com": null,
"ggwcash.com": null,
"gl-cash.com": null,
"go2euroshop.com": null,
"goallurl.ru": null,
"goklics.ru": null,
"golderotica.com": null,
"greatcpm.com": null,
"gtsads.com": null,
"hdat.xyz": null,
"helltraffic.com": null,
"hentaibiz.com": null,
"herezera.com": null,
"hhit.xyz": null,
"hickle.link": null,
"hiddenbucks.com": null,
"highnets.com": null,
"hookupbucks.com": null,
"hornymatches.com": null,
"host-go.info": null,
"hostave.net": null,
"hostave2.net": null,
"hostave4.net": null,
"hot-dances.com": null,
"hot-socials.com": null,
"hotsocials.com": null,
"hsmclick.com": null,
"hubtraffic.com": null,
"icetraffic.com": null,
"icqadvert.org": null,
"ictowaz.ru": null,
"ideal-sexe.com": null,
"idolbucks.com": null,
"iheartbucks.com": null,
"ijquery10.com": null,
"ilovecheating.com": null,
"impressionmonster.com": null,
"inheart.ru": null,
"intellichatadult.com": null,
"ipornia.com": null,
"iprofit.cc": null,
"itmcash.com": null,
"itrxx.com": null,
"iwebanalyze.com": null,
"javbucks.com": null,
"jaymancash.com": null,
"joinnowinstantly.com": null,
"joyourself.com": null,
"juicycash.net": null,
"justgetitfaster.com": null,
"justresa.com": null,
"kadam.ru": null,
"kingpinmedia.net": null,
"kliklink.ru": null,
"klocko.link": null,
"kolort.ru": null,
"kuhnivsemisrazu.ru": null,
"kwot.biz": null,
"kxqvnfcg.xyz": null,
"lavantat.com": null,
"lifepromo.biz": null,
"limon.biz": null,
"links-and-traffic.com": null,
"livecam.com": null,
"livejasmin.tv": null,
"liveprivates.com": null,
"livestatisc.com": null,
"livetraf.com": null,
"livexxx.me": null,
"lizads.com": null,
"loa-traffic.com": null,
"loveadverts.com": null,
"lovecam.com.br": null,
"lovercash.com": null,
"lsawards.com": null,
"lugiy.ru": null,
"luvcash.com": null,
"lyubnozo.ru": null,
"madbanner.com": null,
"mahnatka.ru": null,
"makechatcash.com": null,
"mallorcash.com": null,
"markswebcams.com": null,
"masterwanker.com": null,
"matrimoniale3x.ro": null,
"matrix-cash.com": null,
"maxcash.com": null,
"maxiadv.com": null,
"mazetin.ru": null,
"mc-nudes.com": null,
"meccahoo.com": null,
"media-click.ru": null,
"mediagra.com": null,
"mediumpimpin.com": null,
"meetthegame.online": null,
"megoads.eu": null,
"menteret.com": null,
"methodcash.com": null,
"meubonus.com": null,
"millioncash.ru": null,
"mobalives.com": null,
"mobbobr.com": null,
"mobilerevenu.com": null,
"mobred.net": null,
"mobtop.ru": null,
"modelsgonebad.com": null,
"mpmcash.com": null,
"mrskincash.com": null,
"mtree.com": null,
"mxpopad.com": null,
"myadultbanners.com": null,
"mymirror.biz": null,
"myprecisionads.com": null,
"mywebclick.net": null,
"naiadexports.com": null,
"nastydollars.com": null,
"newads.bangbros.com": null,
"newnudecash.com": null,
"newsexbook.com": null,
"nikkiscash.com": null,
"ningme.ru": null,
"niytrusmedia.com": null,
"nonkads.com": null,
"nscash.com": null,
"nsfwads.com": null,
"oconner.biz": null,
"oddads.net": null,
"okeo.ru": null,
"onhercam.com": null,
"onyarysh.ru": null,
"orodi.ru": null,
"outster.com": null,
"owpawuk.ru": null,
"oxcluster.com": null,
"ozon.ru": null,
"ozonru.eu": null,
"p51d20aa4.website": null,
"pardina.ru": null,
"partnercash.com": null,
"partnercash.de": null,
"pcruxm.xyz": null,
"pecash.com": null,
"pennynetwork.com": null,
"philstraffic.com": null,
"pictureturn.com": null,
"plachetde.biz": null,
"plantaosexy.com": null,
"pleasedontslaymy.download": null,
"plugrush.com": null,
"pnads.com": null,
"poonproscash.com": null,
"pop-bazar.net": null,
"popander.biz": null,
"popander.com": null,
"popdown.biz": null,
"poppcheck.de": null,
"popupclick.ru": null,
"popxxx.net": null,
"porn-ad.org": null,
"porn-hitz.com": null,
"porn-site-builder.com": null,
"porn88.net": null,
"porn99.net": null,
"pornattitude.com": null,
"pornconversions.com": null,
"pornearn.com": null,
"pornkings.com": null,
"pornleep.com": null,
"porno-file.ru": null,
"pornoow.com": null,
"porntagged.com": null,
"porntrack.com": null,
"pornworld.online": null,
"premature-ejaculation-causes.org": null,
"privacyprotector.com": null,
"profistats.net": null,
"profitstat.biz": null,
"program3.com": null,
"promo4partners.com": null,
"promotion-campaigns.com": null,
"promotools.biz": null,
"promowebstar.com": null,
"protizer.ru": null,
"prpops.com": null,
"prscripts.com": null,
"ptwebcams.com": null,
"pussyeatingclub.com": null,
"pussyeatingclubcams.com": null,
"putanapartners.com": null,
"quagodex.com": null,
"quexotac.com": null,
"rack-media.com": null,
"rareru.ru": null,
"real2clean.ru": null,
"realdatechat.com": null,
"realitycash.com": null,
"realitytraffic.com": null,
"redcash.net": null,
"redpineapplemedia.com": null,
"reliablebanners.com": null,
"renewads.com": null,
"rexbucks.com": null,
"ripbwing.com": null,
"rivcash.com": null,
"rlogoro.ru": null,
"rmkflouh.com": null,
"robotadserver.com": null,
"royal-cash.com": null,
"rsdisp.ru": null,
"rubanners.com": null,
"rukplaza.com": null,
"rulerclick.com": null,
"rulerclick.ru": null,
"runetki.co": null,
"runetki.com": null,
"russianlovematch.com": null,
"safelinktracker.com": null,
"sancdn.net": null,
"sbs-ad.com": null,
"scenesgirls.com": null,
"secretbehindporn.com": null,
"seekbang.com": null,
"seemybucks.com": null,
"senkinar.com": null,
"sexad.net": null,
"sexdatecash.com": null,
"sexengine.sx": null,
"sexiba.com": null,
"sexlist.com": null,
"sexopages.com": null,
"sexplaycam.com": null,
"sexsearch.com": null,
"sextadate.net": null,
"sextracker.com": null,
"sextubecash.com": null,
"sexvertise.com": null,
"sexy-ch.com": null,
"sexypower.net": null,
"shopping-centres.org": null,
"siccash.com": null,
"sixsigmatraffic.com": null,
"smartbn.ru": null,
"sms-xxx.com": null,
"socialsexnetwork.net": null,
"solutionsadultes.com": null,
"sortow.ru": null,
"spunkycash.com": null,
"squeeder.com": null,
"startede.com": null,
"stat-data.net": null,
"statserv.net": null,
"steamtraffic.com": null,
"sterrencash.nl": null,
"streamateaccess.com": null,
"sunnysmedia.com": null,
"sv2.biz": null,
"sweetmedia.org": null,
"targetingnow.com": null,
"targettrafficmarketing.net": null,
"tarkita.ru": null,
"teasernet.ru": null,
"tech-board.com": null,
"teendestruction.com": null,
"telvanil.ru": null,
"the-adult-company.com": null,
"thepayporn.com": null,
"thesocialsexnetwork.com": null,
"titsbro.net": null,
"titsbro.org": null,
"titsbro.pw": null,
"tizernet.com": null,
"tkhigh.com": null,
"todayssn.com": null,
"toget.ru": null,
"topbucks.com": null,
"torrent-anime.ru": null,
"tossoffads.com": null,
"tostega.ru": null,
"tracelive.ru": null,
"tracker2kss.eu": null,
"trackerodss.eu": null,
"traffbiz.ru": null,
"traffic-in.com": null,
"traffic.ru": null,
"trafficholder.com": null,
"traffichunt.com": null,
"trafficjunky.com": null,
"trafficlearn.com": null,
"trafficpimps.com": null,
"trafficstars.com": null,
"traffictraffickers.com": null,
"trafficundercontrol.com": null,
"traficmax.fr": null,
"transexy.it": null,
"trustedadserver.com": null,
"tubeadnetwork.com": null,
"tubedspots.com": null,
"tufosex.com.br": null,
"twistyscash.com": null,
"ukreggae.ru": null,
"unlimedia.net": null,
"utrehter.com": null,
"verticalaffiliation.com": null,
"video-people.com": null,
"virtuagirlhd.com": null,
"vividcash.com": null,
"vlogexpert.com": null,
"vod-cash.com": null,
"vogopita.com": null,
"vogorana.ru": null,
"vogotita.com": null,
"vogozae.ru": null,
"vsexshop.ru": null,
"wamcash.com": null,
"wantatop.com": null,
"watchmygf.to": null,
"webcambait.com": null,
"webcampromotions.com": null,
"webclickengine.com": null,
"webclickmanager.com": null,
"websitepromoserver.com": null,
"webstats.com.br": null,
"webteaser.ru": null,
"weownthetraffic.com": null,
"weselltraffic.com": null,
"wetpeachcash.com": null,
"whaleads.com": null,
"wifelovers.com": null,
"wildmatch.com": null,
"wisozk.link": null,
"worldsbestcams.com": null,
"x-adservice.com": null,
"x-exchanger.co.uk": null,
"xclickdirect.com": null,
"xfuckbook.com": null,
"xhamstercams.com": null,
"xlovecam.com": null,
"xmediawebs.net": null,
"xpctraffic.com": null,
"xpop.co": null,
"xxxadv.com": null,
"xxxallaccesspass.com": null,
"xxxbannerswap.com": null,
"xxxblackbook.com": null,
"xxxex.com": null,
"xxxlnk.com": null,
"xxxmatch.com": null,
"xxxmyself.com": null,
"xxxnavy.com": null,
"xxxvipporno.com": null,
"xxxwebtraffic.com": null,
"yazcash.com": null,
"yesmessenger.com": null,
"yobihost.com": null,
"yoshatia.com": null,
"your-big.com": null,
"yourdatelink.com": null,
"ypmadserver.com": null,
"yuppads.com": null,
"yx0banners.com": null,
"zenkreka.com": null,
"ziphentai.com": null,
"zog.link": null,
"reporo.net": null,
"abbp1.science.": null,
"abbp1.website.": null,
"adspayformymortgage.win.": null,
"3file.info": null,
"3questionsgetthegirl.com": null,
"adsnero.website": null,
"adultmoda.com": null,
"banners.cams.com": null,
"c4tracking01.com": null,
"cam4tracking.com": null,
"chokertraffic.com": null,
"cstraffic.com": null,
"datoporn.com": null,
"dverser.ru": null,
"easysexdate.com": null,
"everyporn.net": null,
"exgfpunished.com": null,
"fbay.tv": null,
"fox-forden.ru": null,
"fpctraffic2.com": null,
"freecamsexposed.com": null,
"freewebcams.com": null,
"gettraff.com": null,
"globaldating.online": null,
"gothot.org": null,
"hapend.biz": null,
"hkinvy.ru": null,
"isanalyze.com": null,
"kaizentraffic.com": null,
"needlive.com": null,
"pinkberrytube.com": null,
"playgirl.com": null,
"reviewdollars.com": null,
"royalads.net": null,
"sex-journey.com": null,
"sexflirtbook.com": null,
"sexintheuk.com": null,
"socialsex.biz": null,
"socialsex.com": null,
"trackvoluum.com": null,
"turnefo.ru": null,
"voyeurbase.com": null,
"watchmygf.com": null,
"x2porn.eu": null,
"xdtraffic.com": null,
"xmatch.com": null,
"xxxbunker.com": null,
"96.9.176.245": null,
"a.livesportmedia.eu": null,
"a04296f070c0146f314d-0dcad72565cb350972beb3666a86f246.r50.cf5.rackcdn.com": null,
"ad.23blogs.com": null,
"ad.about.co.kr": null,
"ad.accessmediaproductions.com": null,
"ad.aquamediadirect.com": null,
"ad.bitmedia.io": null,
"ad.e-kolay.net": null,
"ad.flux.com": null,
"ad.foxnetworks.com": null,
"ad.ghfusion.com": null,
"ad.icasthq.com": null,
"ad.idgtn.net": null,
"ad.imad.co.kr": null,
"ad.indomp3z.us": null,
"ad.jamba.net": null,
"ad.jokeroo.com": null,
"ad.lijit.com": null,
"ad.linkstorms.com": null,
"ad.livere.co.kr": null,
"ad.mail.ru": null,
"ad.mediabong.net": null,
"ad.mesomorphosis.com": null,
"ad.mygamesol.com": null,
"ad.netcommunities.com": null,
"ad.openmultimedia.biz": null,
"ad.outsidehub.com": null,
"ad.pickple.net": null,
"ad.premiumonlinemedia.com": null,
"ad.proxy.sh": null,
"ad.r.worldssl.net": null,
"ad.rambler.ru": null,
"ad.realmcdn.net": null,
"ad.reklamport.com": null,
"ad.sensismediasmart.com.au": null,
"ad.sharethis.com": null,
"ad.smartclip.net": null,
"ad.spielothek.so": null,
"ad.sponsoreo.com": null,
"ad.valuecalling.com": null,
"ad.vidaroo.com": null,
"ad.winningpartner.com": null,
"ad.wsod.com": null,
"ad.zaman.com.tr": null,
"adingo.jp.eimg.jp": null,
"adn.ebay.com": null,
"ads.dynamicyield.com": null,
"ads.linkedin.com": null,
"ads.mp.mydas.mobi": null,
"ads.tremorhub.com": null,
"adscaspion.appspot.com": null,
"adserv.legitreviews.com": null,
"adsrv.eacdn.com": null,
"adss.dotdo.net": null,
"adstest.zaman.com.tr": null,
"affil.mupromo.com": null,
"affiliate.juno.co.uk": null,
"affiliate.mediatemple.net": null,
"affiliatehub.skybet.com": null,
"affiliateprogram.keywordspy.com": null,
"affiliates-cdn.mozilla.org": null,
"affiliates.allposters.com": null,
"affiliates.bookdepository.co.uk": null,
"affiliates.bookdepository.com": null,
"affiliates.homestead.com": null,
"affiliates.lynda.com": null,
"affiliates.picaboocorp.com": null,
"affiliatesmedia.sbobet.com": null,
"affiliation.filestube.com": null,
"affiliation.fotovista.com": null,
"affutdmedia.com": null,
"afimg.liveperson.com": null,
"airpushmarketing.s3.amazonaws.com": null,
"ais.abacast.com": null,
"ak.imgaft.com": null,
"ak1.imgaft.com": null,
"analytics.disneyinternational.com": null,
"athena-ads.wikia.com": null,
"award.sitekeuring.net": null,
"banner.101xp.com": null,
"banner.3ddownloads.com": null,
"banner.europacasino.com": null,
"banner.telefragged.com": null,
"banner.titancasino.com": null,
"banner.titanpoker.com": null,
"banner2.casino.com": null,
"banners.cfspm.com.au": null,
"banners.ixitools.com": null,
"banners.moreniche.com": null,
"banners.smarttweak.com": null,
"banners.videosz.com": null,
"banners.webmasterplan.com": null,
"beta.down2crazy.com": null,
"bl.wavecdn.de": null,
"blamads-assets.s3.amazonaws.com": null,
"blocks.ginotrack.com": null,
"bluhostedbanners.blucigs.com": null,
"bo-videos.s3.amazonaws.com": null,
"box.anchorfree.net": null,
"c.netu.tv": null,
"cas.clickability.com": null,
"cas.criteo.com": null,
"cash.neweramediaworks.com": null,
"caw.criteo.com": null,
"cdn.adblade.com": null,
"cdn.assets.gorillanation.com": null,
"cdn.offcloud.com": null,
"choices.truste.com": null,
"cjmooter.xcache.kinxcdn.com": null,
"clarity.abacast.com": null,
"click.eyk.net": null,
"clickstrip.6wav.es": null,
"code.popup2m.com": null,
"content.livesportmedia.eu": null,
"content.secondspace.com": null,
"cplayer.blinkx.com": null,
"cpm.amateurcommunity.de": null,
"creatives.inmotionhosting.com": null,
"creatives.summitconnect.co.uk": null,
"d13czkep7ax7nj.cloudfront.net": null,
"d140sbu1b1m3h0.cloudfront.net": null,
"d15565yqt7pv7r.cloudfront.net": null,
"d15gt9gwxw5wu0.cloudfront.net": null,
"d1635hfcvs8ero.cloudfront.net": null,
"d17f2fxw547952.cloudfront.net": null,
"d19972r8wdpby8.cloudfront.net": null,
"d1ade4ciw4bqyc.cloudfront.net": null,
"d1aezk8tun0dhm.cloudfront.net": null,
"d1cl1sqtf3o420.cloudfront.net": null,
"d1d43ayl08oaq2.cloudfront.net": null,
"d1d95giojjkirt.cloudfront.net": null,
"d1ebha2k07asm5.cloudfront.net": null,
"d1ep3cn6qx0l3z.cloudfront.net": null,
"d1ey3fksimezm4.cloudfront.net": null,
"d1fo96xm8fci0r.cloudfront.net": null,
"d1gojtoka5qi10.cloudfront.net": null,
"d1grtyyel8f1mh.cloudfront.net": null,
"d1gyluhoxet66h.cloudfront.net": null,
"d1i9kr6k34lyp.cloudfront.net": null,
"d1k74lgicilrr3.cloudfront.net": null,
"d1noellhv8fksc.cloudfront.net": null,
"d1pcttwib15k25.cloudfront.net": null,
"d1pdpbxj733bb1.cloudfront.net": null,
"d1spb7fplenrp4.cloudfront.net": null,
"d1vbm0eveofcle.cloudfront.net": null,
"d1zgderxoe1a.cloudfront.net": null,
"d21j20wsoewvjq.cloudfront.net": null,
"d23guct4biwna6.cloudfront.net": null,
"d23nyyb6dc29z6.cloudfront.net": null,
"d25ruj6ht8bs1.cloudfront.net": null,
"d25xkbr68qqtcn.cloudfront.net": null,
"d26dzd2k67we08.cloudfront.net": null,
"d26j9bp9bq4uhd.cloudfront.net": null,
"d26wy0pxd3qqpv.cloudfront.net": null,
"d27jt7xr4fq3e8.cloudfront.net": null,
"d287x05ve9a63s.cloudfront.net": null,
"d29r6igjpnoykg.cloudfront.net": null,
"d2anfhdgjxf8s1.cloudfront.net": null,
"d2b2x1ywompm1b.cloudfront.net": null,
"d2b560qq58menv.cloudfront.net": null,
"d2b65ihpmocv7w.cloudfront.net": null,
"d2bgg7rjywcwsy.cloudfront.net": null,
"d2cxkkxhecdzsq.cloudfront.net": null,
"d2d2lbvq8xirbs.cloudfront.net": null,
"d2dxgm96wvaa5j.cloudfront.net": null,
"d2gpgaupalra1d.cloudfront.net": null,
"d2gtlljtkeiyzd.cloudfront.net": null,
"d2gz6iop9uxobu.cloudfront.net": null,
"d2hap2bsh1k9lw.cloudfront.net": null,
"d2hcjk8asp3td7.cloudfront.net": null,
"d2ipklohrie3lo.cloudfront.net": null,
"d2mic0r0bo3i6z.cloudfront.net": null,
"d2mq0uzafv8ytp.cloudfront.net": null,
"d2muzdhs7lpmo0.cloudfront.net": null,
"d2nlytvx51ywh9.cloudfront.net": null,
"d2nz8k4xyoudsx.cloudfront.net": null,
"d2o307dm5mqftz.cloudfront.net": null,
"d2oallm7wrqvmi.cloudfront.net": null,
"d2omcicc3a4zlg.cloudfront.net": null,
"d2pgy8h4i30on1.cloudfront.net": null,
"d2plxos94peuwp.cloudfront.net": null,
"d2qz7ofajpstv5.cloudfront.net": null,
"d2r359adnh3sfn.cloudfront.net": null,
"d2s64zaa9ua7uv.cloudfront.net": null,
"d2szg1g41jt3pq.cloudfront.net": null,
"d2tgev5wuprbqq.cloudfront.net": null,
"d2tnimpzlb191i.cloudfront.net": null,
"d2ubicnllnnszy.cloudfront.net": null,
"d2ue9k1rhsumed.cloudfront.net": null,
"d2v4glj2m8yzg5.cloudfront.net": null,
"d2v9ajh2eysdau.cloudfront.net": null,
"d2vt6q0n0iy66w.cloudfront.net": null,
"d2yhukq7vldf1u.cloudfront.net": null,
"d2z1smm3i01tnr.cloudfront.net": null,
"d31807xkria1x4.cloudfront.net": null,
"d32pxqbknuxsuy.cloudfront.net": null,
"d33f10u0pfpplc.cloudfront.net": null,
"d33otidwg56k90.cloudfront.net": null,
"d34obr29voew8l.cloudfront.net": null,
"d34rdvn2ky3gnm.cloudfront.net": null,
"d37kzqe5knnh6t.cloudfront.net": null,
"d38pxm3dmrdu6d.cloudfront.net": null,
"d38r21vtgndgb1.cloudfront.net": null,
"d39xqloz8t5a6x.cloudfront.net": null,
"d3al52d8cojds7.cloudfront.net": null,
"d3bvcf24wln03d.cloudfront.net": null,
"d3dphmosjk9rot.cloudfront.net": null,
"d3dytsf4vrjn5x.cloudfront.net": null,
"d3f9mcik999dte.cloudfront.net": null,
"d3fzrm6pcer44x.cloudfront.net": null,
"d3irruagotonpp.cloudfront.net": null,
"d3iwjrnl4m67rd.cloudfront.net": null,
"d3lc9zmxv46zr.cloudfront.net": null,
"d3lvr7yuk4uaui.cloudfront.net": null,
"d3lzezfa753mqu.cloudfront.net": null,
"d3m41swuqq4sv5.cloudfront.net": null,
"d3nvrqlo8rj1kw.cloudfront.net": null,
"d3p9ql8flgemg7.cloudfront.net": null,
"d3pkae9owd2lcf.cloudfront.net": null,
"d3q2dpprdsteo.cloudfront.net": null,
"d3qszud4qdthr8.cloudfront.net": null,
"d3t2wca0ou3lqz.cloudfront.net": null,
"d3t9ip55bsuxrf.cloudfront.net": null,
"d3tdefw8pwfkbk.cloudfront.net": null,
"d3vc1nm9xbncz5.cloudfront.net": null,
"d5pvnbpawsaav.cloudfront.net": null,
"d6bdy3eto8fyu.cloudfront.net": null,
"d8qy7md4cj3gz.cloudfront.net": null,
"da5w2k479hyx2.cloudfront.net": null,
"dal9hkyfi0m0n.cloudfront.net": null,
"data.apn.co.nz": null,
"data.neuroxmedia.com": null,
"dbam.dashbida.com": null,
"dcdevtzxo4bb0.cloudfront.net": null,
"ddwht76d9jvfl.cloudfront.net": null,
"deals.buxr.net": null,
"deals.macupdate.com": null,
"delivery-dev.thebloggernetwork.com": null,
"delivery-s3.adswizz.com": null,
"delivery.importantmedia.org": null,
"delivery.thebloggernetwork.com": null,
"dew9ckzjyt2gn.cloudfront.net": null,
"dff7tx5c2qbxc.cloudfront.net": null,
"disy2s34euyqm.cloudfront.net": null,
"dizixdllzznrf.cloudfront.net": null,
"djlf5xdlz7m8m.cloudfront.net": null,
"djr4k68f8n55o.cloudfront.net": null,
"dkd69bwkvrht1.cloudfront.net": null,
"dkdwv3lcby5zi.cloudfront.net": null,
"dl392qndlveq0.cloudfront.net": null,
"dl5v5atodo7gn.cloudfront.net": null,
"dlupv9uqtjlie.cloudfront.net": null,
"dm0acvguygm9h.cloudfront.net": null,
"dm8srf206hien.cloudfront.net": null,
"downloadandsave-a.akamaihd.net": null,
"dp51h10v6ggpa.cloudfront.net": null,
"dpsq2uzakdgqz.cloudfront.net": null,
"dq2tgxnc2knif.cloudfront.net": null,
"dqhi3ea93ztgv.cloudfront.net": null,
"dr3k6qonw2kee.cloudfront.net": null,
"dr8pk6ovub897.cloudfront.net": null,
"drf8e429z5jzt.cloudfront.net": null,
"dsh7ky7308k4b.cloudfront.net": null,
"dtrk.slimcdn.com": null,
"du2uh7rq0r0d3.cloudfront.net": null,
"duct5ntjian71.cloudfront.net": null,
"dvf2u7vwmkr5w.cloudfront.net": null,
"dvnafl0qtqz9k.cloudfront.net": null,
"dvt4pepo9om3r.cloudfront.net": null,
"dx5qvhwg92mjd.cloudfront.net": null,
"dxq6c0tx3v6mm.cloudfront.net": null,
"dxqd86uz345mg.cloudfront.net": null,
"dy48bnzanqw0v.cloudfront.net": null,
"dycpc40hvg4ki.cloudfront.net": null,
"dyl3p6so5yozo.cloudfront.net": null,
"engine.gamerati.net": null,
"epowernetworktrackerimages.s3.amazonaws.com": null,
"escape.insites.eu": null,
"euwidget.imshopping.com": null,
"events.kalooga.com": null,
"explorer.sheknows.com": null,
"fatads.toldya.com": null,
"feeds.logicbuy.com": null,
"fileloadr.com": null,
"fileserver.mode.com": null,
"fimserve.myspace.com": null,
"flagship.asp-host.co.uk": null,
"freewheel.mtgx.tv": null,
"gateways.s3.amazonaws.com": null,
"geobanner.friendfinder.com": null,
"geobanner.passion.com": null,
"get.box24casino.com": null,
"get.rubyroyal.com": null,
"get.slotocash.com": null,
"gfaf-banners.s3.amazonaws.com": null,
"gfxa.sheetmusicplus.com": null,
"homad-global-configs.schneevonmorgen.com": null,
"hosting.conduit.com": null,
"hotlinking.dosmil.imap.cc": null,
"ilapi.ebay.com": null,
"im.ov.yahoo.co.jp": null,
"images.criteo.net": null,
"images.dreamhost.com": null,
"images.mylot.com": null,
"img.bluehost.com": null,
"img.hostmonster.com": null,
"img.mybet.com": null,
"img.promoddl.com": null,
"img.servint.net": null,
"imgpop.googlecode.com": null,
"indieclick.3janecdn.com": null,
"interstitial.glsp.netdna-cdn.com": null,
"karma.mdpcdn.com": null,
"kbnetworkz.s3.amazonaws.com": null,
"lapi.ebay.com": null,
"leaddyno-client-images.s3.amazonaws.com": null,
"link.link.ru": null,
"lp.ncdownloader.com": null,
"madisonlogic.com": null,
"mads.aol.com": null,
"maximainvest.net": null,
"media-toolbar.com": null,
"media.netrefer.com": null,
"media.onlineteachers.co.in": null,
"medrx.telstra.com.au": null,
"mobilemetrics.appspot.com": null,
"mozo-widgets.f2.com.au": null,
"mt.sellingrealestatemalta.com": null,
"mto.mediatakeout.com": null,
"news-whistleout.s3.amazonaws.com": null,
"novadune.com": null,
"numb.hotshare.biz": null,
"oas.luxweb.com": null,
"on.maxspeedcdn.com": null,
"ox-i.cordillera.tv": null,
"pagead2.googlesyndication.com": null,
"partner.alloy.com": null,
"partner.bargaindomains.com": null,
"partner.catchy.com": null,
"partner.e-conomic.com": null,
"partner.premiumdomains.com": null,
"partners.autotrader.co.uk": null,
"partners.betus.com": null,
"partners.fshealth.com": null,
"partners.optiontide.com": null,
"partners.rochen.com": null,
"partners.sportingbet.com.au": null,
"partners.vouchedfor.co.uk": null,
"partners.xpertmarket.com": null,
"pcash.imlive.com": null,
"pics.firstload.de": null,
"popmog.com": null,
"pops.freeze.com": null,
"post.rmbn.ru": null,
"premium.naturalnews.tv": null,
"pub.betclick.com": null,
"public.porn.fr": null,
"pubs.hiddennetwork.com": null,
"rack.bauermedia.co.uk": null,
"revealads.appspot.com": null,
"richmedia.yahoo.com": null,
"roia.hutchmedia.com": null,
"rotabanner.kulichki.net": null,
"rotator.tradetracker.net": null,
"rtax.criteo.com": null,
"rya.rockyou.com": null,
"s-yoolk-banner-assets.yoolk.com": null,
"s-yoolk-billboard-assets.yoolk.com": null,
"s.cxt.ms": null,
"s11clickmoviedownloadercom.maynemyltf.netdna-cdn.com": null,
"salefile.googlecode.com": null,
"secretmedia.s3.amazonaws.com": null,
"servedby.keygamesnetwork.com": null,
"server.freegamesall.com": null,
"shopilize.com": null,
"sitescout-video-cdn.edgesuite.net": null,
"slickdeals.meritline.com": null,
"smblock.s3.amazonaws.com": null,
"sndkorea.nowcdn.co.kr": null,
"sportsbetaffiliates.com.au": null,
"squarespace.evyy.net": null,
"static.tradetracker.net": null,
"stats.hosting24.com": null,
"stats.sitesuite.org": null,
"stopadblock.info": null,
"streaming.rtbiddingplatform.com": null,
"strikeadcdn.s3.amazonaws.com": null,
"stuff-nzwhistleout.s3.amazonaws.com": null,
"survey.g.doubleclick.net": null,
"syndication1.viraladnetwork.net": null,
"tags2.adshell.net": null,
"thirdpartycdn.lumovies.com": null,
"ti.tradetracker.net": null,
"topbinaryaffiliates.ck-cdn.com": null,
"track.bcvcmedia.com": null,
"track.effiliation.com": null,
"twinplan.com": null,
"utility.rogersmedia.com": null,
"videozr.com": null,
"visit.homepagle.com": null,
"web-jp.ad-v.jp": null,
"web.adblade.com": null,
"whistleout.s3.amazonaws.com": null,
"widget.cheki.com.ng": null,
"widget.crowdignite.com": null,
"widget.imshopping.com": null,
"widget.jobberman.com": null,
"widget.kelkoo.com": null,
"widget.raaze.com": null,
"widget.scoutpa.com": null,
"widget.searchschoolsnetwork.com": null,
"widget.shopstyle.com.au": null,
"widget.solarquotes.com.au": null,
"widget.wombo.gg": null,
"widgetcf.adviceiq.com": null,
"widgets.adviceiq.com": null,
"widgets.junction.co.za": null,
"widgets.lendingtree.com": null,
"widgets.mobilelocalnews.com": null,
"widgets.mozo.com.au": null,
"widgets.privateproperty.com.ng": null,
"widgets.progrids.com": null,
"widgets.realestate.com.au": null,
"widgets.solaramerica.org": null,
"wlpinnaclesports.eacdn.com": null,
"yeas.yahoo.co.jp": null,
"zapads.zapak.com": null,
"trust.zone": null,
"chronophotographie.science": null,
"croix.science": null,
"d1nmk7iw7hajjn.cloudfront.net": null,
"d3jgr4uve1d188.cloudfront.net": null,
"d3ujids68p6xmq.cloudfront.net": null,
"demande.science": null,
"secretmedia.com": null,
"104.197.207.200": null,
"104.198.188.213": null,
"4utro.ru": null,
"adserving.unibet.com": null,
"affiliates.galapartners.co.uk": null,
"affportal-lb.bevomedia.com": null,
"banner.galabingo.com": null,
"bizinfoyours.info": null,
"casinoadviser.net": null,
"cdn.optmd.com": null,
"cdnfarm18.com": null,
"chatlivejasmin.net": null,
"clickansave.net": null,
"eroticmix.blogspot.": null,
"facebookcoverx.com": null,
"firstload.com": null,
"firstload.de": null,
"flashplayer-updates.com": null,
"free-rewards.com-s.tv": null,
"fsoft4down.com": null,
"getsecuredfiles.com": null,
"lp.titanpoker.com": null,
"makemoneyonline.2yu.in": null,
"noowmedia.com": null,
"opendownloadmanager.com": null,
"pc.thevideo.me": null,
"platinumdown.com": null,
"rackcorp.com": null,
"record.sportsbetaffiliates.com.au": null,
"rocketgames.com": null,
"serve.prestigecasino.com": null,
"serve.williamhillcasino.com": null,
"settlecruise.org": null,
"track.mypcbackup.com": null,
"track.xtrasize.nl": null,
"tracker.lotto365.com": null,
"unlimited-tv.show": null,
"wptpoker.com": null,
"a.sucksex.com": null,
"ad.duga.jp": null,
"ad.favod.net": null,
"ad.iloveinterracial.com": null,
"ad.traffmonster.info": null,
"ads.videosz.com": null,
"adsrv.bangbros.com": null,
"aff-jp.exshot.com": null,
"affiliate.burn-out.tv": null,
"affiliate.dtiserv.com": null,
"affiliate.godaddy.com": null,
"affiliates.cupidplc.com": null,
"affiliates.easydate.biz": null,
"affiliates.franchisegator.com": null,
"affiliates.thrixxx.com": null,
"amateur.amarotic.com": null,
"babes.picrush.com": null,
"banner.69stream.com": null,
"banner.gasuki.com": null,
"banner.resulthost.org": null,
"banner.themediaplanets.com": null,
"banners.adultfriendfinder.com": null,
"banners.alt.com": null,
"banners.amigos.com": null,
"banners.blacksexmatch.com": null,
"banners.fastcupid.com": null,
"banners.fuckbookhookups.com": null,
"banners.nostringsattached.com": null,
"banners.outpersonals.com": null,
"banners.passion.com": null,
"banners.passiondollars.com": null,
"banners.payserve.com": null,
"banners.penthouse.com": null,
"banners.rude.com": null,
"banners.rushcommerce.com": null,
"banners.videosecrets.com": null,
"banners.webcams.com": null,
"bannershotlink.perfectgonzo.com": null,
"bans.bride.ru": null,
"bbp.brazzers.com": null,
"blaaaa12.googlecode.com": null,
"cache.worldfriends.tv": null,
"cams.enjoy.be": null,
"cams.spacash.com": null,
"cash.femjoy.com": null,
"cdncache2-a.akamaihd.net": null,
"cdnjke.com": null,
"click.absoluteagency.com": null,
"click.hay3s.com": null,
"click.kink.com": null,
"clickz.lonelycheatingwives.com": null,
"content.liveuniverse.com": null,
"contentcache-a.akamaihd.net": null,
"core.queerclick.com": null,
"cp.intl.match.com": null,
"cpm.amateurcommunity.com": null,
"cs.celebbusters.com": null,
"cs.exposedontape.com": null,
"d1mib12jcgwmnv.cloudfront.net": null,
"dailyvideo.securejoin.com": null,
"datefree.com": null,
"deal.maabm.com": null,
"dump1.no-ip.biz": null,
"dyn.primecdn.net": null,
"fansign.streamray.com": null,
"feeds.videosz.com": null,
"freexxxvideoclip.aebn.net": null,
"galeriaseroticas.xpg.com.br": null,
"gateway-banner.eravage.com": null,
"geo.camazon.com": null,
"geobanner.adultfriendfinder.com": null,
"geobanner.alt.com": null,
"geobanner.blacksexmatch.com": null,
"geobanner.fuckbookhookups.com": null,
"geobanner.sexfinder.com": null,
"geobanner.socialflirt.com": null,
"hotsocialz.com": null,
"iframe.adultfriendfinder.com": null,
"iframes.hustler.com": null,
"image.cecash.com": null,
"image.nsk-sys.com": null,
"in.zog.link": null,
"layers.spacash.com": null,
"links.freeones.com": null,
"loveme.com": null,
"manager.koocash.fr": null,
"map.pop6.com": null,
"media.eurolive.com": null,
"media.match.com": null,
"media.mykocam.com": null,
"media.mykodial.com": null,
"media.pussycash.com": null,
"megacash.warpnet.com.br": null,
"metartmoney.com": null,
"metartmoney.met-art.com": null,
"ms.wsex.com": null,
"partner.loveplanet.ru": null,
"partners.heart2heartnetwork.": null,
"partners.pornerbros.com": null,
"partners.yobt.com": null,
"partners.yobt.tv": null,
"pcash.globalmailer5.com": null,
"pop6.adultfriendfinder.com": null,
"pornoh.info": null,
"private.camz.": null,
"profile.bharatmatrimony.com": null,
"promo.blackcrush.com": null,
"promo.cams.com": null,
"promo1.webcams.nl": null,
"ptcdn.mbicash.nl": null,
"ruleclaim.web.fc2.com": null,
"s1magnettvcom.maynemyltf.netdna-cdn.com": null,
"sabin.free.fr": null,
"screencapturewidget.aebn.net": null,
"sexy.fling.com": null,
"shared.juicybucks.com": null,
"surv.xbizmedia.com": null,
"sweet.game-rust.ru": null,
"thumbs.sunporno.com": null,
"tool.acces-vod.com": null,
"tools.bongacams.com": null,
"tools.gfcash.com": null,
"tours.imlive.com": null,
"trader.erosdlz.com": null,
"vectorpastel.com": null,
"vserv.bc.cdn.bitgravity.com": null,
"webmaster.erotik.com": null,
"widgets.comcontent.net": null,
"widgetssec.cam-content.com": null,
"1800freecams.com": null,
"21sextury.com": null,
"get-a-fuck-tonight.com": null,
"icgirls.com": null,
"join.filthydatez.com": null,
"join.whitegfs.com": null,
"livecams.com": null,
"livejasmin.com": null,
"pomnach.ru": null,
"sexsearchcom.com": null,
"textad.sexsearch.com": null,
"webcams.com": null,
"a.cdngeek.net": null,
"a.clipconverter.cc": null,
"a.kickass.to": null,
"ac2.msn.com": null,
"access.njherald.com": null,
"ad.cooks.com": null,
"ad.crichd.in": null,
"ad.digitimes.com.tw": null,
"ad.directmirror.com": null,
"ad.download.cnet.com": null,
"ad.evozi.com": null,
"ad.fnnews.com": null,
"ad.jamster.com": null,
"ad.kissanime.io": null,
"ad.kisscartoon.io": null,
"ad.lyricswire.com": null,
"ad.mangareader.net": null,
"ad.newegg.com": null,
"ad.pandora.tv": null,
"ad.reachlocal.com": null,
"ad.search.ch": null,
"ad.services.distractify.com": null,
"ad.spreaker.com": null,
"ad.xmovies8.ru": null,
"adcitrus.com": null,
"addirector.vindicosuite.com": null,
"adi1.mac-torrent-download.net": null,
"adlink.shopsafe.co.nz": null,
"adp1.mac-torrent-download.net": null,
"ads-rolandgarros.com": null,
"ads.pof.com": null,
"ads.yahoo.com": null,
"ads.zynga.com": null,
"adsatt.abcnews.starwave.com": null,
"adsatt.espn.starwave.com": null,
"adshare.freedocast.com": null,
"adsor.openrunner.com": null,
"adss.yahoo.com": null,
"adstil.indiatimes.com": null,
"advertise.twitpic.com": null,
"adverts.itv.com": null,
"advice-ads-cdn.vice.com": null,
"ajnad.aljazeera.net": null,
"analytics.mmosite.com": null,
"asd.projectfreetv.so": null,
"b.thefile.me": null,
"ba.ccm2.net": null,
"banner.automotiveworld.com": null,
"banner.itweb.co.za": null,
"banners.beevpn.com": null,
"banners.beted.com": null,
"banners.clubworldgroup.com": null,
"banners.expressindia.com": null,
"banners.i-comers.com": null,
"banners.itweb.co.za": null,
"banners.playocio.com": null,
"base.filedot.xyz": null,
"beap.gemini.yahoo.com": null,
"bigboy.eurogamer.net": null,
"bizanti.youwatch.org": null,
"click.livedoor.com": null,
"clicks.superpages.com": null,
"cnetwidget.creativemark.co.uk": null,
"content.streamplay.to": null,
"creatives.livejasmin.com": null,
"dacash.streamplay.to": null,
"dads.new.digg.com": null,
"dailydeals.amarillo.com": null,
"dailydeals.augustachronicle.com": null,
"dailydeals.brainerddispatch.com": null,
"dailydeals.lubbockonline.com": null,
"dailydeals.onlineathens.com": null,
"dailydeals.savannahnow.com": null,
"dcad.watersoul.com": null,
"deals.ledgertranscript.com": null,
"dontblockme.modaco.com": null,
"eacash.streamplay.to": null,
"fan.twitch.tv": null,
"finding.hardwareheaven.com": null,
"findnsave.idahostatesman.com": null,
"gameads.digyourowngrave.com": null,
"geoshopping.nzherald.co.nz": null,
"get.thefile.me": null,
"heavenmedia.v3g4s.com": null,
"hejban.youwatch.org": null,
"ibanners.empoweredcomms.com.au": null,
"iframe.travel.yahoo.com": null,
"imads.rediff.com": null,
"kat-ads.torrenticity.com": null,
"ker.pic2pic.site": null,
"kermit.macnn.com": null,
"life.imagepix.org": null,
"lightson.vpsboard.com": null,
"lw2.gamecopyworld.com": null,
"mads.dailymail.co.uk": null,
"marketingsolutions.yahoo.com": null,
"media-delivery.armorgames.com": null,
"media-mgmt.armorgames.com": null,
"media.studybreakmedia.com": null,
"mediamgr.ugo.com": null,
"nest.youwatch.org": null,
"oas.autotrader.co.uk": null,
"oas.skyscanner.net": null,
"oasc07.citywire.co.uk": null,
"oascentral.chron.com": null,
"oascentral.hosted.ap.org": null,
"oascentral.newsmax.com": null,
"ox-d.rantsports.com": null,
"ox-d.sbnation.com": null,
"ox-d.wetransfer.com": null,
"pan2.ephotozine.com": null,
"partners-z.com": null,
"player.accoona.com": null,
"pmm.people.com.cn": null,
"pop-over.powered-by.justplayzone.com": null,
"prerollads.ign.com": null,
"promo.fileforum.com": null,
"pub.chinadailyasia.com": null,
"rad.microsoft.com": null,
"rad.msn.com": null,
"red.bayimg.net": null,
"redvase.bravenet.com": null,
"richmedia.yimg.com": null,
"rpt.anchorfree.net": null,
"runetki.joyreactor.ru": null,
"shoppingpartners2.futurenet.com": null,
"showcase.vpsboard.com": null,
"showing.hardwareheaven.com": null,
"spproxy.autobytel.com": null,
"static.tucsonsentinel.com": null,
"storewidget.pcauthority.com.au": null,
"stream.heavenmedia.net": null,
"targetedinfo.com": null,
"thejesperbay.com": null,
"themis.yahoo.com": null,
"tracking.hostgator.com": null,
"uimserv.net": null,
"unicast.msn.com": null,
"vice-ads-cdn.vice.com": null,
"w.homes.yahoo.net": null,
"widget.directory.dailycommercial.com": null,
"yea.uploadimagex.com": null,
"yrt7dgkf.exashare.com": null,
"ysm.yahoo.com": null,
"zads.care2.com": null,
"a.thefreethoughtproject.com": null,
"104.198.221.99": null,
"104.198.61.40": null,
"130.211.198.219": null,
"35.188.12.5": null,
"pop.billionuploads.com": null,
"tozer.youwatch.org": null,
"trans.youwatch.org": null,
"tumejortorrent.com": null,
"a.eporner.com": null,
"a.killergram-girls.com": null,
"ad.eporner.com": null,
"ad.slutload.com": null,
"ad.thisav.com": null,
"ad.userporn.com": null,
"ads.xxxbunker.com": null,
"affiliates.goodvibes.com": null,
"banner1.pornhost.com": null,
"cams.pornrabbit.com": null,
"creatives.cliphunter.com": null,
"creatives.pichunter.com": null,
"d1wi563t0137vz.cloudfront.net": null,
"d2q52i8yx3j68p.cloudfront.net": null,
"d39hdzmeufnl50.cloudfront.net": null,
"delivery.porn.com": null,
"dot.eporner.com": null,
"dot2.eporner.com": null,
"lw1.cdmediaworld.com": null,
"partners.keezmovies.com": null,
"pr-static.empflix.com": null,
"pr-static.tnaflix.com": null,
"r.radikal.ru": null,
"site.img.4tube.com": null,
"static.kinghost.com": null,
"x.eroticity.net": null,
"x.vipergirls.to": null,
"delivery.porn5.com": null,
"pop.fapxl.com": null,
"pop.mrstiff.com": null,
"rd.cockhero.info": null,
"meetrics.netbb-": null,
"0tracker.com": null,
"149.13.65.144": null,
"195.10.245.55": null,
"1freecounter.com": null,
"212.227.100.108": null,
"24counter.com": null,
"2cnt.net": null,
"2o7.net": null,
"360tag.com": null,
"3dlivestats.com": null,
"3dstats.com": null,
"3gl.net": null,
"62.160.52.73": null,
"66.228.52.30": null,
"67.228.151.70": null,
"72.172.88.25": null,
"74.55.82.102": null,
"77tracking.com": null,
"99counters.com": null,
"99stats.com": null,
"a-counters.com": null,
"aamsitecertifier.com": null,
"abcstats.com": null,
"abmr.net": null,
"absolstats.co.za": null,
"acc-hd.de": null,
"acceptableserver.com": null,
"access-analyze.org": null,
"access-traffic.com": null,
"accessintel.com": null,
"accumulatorg.com": null,
"acecounter.com": null,
"acestats.net": null,
"acetrk.com": null,
"acexedge.com": null,
"activemeter.com": null,
"acxiom-online.com": null,
"ad-score.com": null,
"adalyser.com": null,
"adblade.com": null,
"adchemix.com": null,
"adchemy-content.com": null,
"adclickstats.net": null,
"addfreestats.com": null,
"adelixir.com": null,
"adfox.ru": null,
"admantx.com": null,
"admitad.com": null,
"admother.com": null,
"adobedtm.com": null,
"adobetag.com": null,
"adprotraffic.com": null,
"adsensedetective.com": null,
"adspsp.com": null,
"adsymptotic.com": null,
"adultblogtoplist.com": null,
"advanced-web-analytics.com": null,
"adyapper.com": null,
"afairweb.com": null,
"affilae.com": null,
"affiliateedge.eu": null,
"affiliates-pro.com": null,
"affiliatetrackingsetup.com": null,
"affiliatly.com": null,
"affistats.com": null,
"agkn.com": null,
"aidata.io": null,
"aimediagroup.com": null,
"akstat.com": null,
"alexacdn.com": null,
"alexametrics.com": null,
"alltagcloud.info": null,
"alltracked.com": null,
"altastat.com": null,
"amavalet.com": null,
"amazingcounters.com": null,
"amilliamilli.com": null,
"amung.us": null,
"analoganalytics.com": null,
"analytics-egain.com": null,
"analytics-engine.net": null,
"analyticswizard.com": null,
"analytk.com": null,
"anametrix.net": null,
"angelfishstats.com": null,
"anonymousdmp.com": null,
"answerscloud.com": null,
"apexstats.com": null,
"apicit.net": null,
"app.link": null,
"appboycdn.com": null,
"aqtracker.com": null,
"arena-quantum.co.uk": null,
"arlime.com": null,
"arturtrack.com": null,
"athenainstitute.biz": null,
"attracta.com": null,
"audience.visiblemeasures.com": null,
"audienceiq.com": null,
"audiencerate.com": null,
"autoaffiliatenetwork.com": null,
"autoaudience.com": null,
"avantlink.com": null,
"avastats.com": null,
"avmws.com": null,
"awmcounter.de": null,
"axf8.net": null,
"azalead.com": null,
"b1img.com": null,
"babator.com": null,
"basicstat.com": null,
"beacon.kmi-us.com": null,
"beanstalkdata.com": null,
"beemrdwn.com": null,
"beencounter.com": null,
"behavioralengine.com": null,
"belstat.at": null,
"belstat.be": null,
"belstat.ch": null,
"belstat.com": null,
"belstat.de": null,
"belstat.fr": null,
"belstat.nl": null,
"bestweb2013stat.lk": null,
"betarget.com": null,
"bettermetrics.co": null,
"bigcattracks.com": null,
"bigmir.net": null,
"bigstats.net": null,
"bigtracker.com": null,
"bionicclick.com": null,
"bizible.com": null,
"bkrtx.com": null,
"bkvtrack.com": null,
"blockbreaker.io": null,
"blockmetrics.com": null,
"blog-stat.com": null,
"blogmeetsbrand.com": null,
"blogscounter.com": null,
"blogsontop.com": null,
"blogtoplist.com": null,
"bluecava.com": null,
"blueconic.net": null,
"bluekai.com": null,
"blvdstatus.com": null,
"bm23.com": null,
"bmlmedia.com": null,
"bmmetrix.com": null,
"bookforest.biz": null,
"boomtrain.com": null,
"botsvisit.com": null,
"brat-online.ro": null,
"brcdn.com": null,
"brightedge.com": null,
"browser-statistik.de": null,
"bstk.co": null,
"btbuckets.com": null,
"btstatic.com": null,
"bubblestat.com": null,
"bugsnag.com": null,
"burstbeacon.com": null,
"burt.io": null,
"buzzdeck.com": null,
"bytemgdd.com": null,
"c-webstats.de": null,
"c.adroll.com": null,
"c1exchange.com": null,
"c3metrics.com": null,
"c3tag.com": null,
"call-tracking.co.uk": null,
"callrail.com": null,
"calltrackingmetrics.com": null,
"calltracks.com": null,
"campaigncog.com": null,
"caphyon-analytics.com": null,
"capturly.com": null,
"cashburners.com": null,
"cashcount.com": null,
"cccpmo.com": null,
"ccgateway.net": null,
"cdntrf.com": null,
"cedexis.com": null,
"cedexis.net": null,
"celebros-analytics.com": null,
"celebrus.com": null,
"cetrk.com": null,
"cftrack.com": null,
"chartaca.com": null,
"chartbeat.com": null,
"chartbeat.net": null,
"checkstat.nl": null,
"cheezburger-analytics.com": null,
"chickensaladandads.com": null,
"chrumedia.com": null,
"circular-counters.com": null,
"cleananalytics.com": null,
"clearviewstats.com": null,
"click-linking.com": null,
"click-url.com": null,
"click2meter.com": null,
"click4assistance.co.uk": null,
"clickable.net": null,
"clickaider.com": null,
"clickalyzer.com": null,
"clickclick.net": null,
"clickcloud.info": null,
"clickconversion.net": null,
"clickdensity.com": null,
"clickdimensions.com": null,
"clickening.com": null,
"clickforensics.com": null,
"clickigniter.io": null,
"clickmanage.com": null,
"clickmeter.com": null,
"clickpathmedia.com": null,
"clickprotector.com": null,
"clickreport.com": null,
"clicksagent.com": null,
"clicksen.se": null,
"clickshift.com": null,
"clickstream.co.za": null,
"clicktale.net": null,
"clicktrack1.com": null,
"clicktracks.com": null,
"clickzs.com": null,
"clickzzs.nl": null,
"cloud-exploration.com": null,
"cloud-iq.com": null,
"cloudtracer101.com": null,
"clustrmaps.com": null,
"cnt1.net": null,
"cnxweb.com": null,
"cnzz.com": null,
"codata.ru": null,
"cogmatch.net": null,
"cognitivematch.com": null,
"collserve.com": null,
"company-target.com": null,
"compteur.cc": null,
"contactmonkey.com": null,
"content-square.net": null,
"contentinsights.com": null,
"contentspread.net": null,
"continue.com": null,
"convergetrack.com": null,
"conversionlogic.net": null,
"conversionly.com": null,
"conversionruler.com": null,
"convertexperiments.com": null,
"convertglobal.com": null,
"convertro.com": null,
"cooladata.com": null,
"coremetrics.com": null,
"counter.gd": null,
"counter.top.kg": null,
"counter160.com": null,
"counterbot.com": null,
"countercentral.com": null,
"countergeo.com": null,
"counterland.com": null,
"counters4u.com": null,
"counterservis.com": null,
"countersforlife.com": null,
"countertracker.com": null,
"counterviews.net": null,
"counting4free.com": null,
"cqcounter.com": null,
"craftkeys.com": null,
"craktraffic.com": null,
"crazyegg.com": null,
"criteo.com": null,
"criteo.net": null,
"crmmetrix.fr": null,
"crmmetrixwris.com": null,
"crowdscience.com": null,
"crsspxl.com": null,
"crwdcntrl.net": null,
"csdata1.com": null,
"csi-tracking.com": null,
"cttracking02.com": null,
"customerdiscoverytrack.com": null,
"cxense.com": null,
"cxt.ms": null,
"cybermonitor.com": null,
"dacounter.com": null,
"dailycaller-alerts.com": null,
"dashboard.io": null,
"data-analytics.jp": null,
"databrain.com": null,
"datacaciques.com": null,
"datafeedfile.com": null,
"datam.com": null,
"datamind.ru": null,
"dataperforma.com": null,
"dataxpand.com": null,
"daylife-analytics.com": null,
"dc.tremormedia.com": null,
"decdna.net": null,
"demandbase.com": null,
"demdex.net": null,
"devatics.com": null,
"dgmsearchlab.com": null,
"dhmtracking.co.za": null,
"diffusion-tracker.com": null,
"digitaloptout.com": null,
"digitaltarget.ru": null,
"dinkstat.com": null,
"directrdr.com": null,
"displaymarketplace.com": null,
"distralytics.com": null,
"dmanalytics1.com": null,
"dmclick.cn": null,
"dmtracker.com": null,
"dmtry.com": null,
"dominocounter.net": null,
"dotomi.com": null,
"doubleclick.net": null,
"downture.in": null,
"dsply.com": null,
"dstrack2.info": null,
"dwin1.com": null,
"e-webtrack.net": null,
"earnitup.com": null,
"easy-hit-counters.com": null,
"easycounter.com": null,
"easyhitcounters.com": null,
"easyresearch.se": null,
"ec-track.com": null,
"ecn5.com": null,
"ecommstats.com": null,
"ecsanalytics.com": null,
"ecustomeropinions.com": null,
"edigitalsurvey.com": null,
"email-match.com": null,
"embeddedanalytics.com": null,
"emediatrack.com": null,
"enecto.com": null,
"enectoanalytics.com": null,
"engagemaster.com": null,
"enquisite.com": null,
"eperfectdata.com": null,
"epiodata.com": null,
"epitrack.com": null,
"eproof.com": null,
"eps-analyzer.de": null,
"ereportz.com": null,
"esm1.net": null,
"esomniture.com": null,
"estara.com": null,
"estat.com": null,
"estrack.net": null,
"ethnio.com": null,
"etracker.com": null,
"etrafficcounter.com": null,
"etrafficstats.com": null,
"eu-survey.com": null,
"euleriancdn.net": null,
"europagerank.com": null,
"eventoptimize.com": null,
"everestjs.net": null,
"everesttech.net": null,
"evergage.com": null,
"evisitanalyst.com": null,
"evisitcs.com": null,
"evisitcs2.com": null,
"evolvemediametrics.com": null,
"evyy.net": null,
"ewebanalytics.com": null,
"ewebcounter.com": null,
"exactag.com": null,
"exclusiveclicks.com": null,
"exelator.com": null,
"exovueplatform.com": null,
"explore-123.com": null,
"exposebox.com": null,
"extole.com": null,
"extreme-dm.com": null,
"ezytrack.com": null,
"fabricww.com": null,
"factortg.com": null,
"fandommetrics.com": null,
"fanplayr.com": null,
"fast-thinking.co.uk": null,
"fastanalytic.com": null,
"fastly-analytics.com": null,
"fastonlineusers.com": null,
"fastwebcounter.com": null,
"fdxstats.xyz": null,
"feedjit.com": null,
"filitrac.com": null,
"finalid.com": null,
"fitanalytics.com": null,
"flagcounter.com": null,
"flash-counter.com": null,
"flash-stat.com": null,
"flashgamestats.com": null,
"flcounter.com": null,
"flowstats.net": null,
"fluencymedia.com": null,
"fluidsurveys.com": null,
"flxpxl.com": null,
"flyingpt.com": null,
"followercounter.com": null,
"footprintdns.com": null,
"footprintlive.com": null,
"foreseeresults.com": null,
"forkcdn.com": null,
"formalyzer.com": null,
"fqsecure.com": null,
"free-counter.co.uk": null,
"free-counter.com": null,
"free-counters.co.uk": null,
"free-website-hit-counters.com": null,
"free-website-statistics.com": null,
"freebloghitcounter.com": null,
"freecountercode.com": null,
"freecounterstat.com": null,
"freegeoip.net": null,
"freehitscounter.org": null,
"freelogs.com": null,
"freeonlineusers.com": null,
"freesitemapgenerator.com": null,
"freestats.com": null,
"freetrafficsystem.com": null,
"freeusersonline.com": null,
"freeweblogger.com": null,
"freshcounter.com": null,
"fruitflan.com": null,
"fueldeck.com": null,
"fugetech.com": null,
"funstage.com": null,
"fuse-data.com": null,
"fusestats.com": null,
"fyreball.com": null,
"gaug.es": null,
"gbotvisit.com": null,
"gemius.pl": null,
"gemtrackers.com": null,
"geobytes.com": null,
"geoplugin.net": null,
"getbackstory.com": null,
"getblueshift.com": null,
"getclicky.com": null,
"getfreebl.com": null,
"getsmartlook.com": null,
"getstatistics.se": null,
"gigcount.com": null,
"glbtracker.com": null,
"globalviptraffic.com": null,
"globetrackr.com": null,
"go-mpulse.net": null,
"goaltraffic.com": null,
"goldstats.com": null,
"goodcounter.org": null,
"googleadservices.com": null,
"googlerank.info": null,
"gosquared.com": null,
"gostats.com": null,
"gostats.org": null,
"gostats.ro": null,
"govmetric.com": null,
"grepdata.com": null,
"group-ib.ru": null,
"gsimedia.net": null,
"gstats.cn": null,
"gtopstats.com": null,
"guruquicks.net": null,
"gvisit.com": null,
"halldata.com": null,
"halstats.com": null,
"heapanalytics.com": null,
"heatmap.it": null,
"hentaicounter.com": null,
"hexagon-analytics.com": null,
"heystaks.com": null,
"hiconversion.com": null,
"higherengine.com": null,
"highmetrics.com": null,
"histats.com": null,
"hit-counter-download.com": null,
"hit-counter.info": null,
"hit-counters.net": null,
"hitcounterstats.com": null,
"hitmatic.com": null,
"hitmaze-counters.net": null,
"hitslink.com": null,
"hitsprocessor.com": null,
"hittail.com": null,
"hittracker.com": null,
"hitwebcounter.com": null,
"host-tracker.com": null,
"hostip.info": null,
"hoststats.info": null,
"hotdogsandads.com": null,
"hotjar.com": null,
"hotlog.ru": null,
"hs-analytics.net": null,
"humanclick.com": null,
"hunt-leads.com": null,
"hxtrack.com": null,
"hyfntrak.com": null,
"hypestat.com": null,
"i-stats.com": null,
"ib-ibi.com": null,
"ic-live.com": null,
"iclive.com": null,
"icstats.nl": null,
"id-visitors.com": null,
"ideoclick.com": null,
"idtargeting.com": null,
"igaming.biz": null,
"ijncw.tv": null,
"imanginatium.com": null,
"immanalytics.com": null,
"impcounter.com": null,
"imrtrack.com": null,
"imrworldwide.com": null,
"inboxtag.com": null,
"index.ru": null,
"indexstats.com": null,
"indextools.com": null,
"individuad.net": null,
"inferclick.com": null,
"infinity-tracking.net": null,
"inflectionpointmedia.com": null,
"innovateads.com": null,
"inphonic.com": null,
"inpwrd.com": null,
"insitemetrics.com": null,
"inspectlet.com": null,
"instore.biz": null,
"integritystat.com": null,
"intelli-tracker.com": null,
"intermundomedia.com": null,
"interstateanalytics.com": null,
"invitemedia.com": null,
"invoc.us": null,
"ip-api.com": null,
"ip-label.net": null,
"ipcounter.de": null,
"iperceptions.com": null,
"ipinfodb.com": null,
"ipinyou.com.cn": null,
"ipstat.com": null,
"ist-track.com": null,
"istrack.com": null,
"itrackerpro.com": null,
"itracmediav4.com": null,
"iwebtrack.com": null,
"iwstats.com": null,
"jimdo-stats.com": null,
"jirafe.com": null,
"jscounter.com": null,
"jstracker.com": null,
"jump-time.net": null,
"jumptime.com": null,
"jwmstats.com": null,
"k-analytix.com": null,
"kameleoon.com": null,
"kampyle.com": null,
"keymetric.net": null,
"keywee.co": null,
"keywordmax.com": null,
"killerwebstats.com": null,
"kissmetrics.com": null,
"klldabck.com": null,
"knowlead.io": null,
"knowledgevine.net": null,
"komtrack.com": null,
"krxd.net": null,
"l2.visiblemeasures.com": null,
"lead-123.com": null,
"lead-converter.com": null,
"lead-tracking.biz": null,
"leadforensics.com": null,
"leadformix.com": null,
"leadlife.com": null,
"leadmanagerfx.com": null,
"leadsius.com": null,
"leadsrx.com": null,
"legolas-media.com": null,
"les-experts.com": null,
"levexis.com": null,
"liadm.com": null,
"lijit.com": null,
"linezing.com": null,
"link-smart.com": null,
"linkconnector.com": null,
"linkpulse.com": null,
"linksynergy.com": null,
"linkxchanger.com": null,
"listrakbi.com": null,
"livestat.com": null,
"lockview.cn": null,
"locotrack.net": null,
"logcounter.com": null,
"loggly.com": null,
"lognormal.net": null,
"lookery.com": null,
"losstrack.com": null,
"lporirxe.com": null,
"luckyorange.com": null,
"luminate.com": null,
"lxtrack.com": null,
"lymantriacypresdoctrine.biz": null,
"m-pathy.com": null,
"macandcheeseandads.com": null,
"magnify360.com": null,
"mailstat.us": null,
"maploco.com": null,
"marinsm.com": null,
"market2lead.com": null,
"marketizator.com": null,
"marketo.net": null,
"martianstats.com": null,
"masterstats.com": null,
"matheranalytics.com": null,
"mathtag.com": null,
"maxtracker.net": null,
"mbotvisit.com": null,
"mdotlabs.com": null,
"measuremap.com": null,
"meatballsandads.com": null,
"mediaarmor.com": null,
"mediaforgews.com": null,
"mediagauge.com": null,
"mediametrics.ru": null,
"mediaplex.com": null,
"mediarithmics.com": null,
"mega-stats.com": null,
"memecounter.com": null,
"mercadoclics.com": null,
"mercent.com": null,
"meteorsolutions.com": null,
"metricsdirect.com": null,
"mezzobit.com": null,
"midkotatraffic.net": null,
"millioncounter.com": null,
"minewhat.com": null,
"mixpanel.com": null,
"mkt51.net": null,
"mktoresp.com": null,
"mlclick.com": null,
"mletracker.com": null,
"mlstat.com": null,
"mmccint.com": null,
"mno.link": null,
"mobalyzer.net": null,
"mochibot.com": null,
"monetate.net": null,
"mongoosemetrics.com": null,
"mouseflow.com": null,
"mousestats.com": null,
"mplxtms.com": null,
"mpstat.us": null,
"mstracker.net": null,
"mtracking.com": null,
"mtrics.cdc.gov": null,
"mvilivestats.com": null,
"mvtracker.com": null,
"mxcdn.net": null,
"myaffiliateprogram.com": null,
"myfastcounter.com": null,
"mynewcounter.com": null,
"myomnistar.com": null,
"myroitracking.com": null,
"myseostats.com": null,
"mysitetraffic.net": null,
"mysocialpixel.com": null,
"mytictac.com": null,
"mywebstats.com.au": null,
"mywebstats.org": null,
"naturaltracking.com": null,
"neatstats.com": null,
"nedstat.com": null,
"nedstat.net": null,
"nedstatbasic.net": null,
"nedstatpro.net": null,
"nestedmedia.com": null,
"netclickstats.com": null,
"netflame.cc": null,
"netmining.com": null,
"netmng.com": null,
"newstatscounter.info": null,
"nextstat.com": null,
"nordicresearch.com": null,
"notifyvisitors.com": null,
"novately.com": null,
"nr-data.net": null,
"nstracking.com": null,
"nuconomy.com": null,
"nudatasecurity.com": null,
"nuggad.net": null,
"od.visiblemeasures.com": null,
"odoscope.com": null,
"offermatica.com": null,
"ohmystats.com": null,
"ojrq.net": null,
"oktopost.com": null,
"omtrdc.net": null,
"ondu.ru": null,
"onelink-translations.com": null,
"onestat.com": null,
"online-media-stats.com": null,
"online-metrix.net": null,
"opbandit.com": null,
"openclick.com": null,
"openstat.net": null,
"opentracker.net": null,
"openxtracker.com": null,
"optimizely.com": null,
"optimost.com": null,
"optreadetrus.info": null,
"os-data.com": null,
"ositracker.com": null,
"otracking.com": null,
"ournet-analytics.com": null,
"outboundlink.me": null,
"overstat.com": null,
"owlanalytics.io": null,
"p-td.com": null,
"p.raasnet.com": null,
"p0.raasnet.com": null,
"pagefair.com": null,
"pages05.net": null,
"paidstats.com": null,
"parklogic.com": null,
"parrable.com": null,
"pclicks.com": null,
"peerius.com": null,
"percentmobile.com": null,
"perfectaudience.com": null,
"performanceanalyser.net": null,
"performtracking.com": null,
"perimeterx.net": null,
"petametrics.com": null,
"phone-analytics.com": null,
"photorank.me": null,
"pi-stats.com": null,
"ping-fast.com": null,
"pingdom.net": null,
"pixel.parsely.com": null,
"pixel.watch": null,
"pixeleze.com": null,
"pixelinteractivemedia.com": null,
"pixelrevenue.com": null,
"pixelsnippet.com": null,
"pizzaandads.com": null,
"placemypixel.com": null,
"platformpanda.com": null,
"popsample.com": null,
"populr.me": null,
"porngraph.com": null,
"portfold.com": null,
"postaffiliatepro.com": null,
"postclickmarketing.com": null,
"ppclocation.biz": null,
"ppctracking.net": null,
"prchecker.info": null,
"precisioncounter.com": null,
"predictiveresponse.net": null,
"prnx.net": null,
"profilertracking3.com": null,
"profilesnitch.com": null,
"projecthaile.com": null,
"projectsunblock.com": null,
"proofpositivemedia.com": null,
"proxad.net": null,
"prtracker.com": null,
"pstats.com": null,
"psyma-statistics.com": null,
"ptengine.com": null,
"publishflow.com": null,
"pulselog.com": null,
"purevideo.com": null,
"pzkysq.pink": null,
"q-counter.com": null,
"q-stats.nl": null,
"qbaka.net": null,
"qdtracking.com": null,
"qsstats.com": null,
"quantcount.com": null,
"quantserve.com": null,
"qubitproducts.com": null,
"questradeaffiliates.com": null,
"quillion.com": null,
"quintelligence.com": null,
"radarstats.com": null,
"radarurl.com": null,
"rampanel.com": null,
"rampmetrics.com": null,
"rankingpartner.com": null,
"rapidcounter.com": null,
"rapidstats.net": null,
"rapidtrk.net": null,
"reactful.com": null,
"readertracking.com": null,
"readnotify.com": null,
"real5traf.ru": null,
"realcounter.eu": null,
"realcounters.com": null,
"realtimewebstats.net": null,
"realtracker.com": null,
"realtracking.ninja": null,
"redcounter.net": null,
"redistats.com": null,
"redstatcounter.com": null,
"reinvigorate.net": null,
"relead.com": null,
"reliablecounter.com": null,
"remarketstats.com": null,
"res-x.com": null,
"revenuepilot.com": null,
"revenuewire.net": null,
"revolvermaps.com": null,
"rewardtv.com": null,
"reztrack.com": null,
"rfihub.com": null,
"rhinoseo.com": null,
"riastats.com": null,
"richmetrics.com": null,
"ritecounter.com": null,
"rkdms.com": null,
"rlcdn.com": null,
"rnengage.com": null,
"roia.biz": null,
"roispy.com": null,
"roitesting.com": null,
"roivista.com": null,
"rollingcounters.com": null,
"rs6.net": null,
"rsvpgenius.com": null,
"ru4.com": null,
"rumanalytics.com": null,
"sageanalyst.net": null,
"saletrack.co.uk": null,
"sarevtop.com": null,
"sayutracking.co.uk": null,
"scastnet.com": null,
"schoolyeargo.com": null,
"scorecardresearch.com": null,
"scoutanalytics.net": null,
"script.ag": null,
"scripts21.com": null,
"scriptshead.com": null,
"searchignite.com": null,
"sedotracker.com": null,
"segment-analytics.com": null,
"segment.com": null,
"segment.io": null,
"sematext.com": null,
"sendtraffic.com": null,
"serious-partners.com": null,
"servestats.com": null,
"servingtrkid.com": null,
"servustats.com": null,
"sessioncam.com": null,
"sexcounter.com": null,
"sexystat.com": null,
"shareasale.com": null,
"sharpspring.com": null,
"shinystat.com": null,
"shoelace.com": null,
"showroomlogic.com": null,
"silverpop.com": null,
"simplehitcounter.com": null,
"simplereach.com": null,
"simpli.fi": null,
"singlefeed.com": null,
"site24x7rum.com": null,
"siteapps.com": null,
"sitebro.com": null,
"sitebro.net": null,
"sitebro.tw": null,
"sitecompass.com": null,
"siteimprove.com": null,
"siteimproveanalytics.com": null,
"sitelinktrack.com": null,
"sitemeter.com": null,
"sitereport.org": null,
"sitestat.com": null,
"sitetag.us": null,
"sitetagger.co.uk": null,
"sitetracker.com": null,
"sitetraq.nl": null,
"skimresources.com": null,
"slingpic.com": null,
"smartctr.com": null,
"smartracker.net": null,
"smileyhost.net": null,
"smrtlnks.com": null,
"sniperlog.ru": null,
"snoobi.com": null,
"socialhoney.co": null,
"socialprofitmachine.com": null,
"socialtrack.co": null,
"socialtrack.net": null,
"socketanalytics.com": null,
"soflopxl.com": null,
"softonic-analytics.net": null,
"sojern.com": null,
"sometrics.com": null,
"sophus3.com": null,
"spectate.com": null,
"splittag.com": null,
"springmetrics.com": null,
"spycounter.net": null,
"spylog.com": null,
"spylog.ru": null,
"spywords.com": null,
"squidanalytics.com": null,
"stadsvc.com": null,
"startstat.ru": null,
"stat08.com": null,
"stat24.com": null,
"statcount.com": null,
"statcounter.com": null,
"statcounterfree.com": null,
"statcounters.info": null,
"stathat.com": null,
"stathound.com": null,
"statisfy.net": null,
"statistiche-web.com": null,
"statistx.com": null,
"statowl.com": null,
"stats-analytics.info": null,
"stats.cz": null,
"stats2.com": null,
"stats21.com": null,
"stats2513.com": null,
"stats4all.com": null,
"stats4you.com": null,
"statsbox.nl": null,
"statsevent.com": null,
"statsimg.com": null,
"statsinsight.com": null,
"statsit.com": null,
"statsmachine.com": null,
"statsrely.com": null,
"statssheet.com": null,
"statsw.com": null,
"statswave.com": null,
"statsy.net": null,
"stattooz.com": null,
"stattrax.com": null,
"statun.com": null,
"statuncore.com": null,
"stcounter.com": null,
"steelhousemedia.com": null,
"stormiq.com": null,
"stroeerdigitalmedia.de": null,
"sub2tech.com": null,
"successfultogether.co.uk": null,
"summitemarketinganalytics.com": null,
"sumologic.com": null,
"supercounters.com": null,
"superstats.com": null,
"supert.ag": null,
"surefire.link": null,
"surfcounters.com": null,
"surfertracker.com": null,
"surveyscout.com": null,
"surveywriter.com": null,
"swfstats.com": null,
"swiss-counter.com": null,
"sxtracking.com": null,
"synthasite.net": null,
"t-analytics.com": null,
"tagcommander.com": null,
"tagifydiageo.com": null,
"tagsrvcs.com": null,
"targetfuel.com": null,
"tcimg.com": null,
"tdstats.com": null,
"tedioustooth.com": null,
"tellapart.com": null,
"tendatta.com": null,
"tentaculos.net": null,
"terabytemedia.com": null,
"testin.cn": null,
"thebestlinks.com": null,
"thebrighttag.com": null,
"thecounter.com": null,
"thefreehitcounter.com": null,
"thermstats.com": null,
"thesearchagency.net": null,
"thisisacoolthing.com": null,
"thisisanothercoolthing.com": null,
"tinycounter.com": null,
"tkqlhce.com": null,
"tnctrx.com": null,
"tns-counter.ru": null,
"tns-cs.net": null,
"top100bloggers.com": null,
"top100webshops.com": null,
"top10sportsites.com": null,
"topblogging.com": null,
"toplist.cz": null,
"touchclarity.com": null,
"tracc.it": null,
"trace.events": null,
"tracemyip.org": null,
"tracetracking.net": null,
"track-web.net": null,
"track2.me": null,
"trackalyzer.com": null,
"trackbar.info": null,
"trackcdn.com": null,
"trackcmp.net": null,
"trackconsole.com": null,
"trackdiscovery.net": null,
"trackeame.com": null,
"trackedlink.net": null,
"trackedweb.net": null,
"tracking100.com": null,
"tracking202.com": null,
"trackinglabs.com": null,
"trackkas.com": null,
"trackmyweb.net": null,
"trackset.com": null,
"tracksy.com": null,
"tracktrk.net": null,
"trackuity.com": null,
"trackword.biz": null,
"trackyourstats.com": null,
"tradedoubler.com": null,
"tradescape.biz": null,
"trafficby.net": null,
"trafficengine.net": null,
"trafficfacts.com": null,
"trafficjoint.com": null,
"trafficregenerator.com": null,
"traffikcntr.com": null,
"trafic.ro": null,
"trailheadapp.com": null,
"treasuredata.com": null,
"trekmedia.net": null,
"trendcounter.com": null,
"trgtcdn.com": null,
"triggertag.gorillanation.com": null,
"trovus.co.uk": null,
"trs.cn": null,
"tru.am": null,
"truconversion.com": null,
"truehits.in.th": null,
"truehits1.gits.net.th": null,
"truoptik.com": null,
"tscounter.com": null,
"tubetrafficcash.com": null,
"tynt.com": null,
"ubertags.com": null,
"ubertracking.info": null,
"ugdturner.com": null,
"umbel.com": null,
"upstats.ru": null,
"uptimeviewer.com": null,
"uralweb.ru": null,
"urlbrief.com": null,
"usabilitytools.com": null,
"usabilla.com": null,
"userlook.com": null,
"useronlinecounter.com": null,
"userreport.com": null,
"userzoom.com": null,
"v3cdn.net": null,
"valaffiliates.com": null,
"vantage-media.net": null,
"vbanalytics.com": null,
"vdna-assets.com": null,
"veinteractive.com": null,
"ventivmedia.com": null,
"verticalscope.com": null,
"vertster.com": null,
"video.oms.eu": null,
"videos.oms.eu": null,
"videostat.com": null,
"visibility-stats.com": null,
"visistat.com": null,
"visitlog.net": null,
"visitor-analytics.net": null,
"visitor-track.com": null,
"visitorglobe.com": null,
"visitorinspector.com": null,
"visitorjs.com": null,
"visitorpath.com": null,
"visitorprofiler.com": null,
"visitortracklog.com": null,
"visitorville.com": null,
"visitstreamer.com": null,
"visualdna-stats.com": null,
"visualdna.com": null,
"visualwebsiteoptimizer.com": null,
"voicefive.com": null,
"voodooalerts.com": null,
"vstats.co": null,
"vtracker.net": null,
"w3counter.com": null,
"w55c.net": null,
"waframedia9.com": null,
"web-counter.net": null,
"web-stat.com": null,
"web-stat.net": null,
"webclicktracker.com": null,
"webcounter.co.za": null,
"webcounter.ws": null,
"webflowmetrics.com": null,
"webgains.com": null,
"webglstats.com": null,
"webiqonline.com": null,
"webleads-tracker.com": null,
"webseoanalytics.co.za": null,
"website-hit-counters.com": null,
"websiteceo.com": null,
"websiteonlinecounter.com": null,
"websiteperform.com": null,
"websitewelcome.com": null,
"webspectator.com": null,
"webstat.com": null,
"webstat.net": null,
"webstat.se": null,
"webstats.com": null,
"webstats4u.com": null,
"webtraffic.se": null,
"webtrafficagents.com": null,
"webtraxs.com": null,
"webtrekk-asia.net": null,
"webtrends.com": null,
"webtrendslive.com": null,
"wemfbox.ch": null,
"whackedmedia.com": null,
"whatismyip.win": null,
"whoisvisiting.com": null,
"whosclickingwho.com": null,
"wikia-beacon.com": null,
"wildxtraffic.com": null,
"wiredminds.de": null,
"wisetrack.net": null,
"wishloop.com": null,
"woopra.com": null,
"worldlogger.com": null,
"wowanalytics.co.uk": null,
"wp-stats.com": null,
"wpdstat.com": null,
"wtp101.com": null,
"wtstats.com": null,
"wundercounter.com": null,
"wwwstats.info": null,
"x-stat.de": null,
"xg4ken.com": null,
"xiti.com": null,
"xxxcounter.com": null,
"xyztraffic.com": null,
"y-track.com": null,
"yamanoha.com": null,
"ybotvisit.com": null,
"ycctrk.co.uk": null,
"yieldbot.com": null,
"yieldify.com": null,
"youmetrix.co.uk": null,
"your-counter.be": null,
"youramigo.com": null,
"zanox-affiliate.de": null,
"zanox.com": null,
"zdbb.net": null,
"zenlivestats.com": null,
"zoomanalytics.co": null,
"zoomflow.com": null,
"zqtk.net": null,
"zroitracker.com": null,
"a.mobify.com": null,
"activetracker.activehotels.com": null,
"ad.aloodo.com": null,
"adfox.yandex.ru": null,
"adlog.com.com": null,
"ads-trk.vidible.tv": null,
"ads.bridgetrack.com": null,
"adtrack.calls.net": null,
"affiliate.iamplify.com": null,
"affiliates.mgmmirage.com": null,
"affiliates.minglematch.com": null,
"affiliates.spark.net": null,
"affiliates.swappernet.com": null,
"akatracking.esearchvision.com": null,
"ams.addflow.ru": null,
"an.yandex.ru": null,
"analytic.pho.fm": null,
"analytic.xingcloud.com": null,
"analyticapi.pho.fm": null,
"analyticcdn.globalmailer.com": null,
"analytics-rhwg.rhcloud.com": null,
"analytics-static.ugc.bazaarvoice.com": null,
"analytics-v2.anvato.com": null,
"analytics.abacast.com": null,
"analytics.adeevo.com": null,
"analytics.amakings.com": null,
"analytics.anvato.net": null,
"analytics.apnewsregistry.com": null,
"analytics.artirix.com": null,
"analytics.atomiconline.com": null,
"analytics.avanser.com.au": null,
"analytics.aweber.com": null,
"analytics.bigcommerce.com": null,
"analytics.brandcrumb.com": null,
"analytics.carambo.la": null,
"analytics.cincopa.com": null,
"analytics.clickpathmedia.com": null,
"analytics.closealert.com": null,
"analytics.cmg.net": null,
"analytics.codigo.se": null,
"analytics.conmio.com": null,
"analytics.convertlanguage.com": null,
"analytics.cynapse.com": null,
"analytics.datahc.com": null,
"analytics.dev.springboardvideo.com": null,
"analytics.edgekey.net": null,
"analytics.edgesuite.net": null,
"analytics.episodic.com": null,
"analytics.fairfax.com.au": null,
"analytics.favcy.com": null,
"analytics.gvim.mobi": null,
"analytics.hosting24.com": null,
"analytics.hpprintx.com": null,
"analytics.kaltura.com": null,
"analytics.kapost.com": null,
"analytics.live.com": null,
"analytics.livestream.com": null,
"analytics.mailmunch.co": null,
"analytics.matchbin.com": null,
"analytics.mlstatic.com": null,
"analytics.onlyonlinemarketing.com": null,
"analytics.ooyala.com": null,
"analytics.optilead.co.uk": null,
"analytics.orenshmu.com": null,
"analytics.performable.com": null,
"analytics.photorank.me": null,
"analytics.piksel.com": null,
"analytics.prod.aws.ecnext.net": null,
"analytics.r17.com": null,
"analytics.radiatemedia.com": null,
"analytics.recruitics.com": null,
"analytics.revee.com": null,
"analytics.reyrey.net": null,
"analytics.rogersmedia.com": null,
"analytics.shareaholic.com": null,
"analytics.sitewit.com": null,
"analytics.snidigital.com": null,
"analytics.sonymusic.com": null,
"analytics.springboardvideo.com": null,
"analytics.staticiv.com": null,
"analytics.stg.springboardvideo.com": null,
"analytics.strangeloopnetworks.com": null,
"analytics.themarketiq.com": null,
"analytics.tout.com": null,
"analytics.tribeca.vidavee.com": null,
"analytics.urx.io": null,
"analytics.vendemore.com": null,
"analytics.websolute.it": null,
"analytics.wildtangent.com": null,
"analytics.yola.net": null,
"analytics.yolacdn.net": null,
"analyticsengine.s3.amazonaws.com": null,
"attributiontrackingga.googlecode.com": null,
"audit.median.hu": null,
"axislogger.appspot.com": null,
"b-aws.aol.com": null,
"basilic.netdna-cdn.com": null,
"bat.bing.com": null,
"beacon.affil.walmart.com": null,
"beacon.errorception.com": null,
"beacon.gcion.com": null,
"beacon.gu-web.net": null,
"beacon.guim.co.uk": null,
"beacon.heliumnetwork.com": null,
"beacon.indieclick.com": null,
"beacon.livefyre.com": null,
"beacon.richrelevance.com": null,
"beacon.riskified.com": null,
"beacon.rum.dynapis.com": null,
"beacon.securestudies.com": null,
"beacon.sojern.com": null,
"beacon.squixa.net": null,
"beacon.thred.woven.com": null,
"beacon.viewlift.com": null,
"beacon2.indieclick.com": null,
"beacon2.indieclicktv.com": null,
"beacons.brandads.net": null,
"bid.g.doubleclick.net": null,
"bitdash-reporting.appspot.com": null,
"blip.bizrate.com": null,
"bonsai.internetbrands.com": null,
"bright.bncnt.com": null,
"bs.yandex.ru": null,
"btn.clickability.com": null,
"business.sharedcount.com": null,
"c.compete.com": null,
"c.imedia.cz": null,
"c.wen.ru": null,
"c3metrics.medifast1.com": null,
"cadreon.s3.amazonaws.com": null,
"canvas-ping.conduit-data.com": null,
"canvas-usage-v2.conduit-data.com": null,
"cc.swiftype.com": null,
"cdn.trafficexchangelist.com": null,
"ce.lijit.com": null,
"cgicounter.oneandone.co.uk": null,
"cgicounter.puretec.de": null,
"chanalytics.merchantadvantage.com": null,
"chartaca.com.s3.amazonaws.com": null,
"click.appinthestore.com": null,
"click.aristotle.net": null,
"click.geopaysys.com": null,
"click.rssfwd.com": null,
"click1.email.nymagazine.com": null,
"click1.online.vulture.com": null,
"clicks.dealer.com": null,
"clickstream.loomia.com": null,
"clicktale.pantherssl.com": null,
"clicktalecdn.sslcs.cdngc.net": null,
"clickthru.lefbc.com": null,
"clicktracker.iscan.nl": null,
"clicktracks.aristotle.net": null,
"clientstat.castup.net": null,
"cloudfront-labs.amazonaws.com": null,
"cnt.3dmy.net": null,
"cnt.mastorage.net": null,
"collect.igodigital.com": null,
"collector.air.tv": null,
"collector.contentexchange.me": null,
"collector.leaddyno.com": null,
"collector.nextguide.tv": null,
"collector.roistat.com": null,
"control.adap.tv": null,
"cookies.livepartners.com": null,
"cookietracker.cloudapp.net": null,
"cookiex.ngd.yahoo.com": null,
"count.paycounter.com": null,
"counter.bloke.com": null,
"counter.cam-content.com": null,
"counter.htmlvalidator.com": null,
"counter.hyipexplorer.com": null,
"counter.maases.com": null,
"counter.mgaserv.com": null,
"counter.pagesview.com": null,
"counter.pax.com": null,
"counter.powweb.com": null,
"counter.rambler.ru": null,
"counter.scribblelive.com": null,
"counter.scribblelive.net": null,
"counter.snackly.co": null,
"counter.sparklit.com": null,
"counter.top.ge": null,
"counter.webcom.com": null,
"counter.webmasters.bpath.com": null,
"counter.yadro.ru": null,
"counters.freewebs.com": null,
"counters.gigya.com": null,
"csi.gstatic.com": null,
"curate.nestedmedia.com": null,
"cx.atdmt.com": null,
"d.shareaholic.com": null,
"d169bbxks24g2u.cloudfront.net": null,
"d1cdnlzf6usiff.cloudfront.net": null,
"d1cerpgff739r9.cloudfront.net": null,
"d1clfvuu2240eh.cloudfront.net": null,
"d1clufhfw8sswh.cloudfront.net": null,
"d1cr9zxt7u0sgu.cloudfront.net": null,
"d1gp8joe0evc8s.cloudfront.net": null,
"d1ksyxj9xozc2j.cloudfront.net": null,
"d1lm7kd3bd3yo9.cloudfront.net": null,
"d1m6l9dfulcyw7.cloudfront.net": null,
"d1nh2vjpqpfnin.cloudfront.net": null,
"d1qpxk1wfeh8v1.cloudfront.net": null,
"d1r27qvpjiaqj3.cloudfront.net": null,
"d1r55yzuc1b1bw.cloudfront.net": null,
"d1rgnfh960lz2b.cloudfront.net": null,
"d1ros97qkrwjf5.cloudfront.net": null,
"d1wscoizcbxzhp.cloudfront.net": null,
"d1xfq2052q7thw.cloudfront.net": null,
"d1yu5hbtu8mng9.cloudfront.net": null,
"d1z2jf7jlzjs58.cloudfront.net": null,
"d21o24qxwf7uku.cloudfront.net": null,
"d22v2nmahyeg2a.cloudfront.net": null,
"d23p9gffjvre9v.cloudfront.net": null,
"d28g9g3vb08y70.cloudfront.net": null,
"d2gfdmu30u15x7.cloudfront.net": null,
"d2gfi8ctn6kki7.cloudfront.net": null,
"d2kmrmwhq7wkvs.cloudfront.net": null,
"d2nxi61n77zqpl.cloudfront.net": null,
"d2oh4tlt9mrke9.cloudfront.net": null,
"d2pxb4n3f9klsc.cloudfront.net": null,
"d2ry9vue95px0b.cloudfront.net": null,
"d2so4705rl485y.cloudfront.net": null,
"d2tgfbvjf3q6hn.cloudfront.net": null,
"d2xgf76oeu9pbh.cloudfront.net": null,
"d303e3cdddb4ded4b6ff495a7b496ed5.s3.amazonaws.com": null,
"d3135glefggiep.cloudfront.net": null,
"d33im0067v833a.cloudfront.net": null,
"d34ko97cxuv4p7.cloudfront.net": null,
"d36lvucg9kzous.cloudfront.net": null,
"d36wtdrdo22bqa.cloudfront.net": null,
"d396ihyrqc81w.cloudfront.net": null,
"d3a2okcloueqyx.cloudfront.net": null,
"d3cxv97fi8q177.cloudfront.net": null,
"d3ezl4ajpp2zy8.cloudfront.net": null,
"d3h1v5cflrhzi4.cloudfront.net": null,
"d3hr5gm0wlxm5h.cloudfront.net": null,
"d3kyk5bao1crtw.cloudfront.net": null,
"d3l3lkinz3f56t.cloudfront.net": null,
"d3mskfhorhi2fb.cloudfront.net": null,
"d3ojzyhbolvoi5.cloudfront.net": null,
"d3qxwzhswv93jk.cloudfront.net": null,
"d3r7h55ola878c.cloudfront.net": null,
"d3rmnwi2tssrfx.cloudfront.net": null,
"d3s7ggfq1s6jlj.cloudfront.net": null,
"d3tglifpd8whs6.cloudfront.net": null,
"d4ax0r5detcsu.cloudfront.net": null,
"d6jkenny8w8yo.cloudfront.net": null,
"d81mfvml8p5ml.cloudfront.net": null,
"d8rk54i4mohrb.cloudfront.net": null,
"d9lq0o81skkdj.cloudfront.net": null,
"daq0d0aotgq0f.cloudfront.net": null,
"data.alexa.com": null,
"data.beyond.com": null,
"data.circulate.com": null,
"data.imakenews.com": null,
"data.marketgid.com": null,
"data.minute.ly": null,
"data.queryly.com": null,
"datam8.co.nz": null,
"dc8na2hxrj29i.cloudfront.net": null,
"demandmedia.s3.amazonaws.com": null,
"dfanalytics.dealerfire.com": null,
"dfdbz2tdq3k01.cloudfront.net": null,
"djibeacon.djns.com": null,
"dkj2m377b0yzw.cloudfront.net": null,
"dl1d2m8ri9v3j.cloudfront.net": null,
"dn34cbtcv9mef.cloudfront.net": null,
"dnn506yrbagrg.cloudfront.net": null,
"doug1izaerwt3.cloudfront.net": null,
"dt.sellpoint.net": null,
"du8783wkf05yr.cloudfront.net": null,
"dufue2m4sondk.cloudfront.net": null,
"dw.com.com": null,
"dymlo6ffhj97l.cloudfront.net": null,
"dzmxze7hxwn6b.cloudfront.net": null,
"dzxxxg6ij9u99.cloudfront.net": null,
"ebay.northernhost.com": null,
"ecommstats.s3.amazonaws.com": null,
"entry-stats.huffpost.com": null,
"epl.paypal-communication.com": null,
"eservicesanalytics.com.au": null,
"event.loyalty.bigdoor.com": null,
"event.previewnetworks.com": null,
"event.trove.com": null,
"eventgateway.soundcloud.com": null,
"eventlog.inspsearch.com": null,
"eventlog.inspsearchapi.com": null,
"events.antenna.is": null,
"events.bounceexchange.com": null,
"events.izooto.com": null,
"events.jotform.com": null,
"events.launchdarkly.com": null,
"events.marquee-cdn.net": null,
"events.medio.com": null,
"events.realgravity.com": null,
"events.whisk.com": null,
"eventtracker.videostrip.com": null,
"experience.contextly.com": null,
"fastcounter.bcentral.com": null,
"fastcounter.onlinehoster.net": null,
"fbpixel.network.exchange": null,
"filament-stats.herokuapp.com": null,
"flashstats.libsyn.com": null,
"fluidsurveys-com.fs.cm": null,
"ga-beacon.appspot.com": null,
"geo.q5media.net": null,
"geoip.nekudo.com": null,
"geoip.taskforce.is": null,
"glbdns.microsoft.com": null,
"glogger.inspcloud.com": null,
"go-stats.dlinkddns.com": null,
"gsp1.baidu.com": null,
"gtrk.s3.amazonaws.com": null,
"hawkeye-data-production.sciencemag.org.s3-website-us-east-1.amazonaws.com": null,
"hello.staticstuff.net": null,
"hi.hellobar.com": null,
"hit-pool.upscore.io": null,
"hits.dealer.com": null,
"hm.baidu.com": null,
"hop.clickbank.net": null,
"i-stats.ieurop.net": null,
"ihstats.cloudapp.net": null,
"imp.affiliator.com": null,
"imp.clickability.com": null,
"informer.yandex.ru": null,
"insights.gravity.com": null,
"itracking.fccinteractive.com": null,
"javascriptcounter.appspot.com": null,
"js-agent.newrelic.com": null,
"kalstats.kaltura.com": null,
"l.coincident.tv": null,
"l.fairblocker.com": null,
"l.ooyala.com": null,
"l.player.ooyala.com": null,
"l.sharethis.com": null,
"lct.salesforce.com": null,
"leadtracking.plumvoice.com": null,
"link.americastestkitchencorp.com": null,
"link.huffingtonpost.com": null,
"link.informer.com": null,
"livecounter.theyosh.nl": null,
"livestats.kaltura.com": null,
"log.adap.tv": null,
"log.invodo.com": null,
"log.olark.com": null,
"log1.survey.io": null,
"logger.logidea.info": null,
"logger.snackly.co": null,
"logger.sociablelabs.com": null,
"logging.carambo.la": null,
"loggingapi.spingo.com": null,
"logs.spilgames.com": null,
"logs.thebloggernetwork.com": null,
"logssl.enquisite.com": null,
"loxodo-analytics.ext.nile.works": null,
"lunametrics.wpengine.netdna-cdn.com": null,
"m.addthisedge.com": null,
"magnify360-cdn.s3.amazonaws.com": null,
"mc.yandex.ru": null,
"mediametrics.mpsa.com": null,
"mediapartner.bigpoint.net": null,
"metering.pagesuite.com": null,
"metric.nwsource.com": null,
"metrics-api.librato.com": null,
"metrics.brightcove.com": null,
"metrics.chmedia.com": null,
"metrics.ctvdigital.net": null,
"metrics.el-mundo.net": null,
"metrics.feedroom.com": null,
"metrics.loomia.com": null,
"metrics.scribblelive.com": null,
"metrics.seenon.com": null,
"metrics.sonymusicd2c.com": null,
"metrics.toptenreviews.com": null,
"metrics.upcload.com": null,
"metrics.wikinvest.com": null,
"mmpstats.mirror-image.com": null,
"mp.pianomedia.eu": null,
"mtrcs.samba.tv": null,
"myscoop-tracking.googlecode.com": null,
"neocounter.neoworx-blog-tools.net": null,
"newsanalytics.com.au": null,
"nol.yahoo.com": null,
"nonxt1.c.youtube.com": null,
"o.addthis.com": null,
"observer.ip-label.net": null,
"octopart-analytics.com": null,
"offermatica.intuit.com": null,
"offers.keynote.com": null,
"om.rogersmedia.com": null,
"onespot-tracking.herokuapp.com": null,
"pages-stats.rbl.ms": null,
"partner.cynapse.com": null,
"partners.etoro.com": null,
"partners.thefilter.com": null,
"peermapcontent.affino.com": null,
"perr.h-cdn.com": null,
"ping.hellobar.com": null,
"ping.rasset.ie": null,
"pixel.colorupmedia.com": null,
"pixel.fanbridge.com": null,
"pixel.newsdata.com.au": null,
"pixel.solvemedia.com": null,
"pixels.youknowbest.com": null,
"platform.communicatorcorp.com": null,
"pmetrics.performancing.com": null,
"postpixel.vindicosuite.com": null,
"providence.voxmedia.com": null,
"prstats.postrelease.com": null,
"pt.crossmediaservices.com": null,
"ptracker.nurturehq.com": null,
"ptsc.shoplocal.com": null,
"pub.sheknows.com": null,
"px.excitedigitalmedia.com": null,
"px.owneriq.net": null,
"qlog.adap.tv": null,
"qos.video.yimg.com": null,
"qubitanalytics.appspot.com": null,
"r.mail.ru": null,
"r.msn.com": null,
"referrer.disqus.com": null,
"report.downloastar.com": null,
"reporting.singlefeed.com": null,
"reportinglogger.my.rightster.com": null,
"rich-agent.s3.amazonaws.com": null,
"rlinks.one.in": null,
"roitrack.addlvr.com": null,
"rs.sinajs.cn": null,
"rtt.campanja.com": null,
"s.clickability.com": null,
"s3-tracking.synthasite.net.s3.amazonaws.com": null,
"sadv.dadapro.com": null,
"scout.haymarketmedia.com": null,
"scripts.psyma.com": null,
"search.mediatarget.net": null,
"searchstats.usa.gov": null,
"seg.sharethis.com": null,
"segments.adap.tv": null,
"sftrack.searchforce.net": null,
"shared.65twenty.com": null,
"sig.atdmt.com": null,
"sig.gamerdna.com": null,
"sitereports.officelive.com": null,
"spacedust.netmediaeurope.com": null,
"speedtrap.shopdirect.com": null,
"stat.boredomtherapy.com": null,
"stat.easydate.biz": null,
"stat.ed.cupidplc.com": null,
"stat.itp-nyc.com": null,
"stat.php-d.com": null,
"stat.pladform.ru": null,
"stat.segitek.hu": null,
"stat.to.cupidplc.com": null,
"stat.web-regie.com": null,
"statdb.pressflex.com": null,
"static.parsely.com": null,
"statistics.infowap.info": null,
"statistics.m0lxcdn.kukuplay.com": null,
"statistics.tattermedia.com": null,
"statistics.wibiya.com": null,
"statm.the-adult-company.com": null,
"stats-messages.gifs.com": null,
"stats-newyork1.bloxcms.com": null,
"stats.big-boards.com": null,
"stats.bitgravity.com": null,
"stats.bluebillywig.com": null,
"stats.cdn.pfn.bz": null,
"stats.cdn.playfair.co.za": null,
"stats.clickability.com": null,
"stats.clipprtv.com": null,
"stats.cloudwp.io": null,
"stats.cnevids.com": null,
"stats.complex.com": null,
"stats.datahjaelp.net": null,
"stats.dice.com": null,
"stats.directnic.com": null,
"stats.edicy.com": null,
"stats.free-rein.net": null,
"stats.g.doubleclick.net": null,
"stats.geegain.com": null,
"stats.gifs.com": null,
"stats.heyoya.com": null,
"stats.highwire.com": null,
"stats.indexstats.com": null,
"stats.inergizedigitalmedia.com": null,
"stats.itweb.co.za": null,
"stats.kaltura.com": null,
"stats.lightningcast.net": null,
"stats.load.com": null,
"stats.lotlinx.com": null,
"stats.magnify.net": null,
"stats.manticoretechnology.com": null,
"stats.mituyu.com": null,
"stats.nebula.fi": null,
"stats.netbopdev.co.uk": null,
"stats.olark.com": null,
"stats.ombx.io": null,
"stats.openload.co": null,
"stats.ozwebsites.biz": null,
"stats.polldaddy.com": null,
"stats.qmerce.com": null,
"stats.ref2000.com": null,
"stats.sa-as.com": null,
"stats.sawlive.tv": null,
"stats.shopify.com": null,
"stats.smartclip.net": null,
"stats.snacktools.net": null,
"stats.snappytv.com": null,
"stats.solidopinion.com": null,
"stats.staging.suite101.com": null,
"stats.surfaid.ihost.com": null,
"stats.svpply.com": null,
"stats.topofblogs.com": null,
"stats.twistage.com": null,
"stats.viddler.com": null,
"stats.vodpod.com": null,
"stats.webs.com": null,
"stats.webstarts.com": null,
"stats.whicdn.com": null,
"stats.wp.com": null,
"stats.yme.com": null,
"stats.yourminis.com": null,
"stats1.tune.pk": null,
"stats2.lightningcast.net": null,
"stats3.unrulymedia.com": null,
"statsadv.dadapro.com": null,
"statsapi.screen9.com": null,
"statsdev.treesd.com": null,
"statsrv.451.com": null,
"statt-collect.herokuapp.com": null,
"su.addthis.com": null,
"survey.interquest.com": null,
"surveywall-api.survata.com": null,
"sync.adap.tv": null,
"t.a3cloud.net": null,
"t.sharethis.com": null,
"t.smile.eu": null,
"t2.t2b.click": null,
"tag.aticdn.net": null,
"tagger.opecloud.com": null,
"targeting.wpdigital.net": null,
"te.supportfreecontent.com": null,
"telemetry.soundcloud.com": null,
"thetradedesk-tags.s3.amazonaws.com": null,
"tl.tradetracker.net": null,
"tm.tradetracker.net": null,
"top-fwz1.mail.ru": null,
"tr-metrics.loomia.com": null,
"tr.advance.net": null,
"tr.cloud-media.fr": null,
"track.99acres.com": null,
"track.addevent.com": null,
"track.atgstores.com": null,
"track.atom-data.io": null,
"track.bannedcelebs.com": null,
"track.cafemomstatic.com": null,
"track.captivate.ai": null,
"track.did-it.com": null,
"track.digitalriver.com": null,
"track.dzloans.com": null,
"track.g-bot.net": null,
"track.gridlockparadise.com": null,
"track.juno.com": null,
"track.kandle.org": null,
"track.leadin.com": null,
"track.mailerlite.com": null,
"track.mybloglog.com": null,
"track.mycliplister.com": null,
"track.omg2.com": null,
"track.parse.ly": null,
"track.pricespider.com": null,
"track.propelplus.com": null,
"track.qcri.org": null,
"track.qoof.com": null,
"track.redirecting2.net": null,
"track.ringcentral.com": null,
"track.sauce.ly": null,
"track.searchignite.com": null,
"track.securedvisit.com": null,
"track.shop2market.com": null,
"track.sigfig.com": null,
"track.sitetag.us": null,
"track.social.com": null,
"track.spots.im": null,
"track.sprinklecontent.com": null,
"track.strife.com": null,
"track.td3x.com": null,
"track.untd.com": null,
"track.vscash.com": null,
"track.written.com": null,
"track.yfret.com": null,
"track.yieldsoftware.com": null,
"tracker.beezup.com": null,
"tracker.downdetector.com": null,
"tracker.everestnutrition.com": null,
"tracker.financialcontent.com": null,
"tracker.icerocket.com": null,
"tracker.iqnomy.com": null,
"tracker.issuu.com": null,
"tracker.keywordintent.com": null,
"tracker.marinsoftware.com": null,
"tracker.mgnetwork.com": null,
"tracker.mtrax.net": null,
"tracker.myseofriend.net": null,
"tracker.neon-images.com": null,
"tracker.neon-lab.com": null,
"tracker.roitesting.com": null,
"tracker.seoboost.net": null,
"tracker.timesgroup.com": null,
"tracker.twenga.": null,
"tracker.u-link.me": null,
"tracker.vreveal.com": null,
"tracker2.apollo-mail.net": null,
"trackerapi.truste.com": null,
"trackicollect.ibase.fr": null,
"tracking.adalyser.com": null,
"tracking.allposters.com": null,
"tracking.badgeville.com": null,
"tracking.bidmizer.com": null,
"tracking.cmcigroup.com": null,
"tracking.cmjump.com.au": null,
"tracking.dealerwebwatcher.com": null,
"tracking.drsfostersmith.com": null,
"tracking.dsmmadvantage.com": null,
"tracking.edvisors.com": null,
"tracking.ehavior.net": null,
"tracking.fanbridge.com": null,
"tracking.fccinteractive.com": null,
"tracking.feedperfect.com": null,
"tracking.fits.me": null,
"tracking.g2crowd.com": null,
"tracking.godatafeed.com": null,
"tracking.i-click.com.hk": null,
"tracking.interweave.com": null,
"tracking.jotform.com": null,
"tracking.keywee.co": null,
"tracking.lengow.com": null,
"tracking.listhub.net": null,
"tracking.livingsocial.com": null,
"tracking.maxcdn.com": null,
"tracking.musixmatch.com": null,
"tracking.performgroup.com": null,
"tracking.plattformad.com": null,
"tracking.plinga.de": null,
"tracking.practicefusion.com": null,
"tracking.quillion.com": null,
"tracking.quisma.com": null,
"tracking.rapidape.com": null,
"tracking.searchmarketing.com": null,
"tracking.sembox.it": null,
"tracking.skyword.com": null,
"tracking.sokrati.com": null,
"tracking.sponsorpay.com": null,
"tracking.synthasite.net": null,
"tracking.target2sell.com": null,
"tracking.theeword.co.uk": null,
"tracking.thehut.net": null,
"tracking.tradeking.com": null,
"tracking.waterfrontmedia.com": null,
"tracking.worldmedia.net": null,
"tracking2.channeladvisor.com": null,
"tracking2.interweave.com": null,
"trackingapi.cloudapp.net": null,
"trackingdev.nixxie.com": null,
"tracksys.developlabs.net": null,
"traffic.acwebconnecting.com": null,
"traffic.belaydevelopment.com": null,
"traffic.prod.cobaltgroup.com": null,
"traffic.pubexchange.com": null,
"traffic.shareaholic.com": null,
"trakksocial.googlecode.com": null,
"trax.dirxion.com": null,
"tree-pixel-log.s3.amazonaws.com": null,
"trf.intuitwebsites.com": null,
"triad.technorati.com": null,
"trk.vindicosuite.com": null,
"ts.tradetracker.net": null,
"ttdetect.staticimgfarm.com": null,
"ucounter.ucoz.net": null,
"usage.trackjs.com": null,
"userlog.synapseip.tv": null,
"vertical-stats.huffpost.com": null,
"video-ad-stats.googlesyndication.com": null,
"visit.geocities.com": null,
"visit.webhosting.yahoo.com": null,
"vtracking.in.com": null,
"watch.teroti.com": null,
"webeffective.keynote.com": null,
"weblog.livesport.eu": null,
"weblogger-dynamic-lb.playdom.com": null,
"webservices.websitepros.com": null,
"webstats.motigo.com": null,
"webstats.seoinc.com": null,
"webstats.thaindian.com": null,
"webtracker.apicasystem.com": null,
"webtracker.educationconnection.com": null,
"whoson.creativemark.co.uk": null,
"wibiya-actions.conduit-data.com": null,
"wibiya-june-new-log.conduit-data.com": null,
"widget.perfectmarket.com": null,
"widget.quantcast.com": null,
"win.staticstuff.net": null,
"wp-stat.s3.amazonaws.com": null,
"wstat.wibiya.com": null,
"analytics.mecloud.vn": null,
"aax-us-iad.amazon.com": null,
"acookie.alibaba.com": null,
"adguru.guruji.com": null,
"adv.drtuber.com": null,
"advancedtracker.appspot.com": null,
"adwiretracker.fwix.com": null,
"affiliate.mercola.com": null,
"affiliate.productreview.com.au": null,
"affiliate.resellerclub.com": null,
"affiliates.genealogybank.com": null,
"affiliates.londonmarketing.com": null,
"affiliates.mozy.com": null,
"affiliates.myfax.com": null,
"affiliates.treasureisland.com": null,
"affiliates.vpn.ht": null,
"amp.virginmedia.com": null,
"analytic.imlive.com": null,
"analytics.adfreetime.com": null,
"analytics.archive.org": null,
"analytics.bloomberg.com": null,
"analytics.femalefirst.co.uk": null,
"analytics.global.sky.com": null,
"analytics.go.com": null,
"analytics.gorillanation.com": null,
"analytics.ifood.tv": null,
"analytics.iraiser.eu": null,
"analytics.localytics.com": null,
"analytics.mindjolt.com": null,
"analytics.msnbc.msn.com": null,
"analytics.newsinc.com": null,
"analytics.posttv.com": null,
"analytics.services.distractify.com": null,
"analytics.skyscanner.net": null,
"analytics.slashdotmedia.com": null,
"analytics.teespring.com": null,
"analytics.thenest.com": null,
"analytics.thenewslens.com": null,
"analytics.thevideo.me": null,
"analytics.twitter.com": null,
"analytics.upworthy.com": null,
"analytics.us.archive.org": null,
"analytics.volvocars.com": null,
"analytics.wetpaint.me": null,
"analytics.whatculture.com": null,
"analytics.yahoo.com": null,
"analyze.yahooapis.com": null,
"atax.gamermetrics.com": null,
"atax.gamespy.com": null,
"atax.gamestats.com": null,
"athenatmpbeacon.theglobeandmail.ca": null,
"atrack.allposters.com": null,
"atrack.art.com": null,
"atracktive.collegehumor.com": null,
"b-aws.techcrunch.com": null,
"b.huffingtonpost.com": null,
"b.myspace.com": null,
"b.photobucket.com": null,
"bat.adforum.com": null,
"bats.video.yahoo.com": null,
"bc.yahoo.com": null,
"beacon-1.newrelic.com": null,
"beacon.ehow.com": null,
"beacon.examiner.com": null,
"beacon.indieclicktv.com": null,
"beacon.lycos.com": null,
"beacon.netflix.com": null,
"beacon.nuskin.com": null,
"beacon.search.yahoo.com": null,
"beacon.walmart.com": null,
"beacon.wikia-services.com": null,
"beacon.www.theguardian.com": null,
"beacons.helium.com": null,
"beap-bc.yahoo.com": null,
"bench.uc.cn": null,
"c.microsoft.com": null,
"cbs.wondershare.com": null,
"cdnstats.tube8.com": null,
"chkpt.zdnet.com": null,
"cl.expedia.com": null,
"clck.yandex.com": null,
"click.aliexpress.com": null,
"click.engage.xbox.com": null,
"click.mmosite.com": null,
"click.udimg.com": null,
"click2.cafepress.com": null,
"clicks.hurriyet.com.tr": null,
"clicks.traffictrader.net": null,
"clkstat.china.cn": null,
"clog.go.com": null,
"cls.ichotelsgroup.com": null,
"cmstrendslog.timesnow.tv": null,
"cnt.nicemix.com": null,
"cnt.nuvid.com": null,
"cnt.vivatube.com": null,
"collector-cdn.github.com": null,
"collector.shopstream.co": null,
"collector.shorte.st": null,
"collector.statowl.com": null,
"comms-web-tracking.uswitchinternal.com": null,
"coolertracks.emailroi.com": null,
"count.livetv.ru": null,
"count.prx.org": null,
"count.rin.ru": null,
"counter.entertainmentwise.com": null,
"counter.joins.com": null,
"counter.promodeejay.net": null,
"counter.sina.com.cn": null,
"counter.theconversation.edu.au": null,
"counter.zerohedge.com": null,
"da.virginmedia.com": null,
"data.mic.com": null,
"data.ryanair.com": null,
"data.younow.com": null,
"datacollector.coin.scribol.com": null,
"dmtracking2.alibaba.com": null,
"dw.cnet.com": null,
"ec2-prod-tracker.babelgum.com": null,
"enlightenment.secureshoppingbasket.com": null,
"entry-stats.huffingtonpost.com": null,
"eventlogger.soundcloud.com": null,
"events.privy.com": null,
"events.redditmedia.com": null,
"events.turbosquid.com": null,
"eventtracker.elitedaily.com": null,
"evisit.exeter.ac.uk": null,
"expbl2ro.xbox.com": null,
"expdb2.msn.com": null,
"f.staticlp.com": null,
"fast.forbes.com": null,
"g.msn.com": null,
"ga.nsimg.net": null,
"geo.yahoo.com": null,
"geobeacon.ign.com": null,
"geoip-lookup.vice.com": null,
"geoip.al.com": null,
"geoip.boredpanda.com": null,
"geoip.cleveland.com": null,
"geoip.gulflive.com": null,
"geoip.inquirer.net": null,
"geoip.lehighvalleylive.com": null,
"geoip.masslive.com": null,
"geoip.mlive.com": null,
"geoip.nj.com": null,
"geoip.nola.com": null,
"geoip.oregonlive.com": null,
"geoip.pennlive.com": null,
"geoip.silive.com": null,
"geoip.syracuse.com": null,
"geoip.viamichelin.com": null,
"geoiplookup.wikimedia.org": null,
"glean.pop6.com": null,
"gmonitor.aliimg.com": null,
"imgtrack.domainmarket.com": null,
"immassets.s3.amazonaws.com": null,
"kinesisproxy.hearstlabs.com": null,
"lh.secure.yahoo.com": null,
"lilb2.shutterstock.com": null,
"linkpuls.idg.no": null,
"live-audience.dailymotion.com": null,
"log.data.disney.com": null,
"log.go.com": null,
"log.optimizely.com": null,
"log.snapdeal.com": null,
"log.thevideo.me": null,
"log.vdn.apps.cntv.cn": null,
"log.wat.tv": null,
"logdev.openload.co": null,
"logger.dailymotion.com": null,
"logger.viki.io": null,
"logging.goodgamestudios.com": null,
"loggingservices.tribune.com": null,
"logs.dashlane.com": null,
"lsam.research.microsoft.com": null,
"lslmetrics.djlmgdigital.com": null,
"marketing.alibaba.com": null,
"meter-svc.nytimes.com": null,
"metric.gstatic.com": null,
"metric.inetcore.com": null,
"metrics.apartments.com": null,
"metrics.aws.sitepoint.com": null,
"metrics.cbn.com": null,
"metrics.cnn.com": null,
"metrics.dailymotion.com": null,
"metrics.ee.co.uk": null,
"metrics.extremetech.com": null,
"metrics.tbliab.net": null,
"metrics.ted.com": null,
"metrics.washingtonpost.com": null,
"mp.twitch.tv": null,
"nb.myspace.com": null,
"nmtracking.netflix.com": null,
"oimg.m.cnbc.com": null,
"oimg.mobile.cnbc.com": null,
"optimize-stats.voxmedia.com": null,
"origin-tracking.trulia.com": null,
"partner.worldoftanks.com": null,
"partners.badongo.com": null,
"partners.mysavings.com": null,
"pclick.europe.yahoo.com": null,
"pclick.internal.yahoo.com": null,
"pclick.yahoo.com": null,
"performances.bestofmedia.com": null,
"ping.buto.tv": null,
"pings.blip.tv": null,
"pix.eads.com": null,
"pixel.facebook.com": null,
"pixel.pcworld.com": null,
"pixel.redditmedia.com": null,
"pixels.livingsocial.com": null,
"presentationtracking.netflix.com": null,
"proxypage.msn.com": null,
"pulse-analytics-beacon.reutersmedia.net": null,
"pvstat.china.cn": null,
"rainbow-uk.mythings.com": null,
"rd.meebo.com": null,
"reco.hardsextube.com": null,
"rel.msn.com": null,
"report.shell.com": null,
"revsci.tvguide.com": null,
"roll.bankofamerica.com": null,
"rs.mail.ru": null,
"rta.dailymail.co.uk": null,
"s.youtube.com": null,
"s2.youtube.com": null,
"sana.newsinc.com.s3.amazonaws.com": null,
"scribe.twitter.com": null,
"sense.dailymotion.com": null,
"session-tracker.badcreditloans.com": null,
"sitelife.ehow.com": null,
"sixpack.udimg.com": null,
"smetrics.att.com": null,
"smetrics.delta.com": null,
"sp.udimg.com": null,
"spade.twitch.tv": null,
"spanids.thesaurus.com": null,
"spotlight.accuweather.com": null,
"ssl-stats.wordpress.com": null,
"stat.alibaba.com": null,
"stat.dealtime.com": null,
"stat.ruvr.ru": null,
"stat.torrentbar.com": null,
"statistics.crowdynews.com": null,
"stats.aplus.com": null,
"stats.articlesbase.com": null,
"stats.avg.com": null,
"stats.bbc.co.uk": null,
"stats.behance.net": null,
"stats.binki.es": null,
"stats.blogg.se": null,
"stats.break.com": null,
"stats.cardschat.com": null,
"stats.christianpost.com": null,
"stats.clear-media.com": null,
"stats.ebay.com": null,
"stats.europe.newsweek.com": null,
"stats.eyeviewdigital.com": null,
"stats.farfetch.com": null,
"stats.firedrive.com": null,
"stats.harpercollins.com": null,
"stats.ibtimes.co.in": null,
"stats.macmillanusa.com": null,
"stats.mehrnews.com": null,
"stats.nymag.com": null,
"stats.opoloo.de": null,
"stats.pandora.com": null,
"stats.paste2.org": null,
"stats.paypal.com": null,
"stats.piaggio.com": null,
"stats.propublica.org": null,
"stats.pusher.com": null,
"stats.radiostreamlive.com": null,
"stats.redditmedia.com": null,
"stats.searchftps.net": null,
"stats.searchftps.org": null,
"stats.searchsight.com": null,
"stats.sharenet.co.za": null,
"stats.shoppydoo.com": null,
"stats.slashgear.com": null,
"stats.slideshare.net": null,
"stats.someecards.com": null,
"stats.storify.com": null,
"stats.suite101.com": null,
"stats.thevideo.me": null,
"stats.townnews.com": null,
"stats.tvmaze.com": null,
"stats.uswitch.com": null,
"stats.vc.gg": null,
"stats.video.search.yahoo.com": null,
"stats.visistat.com": null,
"stats.vulture.com": null,
"stats.wordpress.com": null,
"stats.wwd.com": null,
"stats.wwitv.com": null,
"stats.ynet.co.il": null,
"stats.zmags.com": null,
"statscol.pond5.com": null,
"statstracker.celebrity-gossip.net": null,
"stattrack.0catch.com": null,
"stcollection.moneysupermarket.com": null,
"streamstats1.blinkx.com": null,
"sugar.gameforge.com": null,
"surveys.cnet.com": null,
"t.blinkist.com": null,
"t.dailymail.co.uk": null,
"t.paypal.com": null,
"tag-stats.huffpost.com": null,
"ted.dailymail.co.uk": null,
"timeslogtn.timesnow.tv": null,
"timestrends.timesnow.tv": null,
"tk.kargo.com": null,
"total.shanghaidaily.com": null,
"tracelog.www.alibaba.com": null,
"track.briskfile.com": null,
"track.catalogs.com": null,
"track.cbs.com": null,
"track.codepen.io": null,
"track.collegehumor.com": null,
"track.dictionary.com": null,
"track.engagesciences.com": null,
"track.ft.com": null,
"track.fxstreet.com": null,
"track.gawker.com": null,
"track.hubspot.com": null,
"track.netzero.net": null,
"track.ning.com": null,
"track.promptfile.com": null,
"track.pushbullet.com": null,
"track.slideshare.net": null,
"track.thesaurus.com": null,
"track.ugamezone.com": null,
"track.webgains.com": null,
"track.websiteceo.com": null,
"track.wildblue.com": null,
"track.zalando.": null,
"track.zomato.com": null,
"tracker.anandtech.com": null,
"tracker.calameo.com": null,
"tracker.cpapath.com": null,
"tracker.joost.com": null,
"tracker.lolalytics.com": null,
"tracker.mattel.com": null,
"tracker.pinnaclesports.com": null,
"tracker.realclearpolitics.com": null,
"tracker.redditmedia.com": null,
"tracker.revip.info": null,
"tracker.secretescapes.com": null,
"tracker.uprinting.com": null,
"tracker.washtimes.com": null,
"tracker.wordstream.com": null,
"tracking.ancestry.com": null,
"tracking.batanga.com": null,
"tracking.battleon.com": null,
"tracking.carprices.com": null,
"tracking.carsales.com.au": null,
"tracking.chacha.com": null,
"tracking.conduit.com": null,
"tracking.eurosport.com": null,
"tracking.goodgamestudios.com": null,
"tracking.hsn.com": null,
"tracking.koego.com": null,
"tracking.military.com": null,
"tracking.moneyam.com": null,
"tracking.mycapture.com": null,
"tracking.olx-st.com": null,
"tracking.olx.": null,
"tracking.porndoelabs.com": null,
"tracking.realtor.com": null,
"tracking.resumecompanion.com": null,
"tracking.shoptogether.buy.com": null,
"tracking.softwareprojects.com": null,
"tracking.tidalhifi.com": null,
"tracking.times247.com": null,
"tracking.ukwm.co.uk": null,
"tracking.unrealengine.com": null,
"tracking.ustream.tv": null,
"tracking.yourfilehost.com": null,
"trackpm.shop2market.com": null,
"traffic.buyservices.com": null,
"traffic.tuberip.com": null,
"trax.tvguide.com": null,
"trueffect.underarmour.com": null,
"up.nytimes.com": null,
"uptpro.homestead.com": null,
"urchin-tracker.bigpoint.net": null,
"vertical-stats.huffingtonpost.com": null,
"video-stats.video.google.com": null,
"videotracker.washingtonpost.com": null,
"visit.dealspwn.com": null,
"visit.mobot.net": null,
"visit.theglobeandmail.com": null,
"visitors.sourcingmap.com": null,
"vitamine.networldmedia.net": null,
"vstat.vidigy.com": null,
"vstats.digitaltrends.com": null,
"weblog.strawberrynet.com": null,
"weblogger01.data.disney.com": null,
"webstats.perfectworld.com": null,
"wtk.db.com": null,
"wusstrack.wunderground.com": null,
"wzus1.thesaurus.com": null,
"ynuf.alibaba.com": null,
"zap.dw-world.de": null };
var bad_da_host_exact_flag = 8455 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 21 rules:
var bad_da_host_regex = `anet*.tradedoubler.com
imp*.tradedoubler.com
adr-*.vindicosuite.com
cas.*.criteo.com
caw.*.criteo.com
images.*.criteo.net
banners*.spacash.com
sextronix.*.cdnaccess.com
ads-*.hulu.com
img*.i-comers.com
plundermedia.com*rectangle-
analytics-beacon-*.amazonaws.com
collector-*.elb.amazonaws.com
collector-*.tvsquared.com
datacollect*.abtasty.com
metro-trending-*.amazonaws.com
siteintercept*.qualtrics.com
trk*.vidible.tv
vtnlog-*.elb.amazonaws.com
logger-*.dailymotion.com
metric*.rediff.com`;
var bad_da_host_regex_flag = 21 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 4252 rules:
var bad_da_hostpath_JSON = { "ad.admitad.com/banner": null,
"ad.admitad.com/f": null,
"ad.admitad.com/fbanner": null,
"ad.admitad.com/j": null,
"ad.atdmt.com/i/a.html": null,
"ad.atdmt.com/i/a.js": null,
"ad.mo.doubleclick.net/dartproxy": null,
"doubleclick.net/ad": null,
"doubleclick.net/adi": null,
"doubleclick.net/adj": null,
"doubleclick.net/adx": null,
"doubleclick.net/N2/pfadx/video.allthingsd.com": null,
"doubleclick.net/N2/pfadx/video.marketwatch.com": null,
"doubleclick.net/N2/pfadx/video.wsj.com": null,
"doubleclick.net/N3626/pfadx/thehothits.com.au": null,
"doubleclick.net/N5202/pfadx/cmn_livemixtapes": null,
"doubleclick.net/N6088/pfadx/ssp.kshb": null,
"doubleclick.net/N6872/pfadx/shaw.mylifetimetv.ca": null,
"doubleclick.net/pfadx/aetn.aetv.shows": null,
"doubleclick.net/pfadx/belo.king5.pre": null,
"doubleclick.net/pfadx/bet.com": null,
"doubleclick.net/pfadx/bzj.bizjournals": null,
"doubleclick.net/pfadx/cblvsn.nwsd.videogallery": null,
"doubleclick.net/pfadx/ctv.ctvwatch.ca": null,
"doubleclick.net/pfadx/ctv.muchmusic.com": null,
"doubleclick.net/pfadx/ctv.spacecast": null,
"doubleclick.net/pfadx/ddm.ksl": null,
"doubleclick.net/pfadx/gn.movieweb.com": null,
"doubleclick.net/pfadx/intl.sps.com": null,
"doubleclick.net/pfadx/ltv.wtvr.video": null,
"doubleclick.net/pfadx/miniclip.midvideo": null,
"doubleclick.net/pfadx/miniclip.prevideo": null,
"doubleclick.net/pfadx/muzumain": null,
"doubleclick.net/pfadx/muzuoffsite": null,
"doubleclick.net/pfadx/nbcu.nbc": null,
"doubleclick.net/pfadx/nbcu.nhl": null,
"doubleclick.net/pfadx/ndm.tcm": null,
"doubleclick.net/pfadx/ng.videoplayer": null,
"doubleclick.net/pfadx/ssp.kgtv": null,
"doubleclick.net/pfadx/storm.no": null,
"doubleclick.net/pfadx/sugar.poptv": null,
"doubleclick.net/pfadx/tmz.video.wb.dart": null,
"doubleclick.net/pfadx/ugo.gv.1up": null,
"doubleclick.net/pfadx/video.marketwatch.com": null,
"doubleclick.net/pfadx/video.wsj.com": null,
"googletagservices.com/tag/static": null,
"ltassrv.com/goads.swf": null,
"serving-sys.com/BurstingPipe": null,
"serving-sys.com/BurstingRes": null,
"view.atdmt.com/partner": null,
"zanox-affiliate.de/ppv": null,
"zanox.com/ppv": null,
"ad.doubleclick.net/ddm/trackclk": null,
"000webhost.com/images/banners": null,
"1-million-usd.com/images/banners": null,
"110mb.com/images/banners": null,
"12dayswidget.com/widgets": null,
"1page.co.za/affiliate": null,
"1stag.com/main/img/banners": null,
"1whois.org/static/popup.js": null,
"24.com//flashplayer/ova-jw.swf": null,
"24hrlikes.com/images": null,
"2yu.in/banner": null,
"360pal.com/ads": null,
"3dots.co.il/pop": null,
"a1channel.net/img/downloadbtn2.png": null,
"a1channel.net/img/watch_now.gif": null,
"abacast.com/banner": null,
"ablacrack.com/popup-pvd.js": null,
"ad-v.jp/adam": null,
"ad2links.com/js": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"adap.tv/redir/plugins": null,
"adap.tv/redir/plugins3": null,
"adf.ly/images/banners": null,
"adimgs.t2b.click/assets/js/ttbir.js": null,
"agoda.net/banners": null,
"ahlanlive.com/newsletters/banners": null,
"airvpn.org/images/promotional": null,
"akamaihd.net/lmedianet.js": null,
"allsend.com/public/assets/images": null,
"alpsat.com/banner": null,
"altushost.com/docs": null,
"amazonaws.com/ad_w_intersitial.html": null,
"amazonaws.com/bo-assets/production/banner_attachments": null,
"amazonaws.com/btrb-prd-banners": null,
"amazonaws.com/fvefwdds": null,
"amazonaws.com/lms/sponsors": null,
"amazonaws.com/photos.offers.analoganalytics.com": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"amazonaws.com/promotions": null,
"amazonaws.com/publishflow": null,
"amazonaws.com/skyscrpr.js": null,
"amazonaws.com/streetpulse/ads": null,
"amazonaws.com/wafmedia6.com": null,
"amazonaws.com/widgets.youcompare.com.au": null,
"amazonaws.com/youpop": null,
"any.gs/visitScript": null,
"aolcdn.com/os/mapquest/marketing/promos": null,
"aolcdn.com/os/mapquest/promo-images": null,
"api.groupon.com/v2/deals": null,
"appdevsecrets.com/images/nuts": null,
"apple.com/itunesaffiliates": null,
"appsgenius.com/images": null,
"artistdirect.com/partner": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"assets.betterbills.com/widgets": null,
"astalavista.box.sk/c-astalink2a.jpg": null,
"astrology.com/partnerpages": null,
"atomicpopularity.com/dfpd.js": null,
"autotrader.co.za/partners": null,
"axandra.com/affiliates": null,
"b92s.net/images/banners": null,
"babylon.com/site/images/common.js": null,
"bamstudent.com/files/banners": null,
"bannermaken.nl/banners": null,
"bbcchannels.com/workspace/uploads": null,
"bc.vc/js/link-converter.js": null,
"beachcamera.com/assets/banners": null,
"bee4.biz/banners": null,
"besthosting.ua/banner": null,
"bestofmedia.com/ws/communicationSpot.php": null,
"bet-at-home.com/oddbanner.aspx": null,
"betterbills.com.au/widgets": null,
"betwaypartners.com/affiliate_media": null,
"bharatmatrimony.com/matrimoney/matrimoneybanners": null,
"bigrock.in/affiliate": null,
"binbox.io/public/img/promo": null,
"binopt.net/banners": null,
"bitcoinwebhosting.net/banners": null,
"bittorrent.am/serws.php": null,
"blinkx.com/f2/overlays": null,
"blissful-sin.com/affiliates": null,
"blogatus.com/images/banner": null,
"bloodstock.uk.com/affiliates": null,
"bluehost-cdn.com/media/partner/images": null,
"bluepromocode.com/images/widgets": null,
"bollyrulez.net/media/adz": null,
"bordernode.com/images": null,
"borrowlenses.com/affiliate": null,
"bpath.com/affiliates": null,
"bravenet.com/cserv.php": null,
"brettterpstra.com/wp-content/uploads": null,
"bruteforceseo.com/affiliates": null,
"bruteforcesocialmedia.com/affiliates": null,
"btguard.com/images": null,
"bubbles-uk.com/banner": null,
"businessnewswatch.ca/images/nnwbanner": null,
"buyhatke.com/widgetBack": null,
"cachefly.net/cricad.html": null,
"cactusvpn.com/images/affiliates": null,
"cal-one.net/ellington/deals_widget.php": null,
"carbiz.in/affiliates-and-partners": null,
"careerjunction.co.za/widgets": null,
"carfax.com/img_myap": null,
"cashmyvideo.com/images/cashmyvideo_banner.gif": null,
"casti.tv/adds": null,
"cbpirate.com/getimg.php": null,
"cccam.co/banner_big.gif": null,
"cdn.cdncomputer.com/js/main.js": null,
"cdn.ndparking.com/js/init.min.js": null,
"cdn.sweeva.com/images": null,
"cdn77.org/tags": null,
"cdnpark.com/scripts/js3.js": null,
"cdnprk.com/scripts/js3.js": null,
"cdnprk.com/scripts/js3caf.js": null,
"cdnservices.net/megatag.js": null,
"centralscotlandjoinery.co.uk/images/csj-125.gif": null,
"centrora.com//store/image": null,
"cex.io/img/b": null,
"cfcdn.com/showcase_sample/search_widget": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"chameleon.ad/banner": null,
"cimg.in/images/banners": null,
"citygridmedia.com/ads": null,
"clicktripz.com/scripts/js/ct.js": null,
"cloudbet.com/ad": null,
"cloudfront.net/dfpd.js": null,
"cloudfront.net/nimblebuy": null,
"cloudfront.net/scripts/js3caf.js": null,
"cloudfront.net/st.js": null,
"cloudfront.net/tie.js": null,
"cloudzer.net/ref": null,
"cngroup.co.uk/service/creative": null,
"cnnewmedia.co.uk/locker": null,
"codeartlove.com/clients": null,
"complexmedianetwork.com/js/cmnUNT.js": null,
"comx-computers.co.za/banners": null,
"conduit.com//banners": null,
"content.ad/GetWidget.aspx": null,
"couptopia.com/affiliate": null,
"crowdsavings.com/r/banner": null,
"cruiseline.com/widgets": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"crunchyroll.com/awidget": null,
"cursecdn.com/banner": null,
"customcodebydan.com/images/banner.gif": null,
"cuteonly.com/banners.php": null,
"d1wa9546y9kg0n.cloudfront.net/index.js": null,
"d33t3vvu2t2yu5.cloudfront.net/pub": null,
"dapatwang.com/images/banner": null,
"datafeedfile.com/widget/readywidget": null,
"datakl.com/banner": null,
"dawanda.com/widget": null,
"dealextreme.com/affiliate_upload": null,
"dealtoday.com.mt/banners": null,
"deskbabes.com/ref.php": null,
"desperateseller.co.uk/affiliates": null,
"detroitmedia.com/jfry": null,
"developermedia.com/a.min.js": null,
"devil-bet.com/banner": null,
"digitalmediacommunications.com/belleville/employment": null,
"digitalsatellite.tv/banners": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"dorabet.com/banner": null,
"dot.tk/urlfwd/searchbar/bar.html": null,
"dotz123.com/run.php": null,
"download.bitdefender.com/resources/media": null,
"dramafever.com/widget": null,
"dramafeverw2.appspot.com/widget": null,
"dreamhost.com/rewards": null,
"dreamstime.com/banner": null,
"droidnetwork.net/img/dt-atv160.jpg": null,
"droidnetwork.net/img/vendors": null,
"dunhilltraveldeals.com/iframes": null,
"dvdfab.com/images/fabnewbanner": null,
"dx.com/affiliate": null,
"e-tailwebstores.com/accounts/default1/banners": null,
"e-webcorp.com/images": null,
"easy-share.com/images/es20": null,
"easyretiredmillionaire.com/img/aff-img": null,
"eattoday.com.mt/widgets": null,
"ebaycommercenetwork.com/publisher": null,
"eharmony.com.au/partner": null,
"eholidayfinder.com/images/logo.gif": null,
"elliottwave.com/fw/regular_leaderboard.js": null,
"eltexonline.com/contentrotator": null,
"emailcashpro.com/images": null,
"epimg.net/js/pbs": null,
"etoolkit.com/banner": null,
"expekt.com/affiliates": null,
"extensoft.com/artisteer/banners": null,
"extremereach.io/media": null,
"exwp.org/partners": null,
"eyetopics.com/content_images": null,
"facebook.com/audiencenetwork": null,
"fairfaxregional.com.au/proxy/commercial-partner-solar": null,
"familytreedna.com/img/affiliates": null,
"farmholidays.is/iframeallfarmsearch.aspx": null,
"fastcccam.com/images/fcbanner2.gif": null,
"filedownloader.net/design": null,
"filedroid.net/af_ta": null,
"filejungle.com/images/banner": null,
"fileparadox.com/images/banner": null,
"filepost.com/static/images/bn": null,
"filterforge.com/images/banners": null,
"firecenter.pl/banners": null,
"flipkart.com/affiliateWidget": null,
"flixcart.com/affiliate": null,
"flower.com/img/lsh": null,
"followfairy.com/followfairy300x250.jpg": null,
"footymad.net/partners": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"forumimg.ipmart.com/swf/img.php": null,
"fragfestservers.com/bannerb.gif": null,
"freakshare.com/banner": null,
"freakshare.net/banner": null,
"free-football.tv/images/usd": null,
"freetrafficsystem.com/fts/ban": null,
"freshbooks.com/images/banners": null,
"friedrice.la/widget": null,
"frogatto.com/images": null,
"fxcc.com/promo": null,
"fxultima.com/banner": null,
"gamblingwages.com/images": null,
"gameduell.com/res/affiliate": null,
"gameorc.net/a.html": null,
"gamer-network.net/plugins/dfp": null,
"gamersaloon.com/images/banners": null,
"gamesports.net/img/betting_campaigns": null,
"gamingjobsonline.com/images/banner": null,
"garudavega.net/indiaclicks": null,
"getadblock.com/images/adblock_banners": null,
"getnzb.com/img/partner/banners": null,
"getpaidforyourtime.org/basic-rotating-banner": null,
"giffgaff.com/banner": null,
"glam.com/gad": null,
"glam.com/js/widgets/glam_native.act": null,
"globalprocash.com/banner125.gif": null,
"gold4rs.com/images": null,
"goldmoney.com/~/media/Images/Banners": null,
"google.com/pagead": null,
"googlesyndication.com/pagead": null,
"googlesyndication.com/sadbundle": null,
"googlesyndication.com/safeframe": null,
"googlesyndication.com/simgad": null,
"googlesyndication.com/sodar": null,
"googletagservices.com/dcm/dcmads.js": null,
"gorgonprojectinvest.com/images/banners": null,
"govids.net/adss": null,
"graboid.com/affiliates": null,
"graduateinjapan.com/affiliates": null,
"grindabuck.com/img/skyscraper.jpg": null,
"groupon.com/javascripts/common/affiliate_widget": null,
"grscty.com/images/banner": null,
"gsniper.com/images": null,
"guim.co.uk/guardian/thirdparty/tv-site/side.html": null,
"guzzle.co.za/media/banners": null,
"halllakeland.com/banner": null,
"handango.com/marketing/affiliate": null,
"heidiklein.com/media/banners": null,
"hexero.com/images/banner.gif": null,
"hide-my-ip.com/promo": null,
"highepcoffer.com/images/banners": null,
"hitleap.com/assets/banner.png": null,
"hostdime.com/images/affiliate": null,
"hostgator.com/~affiliat/cgi-bin/affiliates": null,
"hostinger.nl/banners": null,
"hostmonster.com/src/js/izahariev": null,
"hoteltravel.com/partner": null,
"hstpnetwork.com/ads": null,
"hyipregulate.com/images/hyipregulatebanner.gif": null,
"hyperfbtraffic.com/images/graphicsbanners": null,
"hyperscale.com/images/adh_button.jpg": null,
"ibsrv.net/ForumSponsor": null,
"ibsrv.net/sponsor_images": null,
"ibvpn.com/img/banners": null,
"idealo.co.uk/priceinfo": null,
"images-pw.secureserver.net/images/100yearsofchevy.gif": null,
"images.youbuy.it/images": null,
"imagetwist.com/banner": null,
"imgdino.com/gsmpop.js": null,
"imgix.net/sponsors": null,
"indeed.fr/ads": null,
"infibeam.com/affiliate": null,
"infomarine.gr/images/banerr.gif": null,
"instant-gaming.com/affgames": null,
"instantpaysites.com/banner": null,
"instaprofitgram.com/images/banners": null,
"integrityvpn.com/img/integrityvpn.jpg": null,
"internetbrands.com/partners": null,
"intexchange.ru/Content/banners": null,
"intoday.in/microsites/sponsor": null,
"iobit.com/partner": null,
"itsup.com/creatives": null,
"iwebzoo.com/banner": null,
"jalbum.net/widgetapi/js/dlbutton.js": null,
"jenningsforddirect.co.uk/sitewide/extras": null,
"jinx.com/content/banner": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"joblet.jp/javascripts": null,
"jobs-affiliates.ws/images": null,
"jubimax.com/banner_images": null,
"jugglu.com/content/widgets": null,
"junction.co.za/widget": null,
"justclicktowatch.to/jstp.js": null,
"jvzoo.com/assets/widget": null,
"k-po.com/img/ebay.png": null,
"keyword-winner.com/demo/images": null,
"knorex.asia/static-firefly": null,
"kontera.com/javascript/lib/KonaLibInline.js": null,
"kozmetikcerrahi.com/banner": null,
"lawdepot.com/affiliate": null,
"leadsleap.com/widget": null,
"legaljobscentre.com/feed/jobad.aspx": null,
"legitonlinejobs.com/images": null,
"lesmeilleurs-jeux.net/images/ban": null,
"lifedaily.com/prebid.js": null,
"lijit.com/adif_px.php": null,
"lijit.com/delivery": null,
"linkconnector.com/tr.php": null,
"linkconnector.com/traffic_record.php": null,
"literatureandlatte.com/gfx/buynowaffiliate.jpg": null,
"liutilities.com/partners": null,
"liveperson.com/affiliates": null,
"localdata.eu/images/banners": null,
"loot.co.za/shop/product.jsp": null,
"lottoelite.com/banners": null,
"lowcountrymarketplace.com/widgets": null,
"ltfm.ca/stats.php": null,
"lucky-ace-casino.net/banners": null,
"lucky-dating.net/banners": null,
"luckyshare.net/images/banners": null,
"lumfile.com/lumimage/ourbanner": null,
"lygo.com/d/toolbar/sponsors": null,
"lynku.com/partners": null,
"magicaffiliateplugin.com/img/mga-125x125.gif": null,
"magniwork.com/banner": null,
"mahndi.com/images/banner": null,
"mantisadnetwork.com/mantodea.min.js": null,
"marinejobs.gr/images/marine_adv.gif": null,
"mastiway.com/webimages": null,
"matchbin.com/javascripts/remote_widget.js": null,
"matrixmails.com/images": null,
"mazda.com.au/banners": null,
"mcclatchyinteractive.com/creative": null,
"media.complex.com/videos/prerolls": null,
"media.domainking.ng/media": null,
"media.enimgs.net/brand/files/escalatenetwork": null,
"mediaon.com/moneymoney": null,
"mediaplex.com/ad/bn": null,
"mediaplex.com/ad/fm": null,
"mediaplex.com/ad/js": null,
"mfcdn.net/store/spotlight": null,
"mightydeals.com/widgets": null,
"mightydeals.s3.amazonaws.com/md_adv": null,
"millionaires-club-international.com/banner": null,
"missnowmrs.com/images/banners": null,
"mkini.net/banners": null,
"mlive.com/js/oas": null,
"mmdcash.com/mmdcash01.gif": null,
"mmosale.com/baner_images": null,
"mobyler.com/img/banner": null,
"mol.im/i/pix/ebay": null,
"moneycontrol.com/share-market-game": null,
"moneywise.co.uk/affiliate": null,
"musicmemorization.com/images": null,
"mybdhost.com/imgv2": null,
"mydownloader.net/banners": null,
"myezbz.com/marketplace/widget": null,
"myfreeresources.com/getimg.php": null,
"myfreeshares.com/120x60b.gif": null,
"myhpf.co.uk/banners": null,
"mylife.com/partner": null,
"mynativeplatform.com/pub2": null,
"mytrafficstrategy.com/images": null,
"myvi.ru/feed": null,
"n.nu/banner.js": null,
"namecheap.com/graphics/linkus": null,
"neogames-tech.com/resources/genericbanners": null,
"netdigix.com/google_banners": null,
"nimblecommerce.com/widget.action": null,
"nitroflare.com/img/banners": null,
"nster.com/tpl/this/js/popnster.js": null,
"nude.mk/images": null,
"nwadealpiggy.com/widgets": null,
"oasap.com/images/affiliate": null,
"obox-design.com/affiliate-banners": null,
"office.eteachergroup.com/leads": null,
"oilofasia.com/images/banners": null,
"onegameplace.com/iframe.php": null,
"origin.getprice.com.au/widgetnewssmall.aspx": null,
"ouo.io/images/banners": null,
"overseasradio.com/affbanner.php": null,
"ovpn.to/ovpn.to/banner": null,
"oxygenboutique.com/Linkshare": null,
"p.pw/banners": null,
"partners.dogtime.com/network": null,
"payza.com/images/banners": null,
"pcmall.co.za/affiliates": null,
"pearlriverusa.com/images/banner": null,
"perfectmoney.com/img/banners": null,
"phonephotographytricks.com/images/banners": null,
"pianoteq.com/images/banners": null,
"picoasis.net/3xlayer.htm": null,
"playbitcoingames.com/images/banners": null,
"playfooty.tv/jojo.html": null,
"pokerjunkie.com/rss": null,
"pokerstars.com/euro_bnrs": null,
"pornturbo.com/tmarket.php": null,
"ppc-coach.com/jamaffiliates": null,
"premium-template.com/banner": null,
"press-start.com/affgames": null,
"pricegrabber.com/cb_table.php": null,
"pricegrabber.com/export_feeds.php": null,
"pricegrabber.com/mlink.php": null,
"pricegrabber.com/mlink3.php": null,
"primeloopstracking.com/affil": null,
"print2webcorp.com/widgetcontent": null,
"privatewifi.com/swf/banners": null,
"propgoluxury.com/partners": null,
"proxies2u.com/images/btn": null,
"proxify.com/i": null,
"proxy.org/blasts.gif": null,
"proxynoid.com/images/referrals": null,
"proxyroll.com/proxybanner.php": null,
"proxysolutions.net/affiliates": null,
"puntersparadise.com.au/banners": null,
"purevpn.com/affiliates": null,
"putlocker.com/images/banners": null,
"quirk.biz/webtracking": null,
"racebets.com/media.php": null,
"radiocentre.ca/randomimages": null,
"rapidgator.net/images/pics": null,
"rapidjazz.com/banner_rotation": null,
"ratesupermarket.ca/widgets": null,
"rbth.ru/widget": null,
"rdio.com/media/images/affiliate": null,
"readme.ru/informer": null,
"redbeacon.com/widget": null,
"redflagdeals.com/dealoftheday/widgets": null,
"relink.us/images": null,
"resources.heavenmedia.net/selection.php": null,
"rewards1.com/images/referralbanners": null,
"roadrecord.co.uk/widget.js": null,
"roshansports.com/iframe.php": null,
"runerich.com/images/sty_img/runerich.gif": null,
"russian-dreams.net/static/js": null,
"s3.amazonaws.com/draftset/banners": null,
"safarinow.com/affiliate-zone": null,
"salemwebnetwork.com/Stations/images/SiteWrapper": null,
"sat-shop.co.uk/images": null,
"satshop.tv/images/banner": null,
"schurzdigital.com/deals/widget": null,
"sciencecareers.org/widget": null,
"sciremedia.tv/images/banners": null,
"scoopdragon.com/images/Goodgame-Empire-MPU.jpg": null,
"secondspin.com/twcontent": null,
"secureupload.eu/banners": null,
"seedsman.com/affiliate": null,
"selectperformers.com/images/a": null,
"selectperformers.com/images/elements/bannercolours": null,
"server4.pro/images/banner.jpg": null,
"serverjs.net/scripts": null,
"service.smscoin.com/js/sendpic.js": null,
"sfimg.com/images/banners": null,
"sfimg.com/SFIBanners": null,
"sfm-offshore.com/images/banners": null,
"shareasale.com/image": null,
"shareflare.net/images": null,
"shariahprogram.ca/banners": null,
"shink.in/js/script.js": null,
"shop-top1000.com/images": null,
"shopbrazos.com/widgets": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"shorte.st/link-converter.min.js": null,
"shows-tv.net/codepopup.js": null,
"sidekickunlock.net/banner": null,
"singlehop.com/affiliates": null,
"singlemuslim.com/affiliates": null,
"sisters-magazine.com/iframebanners": null,
"site5.com/creative": null,
"sitegiant.my/affiliate": null,
"skydsl.eu/banner": null,
"slysoft.com/img/banner": null,
"smartasset.com/embed.js": null,
"smilepk.com/bnrsbtns": null,
"snacktools.net/bannersnack": null,
"socialmonkee.com/images": null,
"socialorganicleads.com/interstitial": null,
"softneo.com/popup.js": null,
"speedtv.com.edgesuite.net/img/static/takeovers": null,
"spilcdn.com/vda/css/sgadfamily.css": null,
"spilcdn.com/vda/css/sgadfamily2.css": null,
"spilcdn.com/vda/vendor/flowplayer/ova.swf": null,
"splashpagemaker.com/images": null,
"sportingbet.com.au/sbacontent/puntersparadise.html": null,
"sportsdigitalcontent.com/betting": null,
"ssshoesss.ro/banners": null,
"stacksocial.com/bundles": null,
"stargames.com/bridge.asp": null,
"static.plista.com/tiny": null,
"static.plista.com/upload/videos": null,
"static.tumblr.com/dhqhfum/WgAn39721/cfh_header_banner_v2.jpg": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"storage.to/affiliate": null,
"stuff.com/javascripts/more-stuff.js": null,
"surveymonkey.com/jspop.aspx": null,
"sweed.to/affiliates": null,
"synapsys.us/widgets/chatterbox": null,
"synapsys.us/widgets/dynamic_widget": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"take2.co.za/misc/bannerscript.php": null,
"techbargains.com/inc_iframe_deals_feed.cfm": null,
"techbargains.com/scripts/banner.js": null,
"techkeels.com/creatives": null,
"tedswoodworking.com/images/banners": null,
"textlinks.com/images/banners": null,
"thatfreething.com/images/banners": null,
"theatm.info/images": null,
"thebloggernetwork.com/demandfusion.js": null,
"thefreesite.com/nov99bannov.gif": null,
"themify.me/banners": null,
"thereadystore.com/affiliate": null,
"theseblogs.com/visitScript": null,
"theseforums.com/visitScript": null,
"ticketkai.com/banner": null,
"ticketmaster.com/promotionalcontent": null,
"toksnn.com/ads": null,
"tonefuse.s3.amazonaws.com/clientjs": null,
"topmedia.com/external": null,
"topservers200.com/img/banners": null,
"toptenreviews.com/w/af_widget.js": null,
"torguard.net/images/aff": null,
"toysrus.com/graphics/promo": null,
"tradeboss.com/1/banners": null,
"travel-assets.com/ads": null,
"trialfunder.com/banner": null,
"tshirthell.com/img/affiliate_section": null,
"ukcast.tv/adds": null,
"ukrd.com/images/icons/amazon.png": null,
"ukrd.com/images/icons/itunes.png": null,
"unsereuni.at/resources/img": null,
"uploaded.net/img/public": null,
"uploaded.to/img/public": null,
"uploadstation.com/images/banners": null,
"urtig.net/scripts/js3caf.js": null,
"usersfiles.com/images/72890UF.png": null,
"usfine.com/images/sty_img/usfine.gif": null,
"ussearch.com/preview/banner": null,
"valuechecker.co.uk/banners": null,
"vast.videe.tv/vast-proxy": null,
"vcnewsdaily.com/images/vcnews_right_banner.gif": null,
"viagogo.co.uk/feeds/widget.ashx": null,
"videoweed.es/js/aff.js": null,
"vidible.tv/placement/vast": null,
"vidible.tv/prod/tags": null,
"viglink.com/api/widgets/offerbox.js": null,
"viglink.com/images/pixel.gif": null,
"virool.com/widgets": null,
"virtuagirl.com/ref.php": null,
"visitorboost.com/images": null,
"vitabase.com/images/relationships": null,
"vittgam.net/images/b": null,
"vpnarea.com/affiliate": null,
"vpntunnel.se/aff": null,
"vxite.com/banner": null,
"warezhaven.org/warezhavenbann.jpg": null,
"warrantydirect.co.uk/widgets": null,
"watch-naruto.tv/images": null,
"web2feel.com/images": null,
"webdev.co.zw/images/banners": null,
"webgains.com/link.html": null,
"widgeo.net/popup.js": null,
"wildamaginations.com/mdm/banner": null,
"winsms.co.za/banner": null,
"wishlistproducts.com/affiliatetools": null,
"wonderlabs.com/affiliate_pro/banners": null,
"worldnow.com/images/incoming/RTJ/rtj201303fall.jpg": null,
"worldofjudaica.com/products/dynamic_banner": null,
"worldofjudaica.com/static/show/external": null,
"wupload.com/images/banners": null,
"wupload.com/referral": null,
"x3cms.com/ads": null,
"xcams.com/livecams/pub_collante/script.php": null,
"xproxyhost.com/images/banners": null,
"yimg.com/gs/apex/mediastore": null,
"you-cubez.com/images/banners": null,
"youinsure.co.za/frame": null,
"zergnet.com/zerg-inf.js": null,
"zeusfiles.com/promo": null,
"ziffdavisenterprise.com/contextclicks": null,
"zip2save.com/widget.php": null,
"adfoc.us/serve": null,
"chaturbate.com/affiliates": null,
"coolguruji.com/l.php": null,
"erotikdeal.com/advertising.html": null,
"fulltiltpoker.com/affiliates": null,
"homemadecelebrityporn.com/track": null,
"hyperlinksecure.com/go": null,
"lovefilm.com/partners": null,
"planet49.com/cgi-bin/wingame.pl": null,
"promo.xcasino.com": null,
"protect-your-privacy.net": null,
"red-tube.com/popunder": null,
"thefile.me/apu.php": null,
"virtuagirl.com/landing": null,
"204.140.25.247/ads": null,
"213.174.130.10/banners": null,
"213.174.130.8/banners": null,
"213.174.130.9/banners": null,
"213.174.140.76/js/showbanner4.js": null,
"4tube.com/iframe": null,
"adultfax.com/service/vsab.php": null,
"adultfriendfinder.com/go": null,
"adultfriendfinder.com/images/banners": null,
"adultfriendfinder.com/javascript": null,
"adultporntubemovies.com/images/banners": null,
"aebn.net/banners": null,
"allanalpass.com/visitScript": null,
"amateurseite.com/banner": null,
"animalsexfun.com/baner": null,
"asianbutterflies.com/potd": null,
"assinclusive.com/linkstxt2.html": null,
"avatraffic.com/b": null,
"bigmovies.com/images/banners": null,
"blackbrazilianshemales.com/bbs/banners": null,
"bongacams.com/promo.php": null,
"bongacash.com/dynamic_banner": null,
"bongacash.com/promo.php": null,
"bongacash.com/tools/promo.php": null,
"brasileirinhas.com.br/banners": null,
"brazzers.com/ads": null,
"camelmedia.net/thumbs": null,
"cams.com/go": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"camsoda.com/promos": null,
"camsrule.com/exports": null,
"chaturbate.com/creative": null,
"closepics.com/media/banners": null,
"cockfortwo.com/track": null,
"crocogirls.com/croco-new.js": null,
"ddfcash.com/iframes": null,
"devilgirls.co/images/devil.gif": null,
"devilgirls.co/pop.js": null,
"dom2xxx.com/ban": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"eliterotica.com/images/banners": null,
"escortforum.net/images/banners": null,
"evilangel.com/static": null,
"exposedemos.com/track": null,
"exposedteencelebs.com/banner": null,
"extremeladyboys.com/elb/banners": null,
"f5porn.com/porn.gif": null,
"fastcdn.me/js/snpp": null,
"fastcdn.me/mlr": null,
"fleshlight.com/images/banners": null,
"fleshlight.com/images/peel": null,
"freebbw.com/webcams.html": null,
"freeporn.hu/banners": null,
"gagthebitch.com/track": null,
"gammasites.com/pornication/pc_browsable.php": null,
"gfrevenge.com/vbanners": null,
"girls-home-alone.com/dating": null,
"go2cdn.org/brand": null,
"hardbritlads.com/banner": null,
"hentaikey.com/images/banners": null,
"highrollercams.com/widgets": null,
"hodun.ru/files/promo": null,
"homoactive.tv/banner": null,
"hostave3.net/hvw/banners": null,
"hosting24.com/images/banners": null,
"hotcaracum.com/banner": null,
"hotkinkyjo.xxx/resseler/banners": null,
"hotmovies.com/custom_videos.php": null,
"ihookup.com/configcreatives": null,
"images.elenasmodels.com/Upload": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"interracialbangblog.info/banner.jpg": null,
"justcutegirls.com/banners": null,
"kau.li/yad.js": null,
"kuntfutube.com/bgbb.gif": null,
"lacyx.com/images/banners": null,
"ladyboygoo.com/lbg/banners": null,
"latinteencash.com/potd": null,
"longmint.com/lm/banners": null,
"lucasentertainment.com/banner": null,
"magazine-empire.com/images/pornstarad.jpg": null,
"match.com/landing": null,
"mrskin.com/affiliateframe": null,
"mtoon.com/banner": null,
"mycams.com/freechat.php": null,
"myexposedgirlfriendz.com/pop/popuppp.js": null,
"myexposedgirlfriendz.com/pop/popuprk.js": null,
"myfreakygf.com/www/click": null,
"mykocam.com/js/feeds.js": null,
"mysexjourney.com/revenue": null,
"naked.com/promos": null,
"nakedshygirls.com/bannerimg": null,
"nakedswordcashcontent.com/videobanners": null,
"natuko-miracle.com/banner": null,
"naughtycdn.com/public/iframes": null,
"netvideogirls.com/adultfyi.jpg": null,
"nude.hu/html": null,
"nudemix.com/widget": null,
"orgasmtube.com/js/superP": null,
"otcash.com/images": null,
"plugin-x.com/rotaban": null,
"pokazuwka.com/popu": null,
"pop6.com/banners": null,
"porn2blog.com/wp-content/banners": null,
"pornravage.com/notification": null,
"prettyincash.com/premade": null,
"privatamateure.com/promotion": null,
"private.com/banner": null,
"pussycash.com/content/banners": null,
"putana.cz/banners": null,
"rabbitporno.com/friends": null,
"rabbitporno.com/iframes": null,
"rawtubelive.com/exports": null,
"realitykings.com/vbanners": null,
"red-tube.com/dynbanner.php": null,
"rexcams.com/misc/iframes_new": null,
"rotci.com/images/rotcibanner.png": null,
"ruscams.com/promo": null,
"russkoexxx.com/ban": null,
"sakuralive.com/dynamicbanner": null,
"scoreland.com/banner": null,
"sexgangsters.com/sg-banners": null,
"sextronix.com/b": null,
"sextronix.com/images": null,
"sextubepromo.com/ubr": null,
"sexycams.com/exports": null,
"share-image.com/borky": null,
"shemale.asia/sma/banners": null,
"shemalenova.com/smn/banners": null,
"shinypics.com/blogbanner": null,
"simonscans.com/banner": null,
"snrcash.com/profilerotator": null,
"spacash.com//v2bannerview.php": null,
"spacash.com/popup": null,
"spacash.com/tools/peel": null,
"sponsor4cash.de/script": null,
"streamen.com/exports": null,
"streamray.com/images/cams/flash/cams_live.swf": null,
"swurve.com/affiliates": null,
"teendaporn.com/rk.js": null,
"thrixxx.com/affiliates": null,
"thrixxx.com/scripts/show_banner.php": null,
"tlavideo.com/affiliates": null,
"ts.videosz.com/iframes": null,
"turbolovervidz.com/fling": null,
"twiant.com/img/banners": null,
"updatetube.com/iframes": null,
"updatetube.com/updatetube_html": null,
"uramov.info/wav/wavideo.html": null,
"vidz.com/promo_banner": null,
"vigrax.pl/banner": null,
"virtualhottie2.com/cash/tools/banners": null,
"visit-x.net/promo": null,
"vs3.com/_special/banners": null,
"vzzk.com/uploads/banners": null,
"wafflegirl.com/galleries/banner": null,
"watchmygf.com/preview": null,
"webcams.com/js/im_popup.php": null,
"webcams.com/misc/iframes_new": null,
"wetandpuffy.com/galleries/banners": null,
"xlgirls.com/banner": null,
"xtrasize.pl/banner": null,
"xxxoh.com/number": null,
"yamvideo.com/pop1": null,
"yplf.com/ram/files/sponsors": null,
"adultfriendfinder.com/banners": null,
"amarotic.com": null,
"babecams.net/landing": null,
"cam4.com": null,
"candidvoyeurism.com/ads": null,
"chaturbate.com/sitestats/openwindow": null,
"devilsfilm.com/track/go.php": null,
"fantasti.cc/ajax/gw.php": null,
"flirt4free.com/_special/pops": null,
"fuckbookhookups.com/go": null,
"fuckbooknet.net/dating": null,
"fucktapes.org/fucktube.htm": null,
"hqtubevideos.com/play.html": null,
"imlive.com/wmaster.ashx": null,
"join.teamskeet.com/track": null,
"judgeporn.com/video_pop.php": null,
"letstryanal.com/track": null,
"mydirtyhobby.com": null,
"porno-onlain.info/top.php": null,
"pornslash.com/cbp.php": null,
"redtube.com/bid": null,
"rudefinder.com": null,
"sex.com/popunder": null,
"sexier.com/services/adsredirect.ashx": null,
"socialflirt.com/go": null,
"teenslikeitbig.com/track": null,
"topbucks.com/popunder": null,
"twistys.com/track": null,
"videobox.com/tour": null,
"videosz.com/search.php": null,
"xdating.com/search": null,
"xvideoslive.com/landing": null,
"10-fast-fingers.com/quotebattle-ad.png": null,
"100best-free-web-space.com/images/ipage.gif": null,
"1071radio.com//wp-content/banners": null,
"11points.com/images/slack100.jpg": null,
"1320wils.com/assets/images/promo%20banner": null,
"1337x.to/js/script.js": null,
"1340wcmi.com/images/banners": null,
"1590wcgo.com/images/banners": null,
"1776coalition.com/wp-content/plugins/sam-images": null,
"180upload.com/p1.js": null,
"180upload.com/pir/729.js": null,
"1up.com/scripts/takeover.js": null,
"1up.com/vip/vip_games.html": null,
"2ca.com.au/images/banners": null,
"2cc.net.au/images/banners": null,
"2flashgames.com/img/nfs.gif": null,
"2merkato.com/images/banners": null,
"2mfm.org/images/banners": null,
"2pass.co.uk/img/avanquest2013.gif": null,
"3dsemulator.org/img/download.png": null,
"3pmpickup.com.au/images/kmart_v2.jpg": null,
"4downfiles.com/open1.js": null,
"4fastfile.com/afiliat.png": null,
"4fuckr.com/g": null,
"4shared.com/images/label1.gif": null,
"4sharedtrend.com/ifx/ifx.php": null,
"5star-shareware.com/scripts/5starads.js": null,
"88.80.16.183/streams/counters": null,
"8a.nu/site2/sponsors": null,
"8ch.net/proxy.php": null,
"947fm.bb/images/banners": null,
"aaugh.com/images/dreamhostad.gif": null,
"abook.ws/banner6.png": null,
"abook.ws/pyload.png": null,
"aboutmyarea.co.uk/images/imgstore": null,
"aboutmyip.com/images/SynaManBanner.gif": null,
"abovetopsecret.com/images/plexidigest-300x300.jpg": null,
"abusewith.us/banner.gif": null,
"acidcow.com/banners.php": null,
"adaderana.lk/banners": null,
"adirondackmtnclub.com/images/banner": null,
"adv.li/ads": null,
"advpc.net/site_img/banner": null,
"aerotime.aero/upload/banner": null,
"afmradio.co.za/images/slider": null,
"africanbusinessmagazine.com/images/banners": null,
"afternoondc.in/banners": null,
"agriculturalreviewonline.com/images/banners": null,
"ahk-usa.com/uploads/tx_bannermanagement": null,
"akiba-online.com/forum/images/bs.gif": null,
"akipress.org/bimages": null,
"alachuacountytoday.com/images/banners": null,
"alaska-native-news.com/files/banners": null,
"alatest.co.uk/banner": null,
"alatest.com/banner": null,
"allghananews.com/images/banners": null,
"allmyvideos.net/player/ova-jw.swf": null,
"altdaily.com/images/banners": null,
"amazingmoneymagnet.com//upload/banners": null,
"amazonaws.com/cdn.megacpm.com": null,
"americanangler.com/images/banners": null,
"amnesty.ca/images/banners": null,
"anchorfree.com/delivery": null,
"andr.net/banners": null,
"anhits.com/files/banners": null,
"anime44.com/images/videobb2.png": null,
"animeflavor.com/animeflavor-gao-gamebox.swf": null,
"animehaven.org/wp-content/banners": null,
"anonib.com/zimages": null,
"anonytext.tk/img/paste-eb.png": null,
"anonytext.tk/img/paste-sponsor.png": null,
"anonytext.tk/re.php": null,
"anti-scam.org/abanners": null,
"aol.co.uk/images/skybet-logo.gif": null,
"apcointl.org/images/corporate_partners": null,
"ar15.com/images/highlight": null,
"aravot.am/banner": null,
"archeagedatabase.net/images/okaygoods.gif": null,
"armenpress.am/static/add": null,
"armslist.com/images/sponsors": null,
"arnnet.com.au/files/skins": null,
"asianewsnet.net/banner": null,
"asianfanfics.com/sponsors": null,
"askandyaboutclothes.com/images": null,
"astronomy.com/sitefiles/overlays/overlaygenerator.aspx": null,
"astronomynow.com/wp-content/promos": null,
"atimes.com/banner": null,
"attorrents.com/static/images/download3.png": null,
"autoline-eu.co.uk/atlads": null,
"autoline-eu.co.za/atlads": null,
"autoline-eu.ie/atlads": null,
"autoline.info/atlads": null,
"autorrents.com/static/images/download2.png": null,
"autosport.com/img/promo": null,
"aveherald.com/images/banners": null,
"avforums.com/images/skins": null,
"avitop.com/image/amazon": null,
"avitop.com/image/mig-anim.gif": null,
"avitop.com/image/mig.gif": null,
"avsforum.com/alliance": null,
"avstop.com/avbanner": null,
"b92.net/images/banners": null,
"babelzilla.org/forum/images/powerfox-top.png": null,
"babelzilla.org/images/banners/babelzilla-powerfox.png": null,
"babycenter.com/viewadvertorialpoll.htm": null,
"backin.net/images/player_divx.png": null,
"backpagelead.com.au/images/banners": null,
"bahamaslocal.com/img/banners": null,
"bakercountypress.com/images/banners": null,
"baku2015.com/imgml/sponsor": null,
"ballz.co.za/system-files/banners": null,
"banners.friday-ad.co.uk/hpbanneruploads": null,
"bashandslash.com/images/banners": null,
"basinsradio.com/images/banners": null,
"bay.com.mt/images/banners": null,
"bayfiles.net/img/download-button-orange.png": null,
"baymirror.com/static/img/bar.gif": null,
"baymirror.com/static/js/4728ba74bc.js": null,
"bazaraki.com/bannerImage.php": null,
"beforeitsnews.com/static/data/story-stripmall-new.html": null,
"beforeitsnews.com/static/iframe": null,
"belfasttelegraph.co.uk/editorial/web/survey/recruit-div-img.js": null,
"bernama.com/banner": null,
"bestblackhatforum.com/images/my_compas": null,
"bestlistonline.info/link/ad.js": null,
"bets4free.co.uk/content/5481b452d9ce40.09507031.jpg": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"bettyconfidential.com/media/fmads": null,
"bibme.org/images/grammarly": null,
"bigeddieradio.com/uploads/sponsors": null,
"bigsports.tv/live/ado.php": null,
"bikeforums.net/images/sponsors": null,
"bikeradar.com/media/img/commercial": null,
"binsearch.info/iframe.php": null,
"bioinformatics.org/images/ack_banners": null,
"bit-tech.net/images/backgrounds/skin": null,
"bit.no.com/assets/images/bity.png": null,
"bittorrent.am/banners": null,
"blackberryforums.net/banners": null,
"blackcaps.co.nz/img/commercial-partners": null,
"blasternation.com/images/hearthstone.jpg": null,
"bleacherreport.net/images/skins": null,
"blinkx.com/adhocnetwork": null,
"blitzdownloads.com/promo": null,
"blog.co.uk/script/blogs/afc.js": null,
"blogevaluation.com/templates/userfiles/banners": null,
"blogorama.com/images/banners": null,
"blogsdna.com/wp-content/themes/blogsdna2011/images/advertisments.png": null,
"blogspider.net/images/promo": null,
"botswanaguardian.co.bw/images/banners": null,
"boxbit.co.in/banners": null,
"brandchannel.com/images/educationconference": null,
"breitlingsource.com/images/pflogo.jpg": null,
"brenz.net/img/bannerrss.gif": null,
"bristolairport.co.uk/~/media/images/brs/blocks/internal-promo-block-300x250": null,
"broadbandforum.co/stock": null,
"broadbandgenie.co.uk/images/takeover": null,
"broadbandgenie.co.uk/img/talktalk": null,
"brobible.com/files/uploads/images/takeovers": null,
"brothersoft.com/gg/kontera_com.js": null,
"brothersoft.com/gg/soft_down.js": null,
"browsershots.org/static/images/creative": null,
"brudirect.com/images/banners": null,
"bsmphilly.com/files/banners": null,
"bt-chat.com/images/affiliates": null,
"bt.am/banners": null,
"btkitty.com/static/images/880X60.gif": null,
"btkitty.org/static/images/880X60.gif": null,
"businessincameroon.com/images/stories/pub": null,
"buyselltrade.ca/banners": null,
"buzznet.com/topscript.js.php": null,
"bypassoxy.com/vectrotunnel-banner.gif": null,
"c-ville.com/image/pool": null,
"c21media.net/wp-content/plugins/sam-images": null,
"c9tk.com/images/banner": null,
"caclubindia.com/campaign": null,
"cadplace.co.uk/banner": null,
"cafemomstatic.com/images/background": null,
"cafimg.com/images/other": null,
"calgaryherald.com/images/sponsor": null,
"calgaryherald.com/images/storysponsor": null,
"cameroon-concord.com/images/banners": null,
"cananewsonline.com/files/banners": null,
"cancomuk.com/campaigns": null,
"candystand.com/game-track.do": null,
"capitalethiopia.com/images/banners": null,
"caravansa.co.za/images/banners": null,
"card-sharing.net/cccamcorner.gif": null,
"cardschat.com/pkimg/banners": null,
"cars.com/go/includes/targeting": null,
"cars.com/js/cars/catretargeting.js": null,
"cash9.org/assets/img/banner2.gif": null,
"cast4u.tv/adshd.php": null,
"cast4u.tv/fku.php": null,
"casualgaming.biz/banners": null,
"catalystmagazine.net/images/banners": null,
"catholicculture.org/images/banners": null,
"cbc.ca/deals": null,
"cbc.ca/video/bigbox.html": null,
"cbn.co.za/images/banners": null,
"cbsinteractive.co.uk/cbsi/ads": null,
"cbslocal.com/deals/widget": null,
"cd1025.com/www/assets/a": null,
"cdmagurus.com/forum/cyberflashing.swf": null,
"cdmagurus.com/img/kcpf2.swf": null,
"cdn-surfline.com/home/billabong-xxl.png": null,
"celebstoner.com/assets/components/bdlistings/uploads": null,
"celebstoner.com/assets/images/img/top/420VapeJuice960x90V3.gif": null,
"centralfm.co.uk/images/banners": null,
"cghub.com/files/CampaignCode": null,
"ch131.so/images/2etio.gif": null,
"channel4.com/assets/programmes/images/originals": null,
"channel4fm.com/images/background": null,
"channel5.com/assets/takeovers": null,
"channelonline.tv/channelonline_advantage": null,
"chapala.com/wwwboard/webboardtop.htm": null,
"checkpagerank.net/banners": null,
"checkwebsiteprice.com/images/bitcoin.jpg": null,
"chelsey.co.nz/uploads/Takeovers": null,
"chicagodefender.com/images/banners": null,
"chronicle.lu/images/banners": null,
"ciao.co.uk/load_file.php": null,
"citationmachine.net/images/grammarly": null,
"citeulike.org/static/campaigns": null,
"citizen-usa.com/images/banners": null,
"classic-tv.com/pubaccess.html": null,
"classicsdujour.com/artistbanners": null,
"clgaming.net/interface/img/sponsor": null,
"cloudyvideos.com/banner": null,
"cmpnet.com/ads": null,
"cnn.com/cnn_adspaces": null,
"cntv.cn/Library/js/js_ad_gb.js": null,
"cnx-software.com/pic/gateworks": null,
"cnx-software.com/pic/technexion": null,
"coastfm.ae/images/background": null,
"codecguide.com/driverscan2.gif": null,
"codecguide.com/driverscantop1.gif": null,
"coinad.com/op.php": null,
"coinurl.com/bootstrap/js/bootstrapx-clickover.js": null,
"colombiareports.com/wp-content/banners": null,
"com-a.in/images/banners": null,
"com.com/cnwk.1d/aud": null,
"comicbookresources.com/assets/images/skins": null,
"comparestoreprices.co.uk/images/promotions": null,
"compassnewspaper.com/images/banners": null,
"complaintsboard.com/img/202x202.gif": null,
"complaintsboard.com/img/300x250anti.gif": null,
"computerhelp.com/temp/banners": null,
"con-telegraph.ie/images/banners": null,
"concrete.tv/images/banners": null,
"conscioustalk.net/images/sponsors": null,
"convertmyimage.com/images/banner-square.png": null,
"conwaydailysun.com/images/banners": null,
"conwaydailysun.com/images/Tiles_Skyscrapers": null,
"coolfm.us/lagos969/images/banners": null,
"coolmath-games.com/images/160-notice.gif": null,
"coryarcangel.com/images/banners": null,
"countrychannel.tv/telvos_banners": null,
"crackdb.com/img/vpn.png": null,
"craveonline.com/gnads": null,
"crazy-torrent.com/web/banner/0xxx0.net.jpg": null,
"crazy-torrent.com/web/banner/online.jpg": null,
"creattor.net/flashxmlbanners": null,
"cricbuzz.com/js/banners": null,
"cricketireland.ie//images/sponsors": null,
"crimeaware.co.za/files-upload/banner": null,
"crushorflush.com/html/promoframe.html": null,
"ctv.ca/ctvresources/js/ctvad.js": null,
"ctv.ca/Sites/Ctv/assets/js/ctvDfpAd.js": null,
"cur.lv/bootstrap/js/bootstrapx-clickover.js": null,
"currency.wiki/images/out": null,
"cybergamer.com/skins": null,
"d-h.st/assets/img/download1.png": null,
"dabs.com/images/page-backgrounds": null,
"daily-mail.co.zm/images/banners": null,
"dailybitcoins.org/banners": null,
"dailycommercial.com/inc.php": null,
"dailydeal.news-record.com/widgets": null,
"dailydeals.sfgate.com/widget": null,
"dailyexpress.com.my/banners": null,
"dailyexpress.com.my/image/banner": null,
"dailyfreegames.com/js/partners.html": null,
"dailymail.co.uk/i/pix/ebay": null,
"dailymail.co.uk/modules/commercial": null,
"dailymotion.com/images/ie.png": null,
"dailymotion.com/masscast": null,
"dailynews.co.tz/images/banners": null,
"dailypioneer.com/images/banners": null,
"dailypuppy.com/images/livestrong/ls_diet_120x90_1.gif": null,
"dailysabah.com/banner": null,
"dailytimes.com.pk/banners": null,
"dailytrust.com.ng/Image/LATEST_COLEMANCABLE.gif": null,
"dailytrust.info/images/banners": null,
"dailytrust.info/images/dangote.swf": null,
"dainikbhaskar.com/images/sitetakover": null,
"damnlol.com/a/leaderboard.php": null,
"dayport.com/ads": null,
"deborah-bickel.de/banners": null,
"decadeforum.com/images/misc/download2.png": null,
"decryptedtech.com/images/banners": null,
"defenceweb.co.za/images/sponsorlogos": null,
"demerarawaves.com/images/banners": null,
"deseretnews.com/img/sponsors": null,
"deshvidesh.com/banner": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"desixpress.co.uk/image/banners": null,
"develop-online.net/static/banners": null,
"devshed.com/images/backgrounds": null,
"dezeen.com/wp-content/themes/dezeen-aa-hpto-mini-sept-2014": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"diplodocs.com/shopping/sol.js": null,
"dishusa.net/templates/flero/images/book_sprava.gif": null,
"distrogeeks.com/images/sponsors": null,
"distrowatch.com/images/kokoku": null,
"divxme.com/images/play.png": null,
"divxstage.eu/images/download.png": null,
"djmag.co.uk/sites/default/files/takeover": null,
"djmag.com/sites/default/files/takeover": null,
"dl-protect.com/pop.js": null,
"dl4all.com/data4.files/dpopupwindow.js": null,
"dl4all.com/img/download.jpg": null,
"doge-dice.com/images/faucet.jpg": null,
"doge-dice.com/images/outpost.png": null,
"domaintools.com/partners": null,
"downforeveryoneorjustme.com/images/dotbiz_banner.jpg": null,
"downloadbox.to/Leadertop.html": null,
"downloadian.com/assets/banner.jpg": null,
"dpstatic.com/banner.png": null,
"dpstatic.com/s/ad.js": null,
"drhinternet.net/mwimgsent": null,
"droidgamers.com/images/banners": null,
"dubcnm.com/Adon": null,
"duckload.com/js/abp.php": null,
"dump8.com/tiz": null,
"dump8.com/wget.php": null,
"dump8.com/wget_2leep_bottom.php": null,
"dyncdn.celebuzz.com/assets": null,
"e90post.com/forums/images/banners": null,
"earthmoversmagazine.co.uk/nimg": null,
"eastonline.eu/images/banners": null,
"easybytez.com/pop3.js": null,
"easydiy.co.za/images/banners": null,
"eatsleepsport.com/images/manorgaming1.jpg": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"ebookshare.net/pages/lt.html": null,
"ebuddy.com/textlink.php": null,
"ebuddy.com/web_banners": null,
"eclipse.org/membership/promo/images": null,
"ecommerce-journal.com/specdata.php": null,
"ecostream.tv/assets/js/pu.min.js": null,
"ecostream.tv/js/pu.js": null,
"educationbusinessuk.net/images/stage.gif": null,
"ehow.com/images/brands": null,
"ejpress.org/images/banners": null,
"ejpress.org/img/banners": null,
"ekantipur.com/uploads/banner": null,
"electronicsfeed.com/bximg": null,
"elevenmyanmar.com/images/banners": null,
"elgg.org/images/hostupon_banner.gif": null,
"elivetv.in/pop": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"emoneyspace.com/b.php": null,
"empirestatenews.net/Banners": null,
"energytribune.com/res/banner": null,
"englishgrammar.org/images/30off-coupon.png": null,
"enigmagroup.org/clients/privatetunnels.swf": null,
"epicshare.net/p1.js": null,
"eprop.co.za/images/banners": null,
"escapementmagazine.com/wp-content/banners": null,
"esportsheaven.com/media/skins": null,
"esus.com/images/regiochat_logo.png": null,
"eurochannel.com/images/banners": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"europeonline-magazine.eu/banner": null,
"evernote.com/prom/img": null,
"eweek.com/images/stories/marketing": null,
"eweek.com/widgets/ibmtco": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"exashare.com/hq_stream.html": null,
"exashare.com/player_begin.jpg": null,
"exashare.com/player_file.jpg": null,
"exashare.com/playerexa.jpg": null,
"exashare.com/vod_stream.html": null,
"exchangerates.org.uk/images-NEW/tor.gif": null,
"excite.com/gca_iframe.html": null,
"expatexchange.com/banner": null,
"expatwomen.com/expat-women-sponsors": null,
"expressmilwaukee.com/engines/backgrounds/js/backgrounds.js": null,
"expreview.com/exp2": null,
"extremeoverclocking.com/template_images/it120x240.gif": null,
"faadooengineers.com/ads": null,
"famouspornstarstube.com/images/sponsors": null,
"fancystreems.com/300x2503.php": null,
"fanfusion.org/as.js": null,
"fark.com/cgi/buzzfeed_link.pl": null,
"farmville.com/promo_bar.php": null,
"farsnews.com/banner": null,
"fastpic.ru/b": null,
"fastvideo.eu/images/down.png": null,
"fastvideo.eu/images/pl_box_rapid.jpg": null,
"feedsportal.com/creative": null,
"feedsportal.com/videoserve": null,
"ffiles.com/counters.js": null,
"fgfx.co.uk/banner.js": null,
"fhm.com/images/casinobutton.gif": null,
"fhm.com/images/sportsbutton.gif": null,
"fiberupload.org/300en.png": null,
"fightersonlymag.com/images/banners": null,
"fijitimes.com/images/bspxchange.gif": null,
"file-upload.net/include/mitte.php": null,
"file-upload.net/include/rechts.php": null,
"file.org/fo/scripts/download_helpopt.js": null,
"file2hd.com/sweet.jpg": null,
"filedino.com/imagesn/downloadgif.gif": null,
"filefactory.com/img/casinopilots": null,
"filegaga.com/ot/fast.php": null,
"fileom.com/img/downloadnow.png": null,
"fileom.com/img/instadownload2.png": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"filesharingtalk.com/fst/8242": null,
"filespart.com/ot/fast.aspx": null,
"filespazz.com/imx/template_r2_c3.jpg": null,
"filestream.me/requirements/images/cialis_generic.gif": null,
"filestream.me/requirements/images/ed.gif": null,
"filipinojournal.com/images/banners": null,
"filmey.com/Filmey.Ad.js": null,
"filmsite.org/dart-zones.js": null,
"financialnewsandtalk.com/scripts/slideshow-sponsors.js": null,
"findfiles.com/images/icatchallfree.png": null,
"findfiles.com/images/knife-dancing-1.gif": null,
"findfreegraphics.com/underp.js": null,
"findit.com.mt/dynimage/boxbanner": null,
"firedrive.com/appdata": null,
"firstnationsvoice.com/images/weblinks.swf": null,
"firstrows.biz/js/bn.js": null,
"fishchannel.com/images/sponsors": null,
"fiverr.com/javascripts/conversion.js": null,
"flashscore.com/res/image/bookmaker-list.png": null,
"flashx.tv/img/downloadit.png": null,
"flashy8.com/banner": null,
"fleetwatch.co.za/images/banners": null,
"flicks.co.nz/images/takeovers": null,
"flvto.biz/scripts/banners.php": null,
"flyordie.com/games/free/b": null,
"flyordie.com/games/online/ca.html": null,
"foodingredientsfirst.com/content/banners": null,
"foodingredientsfirst.com/content/flash_loaders/loadlargetile.swf": null,
"foodingredientsfirst.com/content/flash_loaders/loadskyscraper.swf": null,
"football-italia.net/imgs/moveyourmouse.gif": null,
"footballshirtculture.com/images/e12b.jpg": null,
"fordforums.com.au/logos": null,
"forexpeacearmy.com/images/banners": null,
"forumw.org/images/uploading.gif": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"foxsports540.com/images/banner1.png": null,
"foxsports540.com/images/banner2.png": null,
"foxsportsradio.com/pages/second300x250iframe.html": null,
"fpscheats.com/banner-img.jpg": null,
"fpscheats.com/fpsbanner.jpg": null,
"freakshare.com/yild.js": null,
"free-times.com/image/pool": null,
"free-tv-video-online.me/300s.html": null,
"free-webhosts.com/images/a": null,
"freeads.co.uk/ctx.php": null,
"freeappaday.com/nimgs/bb": null,
"freemediatv.com/images/inmemoryofmichael.jpg": null,
"freeminecraft.me/mw3.png": null,
"freenode.net/images/ack_privateinternetaccess-freenode.png": null,
"freenode.net/images/freenode_osuosl.png": null,
"freepornsubmits.com/ads": null,
"freeroms.com/bigbox.html": null,
"freesoftwaremagazine.com/extras": null,
"freetypinggame.net/burst720.asp": null,
"freevermontradio.org/pictures/lauren_Stagnitti.jpg": null,
"frenchradiolondon.com/data/carousel": null,
"fresh-weather.com/popup1.gif": null,
"freshremix.org/templates/freshremix_eng/images/300.gif": null,
"freshremix.ru/images/ffdownloader1.jpg": null,
"friday-ad.co.uk/banner.js": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"frombar.com/ads": null,
"frozen-roms.in/popup.php": null,
"frozen-roms.me/popup.php": null,
"fscheetahs.co.za/images/Sponsers": null,
"ftdworld.net/images/banners": null,
"fulhamfc.com/i/partner": null,
"fuse.tv/images/sponsor": null,
"gabzfm.com/images/banners": null,
"gaccmidwest.org/uploads/tx_bannermanagement": null,
"gaccny.com/uploads/tx_bannermanagement": null,
"gaccsouth.com/uploads/tx_bannermanagement": null,
"gaccwest.com/uploads/tx_bannermanagement": null,
"gadget.co.za/siteimages/banners": null,
"game1games.com/exchange": null,
"gameawayscouponsstorage.blob.core.windows.net/images/greenmangaming": null,
"gamecopyworld.com/games/i/if6.gif": null,
"gamecopyworld.com/games/js/abd.js": null,
"gamemakerblog.com/gma/gatob.php": null,
"gamepressure.com/ajax/f2p.asp": null,
"gamerant.com/ads": null,
"gamesfreez.com/banner": null,
"gamesgames.com/vda": null,
"gamevid.com/13/ads": null,
"gamingsquid.com/wp-content/banners": null,
"gappon.com/images/hot2.gif": null,
"garrysmod.org/img/sad": null,
"gateprep.com/templates/default/images/promo": null,
"gaydarradio.com/userportal/miva": null,
"gaynz.com/mysa/banners": null,
"gaynz.gen.nz/mysa/banners": null,
"gbatemp.net/images/ab": null,
"gcnlive.com/assets/sponsors": null,
"gcnlive.com/assets/sponsorsPlayer": null,
"geckoforums.net/banners": null,
"gelbooru.com/x": null,
"gentoo.org/images/sponsors": null,
"geometria.tv/banners": null,
"get-bitcoins-free.eu/img/blackred728smallsize.gif": null,
"getfoxyproxy.org/images/abine": null,
"getrichslowly.org/blog/img/banner": null,
"ghafla.co.ke/images/banners": null,
"ghafla.co.ke/images/bgmax": null,
"ghananewsagency.org/assets/banners": null,
"giftguide.savannahnow.com/giftguide/widgets": null,
"girlguides.co.za/images/banners": null,
"gizmochina.com/images/blackview.jpg": null,
"gledaisport.com/ads": null,
"globaltimes.cn/desktopmodules/bannerdisplay": null,
"glocktalk.com/forums/images/banners": null,
"go4up.com/assets/img/buttoned.gif": null,
"go4up.com/assets/img/d0.png": null,
"go4up.com/assets/img/download-button.png": null,
"go4up.com/assets/img/downloadbuttoned.png": null,
"gokunming.com/images/prom": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"gold1013fm.com/images/background": null,
"gomlab.com/img/banner": null,
"gonzagamer.com/uci/popover.js": null,
"goodgearguide.com.au/files/skins": null,
"gospel1190.net/rotatorimages": null,
"graphic.com.gh/images/banners": null,
"greatdeals.co.ke/images/banners": null,
"greatgirlsgames.com/100x100.php": null,
"greatgirlsgames.com/a/skyscraper.php": null,
"greenoptimistic.com/images/electrician2.png": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"greyorgray.com/images/hdtv-genie-gog.jpg": null,
"gsprating.com/gap/image.php": null,
"gtop100.com/a_images/show-a.php": null,
"gtweekly.com/images/banners": null,
"guardian.bz/images/banners": null,
"gulf-daily-news.com/180x150.htm": null,
"gurgle.com/modules/mod_m10banners": null,
"guru99.com/images/adblocker": null,
"gwinnettdailypost.com/1.iframe.asp": null,
"h33t.to/images/button_direct.png": null,
"ha.ckers.org/images/fallingrock-bot.png": null,
"ha.ckers.org/images/nto_top.png": null,
"ha.ckers.org/images/sectheory-bot.png": null,
"hackingchinese.com/media/hcw4.png": null,
"hackingchinese.com/media/hellochinese.jpg": null,
"hackingchinese.com/media/pleco.png": null,
"hackingchinese.com/media/skritter5.jpg": null,
"hahasport.com/ads": null,
"hawkesbay.co.nz/images/banners": null,
"hdfree.tv/ad.html": null,
"hdtvtest.co.uk/image/partner": null,
"hentai2read.com/ios/swf": null,
"hentaihaven.org/wp-content/banners": null,
"heraldm.com/iframe": null,
"herold.at/images/dealofday.swf": null,
"herzeleid.com/files/images/banners": null,
"hickoryrecord.com/app/deal": null,
"highdefjunkies.com/images/misc/kindlejoin.jpg": null,
"hipforums.com/images/banners": null,
"hitechlegion.com/images/banners": null,
"hkclubbing.com/images/banners": null,
"hltv.org//images/csgofastsky.png": null,
"hltv.org/images/csLucky.swf": null,
"holyfamilyradio.org/banners": null,
"holyfragger.com/images/skins": null,
"hongfire.com/banner": null,
"hongkongindians.com/advimages": null,
"hostingbulk.com/aad.html": null,
"hostingbulk.com/zad.html": null,
"hostsearch.com/creative": null,
"hot-scene.com/cpop.js": null,
"hotbollywoodactress.net/ff2.gif": null,
"hotbollywoodactress.net/freedatingindia.gif": null,
"hotfiletrend.com/dlp.gif": null,
"hothardware.com/pgmerchanttable.aspx": null,
"houseoftravel.co.nz/flash/banner": null,
"howtogermany.com/banner": null,
"hpfanficarchive.com/freecoins2.jpg": null,
"hulkfile.eu/images/africa.gif": null,
"hulkload.com/b": null,
"hulkload.com/recommended": null,
"hulkshare.com/promo": null,
"hwbot.org/banner.img": null,
"hwinfo.com/images/lansweeper.jpg": null,
"hwinfo.com/images/se2banner.png": null,
"hypemagazine.co.za/assets/bg": null,
"ibizaworldclubtour.net/wp-content/themes/ex-studios/banner": null,
"ibrod.tv/ib.php": null,
"ibtimes.com/banner": null,
"iceinspace.com.au/iisads": null,
"iconeye.com/images/banners": null,
"icxm.net/x/img/kinguin.jpg": null,
"idg.com.au/files/skins": null,
"iftn.ie/images/data/banners": null,
"ijn.com/images/banners": null,
"ijoomla.com/aff/banners": null,
"iload.to/img/ul/impopi.js": null,
"imagebam.com/download_button.png": null,
"imagebam.com/img/coolstuffbro.jpg": null,
"imagefruit.com/includes/js/bgcont.js": null,
"imagefruit.com/includes/js/ex.js": null,
"imagefruit.com/includes/js/layer.js": null,
"imagepix.org/Images/imageput.jpg": null,
"imageporter.com/hiokax.js": null,
"imageporter.com/micromoo.html": null,
"imageporter.com/someo.html": null,
"imagerise.com/ir.js": null,
"imagerise.com/ir2.js": null,
"images.bitreactor.to/designs": null,
"images.sharkscope.com/everest/twister.jpg": null,
"images4et.com/images/other/warning-vpn2.gif": null,
"imageshack.us/ym.php": null,
"imagetoupload.com/images/87633952425570896161.jpg": null,
"imgbox.com/gsmpop.js": null,
"imgburn.com/images/your3gift.gif": null,
"imgchili.net/baexo.php": null,
"imgchili.net/froexo.js": null,
"imgchili.net/js/ns.js": null,
"imgchili.net/js/showa.js": null,
"imgchili.net/lj.js": null,
"imgking.co/poudr.js": null,
"imgrock.net/nb": null,
"imgshots.com/includes/js/layer.js": null,
"imgur.com/include/zedoinviewstub1621.html": null,
"immihelp.com/partner/banners": null,
"imouto.org/images/jlist": null,
"imouto.org/images/mangagamer": null,
"impulsedriven.com/app_images/wallpaper": null,
"inanyevent.ch/images/banners": null,
"incentivetravel.co.uk/images/banners": null,
"indeed.com/ads": null,
"independent.co.ug/images/banners": null,
"india.com/ads/jw/ova-jw.swf": null,
"indiainfoline.com/wc/ads": null,
"indiantelevision.com/banner": null,
"industryabout.com/images/banners": null,
"info.sciencedaily.com/api": null,
"infosecisland.com/ajax/viewbanner": null,
"injpn.net/images/banners": null,
"inkscapeforum.com/images/banners": null,
"insidedp.com/images/banners": null,
"insidehw.com/images/banners": null,
"insideyork.co.uk/assets/images/sponsors": null,
"intel.com/sites/wap/global/wap.js": null,
"intellicast.com/travel/cheapflightswidget.htm": null,
"intelseek.com/intelseekads": null,
"interest.co.nz/banners": null,
"international.to/link_unit.html": null,
"internationalmeetingsreview.com//uploads/banner": null,
"intoday.in/btstryad.html": null,
"ipaddress.com/banner": null,
"ipinfodb.com/img/adds": null,
"iradio.ie/assets/img/backgrounds": null,
"irishamericannews.com/images/banners": null,
"irishdev.com/files/banners": null,
"irishdictionary.ie/view/images/ispaces-makes-any-computer.jpg": null,
"ironspider.ca/pics/hostgator_green120x600.gif": null,
"ironsquid.tv/data/uploads/sponsors": null,
"irv2.com/attachments/banners": null,
"irv2.com/images/sponsors": null,
"isitnormal.com/img/iphone_hp_promo_wide.png": null,
"islamicfinder.org/cimage": null,
"islamicfocus.co.za/images/banners": null,
"island.lk/userfiles/image/danweem": null,
"isportconnect.com//images/banners": null,
"israeldefense.com/_Uploads/dbsBanners": null,
"isup.me/images/dotbiz_banner.jpg": null,
"isxdead.com/images/showbox.png": null,
"italiangenealogy.com/images/banners": null,
"itpro.co.uk/images/skins": null,
"itservicesthatworkforyou.com/sp/ebay.jpg": null,
"itweb.co.za/banners": null,
"itwebafrica.com/images/logos": null,
"itworld.com/slideshow/iframe/topimu": null,
"iurfm.com/images/sponsors": null,
"jacars.net/images/ba": null,
"jamaica-gleaner.com/images/promo": null,
"javamex.com/images/AdFrenchVocabGamesAnim.gif": null,
"jayisgames.com/maxcdn_160x250.png": null,
"jdownloader.org/_media/screenshots/banner.png": null,
"jebril.com/sites/default/files/images/top-banners": null,
"jewishyellow.com/pics/banners": null,
"jheberg.net/img/mp.png": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"johnbridge.com/vbulletin/banner_rotate.js": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"joins.com/common/ui/ad": null,
"joomladigger.com/images/banners": null,
"journal-news.net/annoyingpopup": null,
"journeychristiannews.com/images/banners": null,
"jumptags.com/joozit/presentation/images/banners": null,
"junocloud.me/promos": null,
"just-download.com/banner": null,
"kamcity.com/banager/banners": null,
"kamcity.com/menu/banners": null,
"kaotic.com/assets/toplists/footer.html": null,
"kassfm.co.ke/images/moneygram.gif": null,
"kavkisfile.com/images/ly-mini.gif": null,
"kavkisfile.com/images/ly.gif": null,
"kbcradio.eu/img/banner": null,
"kcrw.com/collage-images/amazon.gif": null,
"kcrw.com/collage-images/itunes.gif": null,
"kdoctv.net/images/banners": null,
"keepvid.com/ads": null,
"kendrickcoleman.com/images/banners": null,
"kentonline.co.uk/weatherimages/Britelite.gif": null,
"kentonline.co.uk/weatherimages/SEW.jpg": null,
"kephyr.com/spywarescanner/banner1.gif": null,
"kewlshare.com/reward.html": null,
"khaleejtimes.com/imgactv/Umrah%20-%20290x60%20-%20EN.jpg": null,
"khaleejtimes.com/imgactv/Umrah-Static-Background-Gutters-N.jpg": null,
"kickasstorrent.ph/kat_adplib.js": null,
"kickoff.com/images/sleeves": null,
"kingfiles.net/images/bt.png": null,
"kinox.tv/g.js": null,
"kirupa.com/supporter": null,
"kitco.com/ssi/dmg_banner_001.stm": null,
"kitguru.net/wp-content/banners": null,
"kitguru.net/wp-content/wrap.jpg": null,
"kitz.co.uk/files/jump2": null,
"kleisauke.nl/static/img/bar.gif": null,
"klfm967.co.uk/resources/creative": null,
"klkdccs.net/pjs/yavli-tools.js": null,
"kncminer.com/userfiles/image/250_240.jpg": null,
"knco.com/wp-content/uploads/wpt": null,
"knowledgespeak.com/images/banner": null,
"knowthecause.com/images/banners": null,
"kob.com/kobtvimages/flexhousepromotions": null,
"kompas.com/js_kompasads.php": null,
"kontraband.com/media/takeovers": null,
"koreanmovie.com/img/banner/banner.jpg": null,
"koreatimes.co.kr/images/bn": null,
"koreatimes.co.kr/www/images/bn": null,
"krzk.com/uploads/banners": null,
"kshp.com/uploads/banners": null,
"ksstradio.com/wp-content/banners": null,
"kuiken.co/static/w.js": null,
"kukmindaily.co.kr/images/bnr": null,
"kuwaittimes.net/banners": null,
"kwanalu.co.za/upload/ad": null,
"kwikupload.com/images/dlbtn.png": null,
"kxlh.com/images/banner": null,
"kyivpost.com/media/banners": null,
"l.yimg.com/ao/i/ad": null,
"l.yimg.com/mq/a": null,
"l4dmaps.com/img/right_gameservers.gif": null,
"labtimes.org/banner": null,
"labx.com/web/banners": null,
"laconiadailysun.com/images/banners": null,
"lake-link.com/images/sponsorLogos": null,
"lankabusinessonline.com/images/banners": null,
"laobserved.com/tch-ad.jpg": null,
"laptopmag.com/images/sponsorships": null,
"laredodaily.com/images/banners": null,
"lasttorrents.org/pcmadd.swf": null,
"latex-community.org/images/banners": null,
"lazygamer.net/kalahari.gif": null,
"lazygirls.info/click.php": null,
"leader.co.za/leadership/banners": null,
"leagueunlimited.com/images/rooty": null,
"learnphotoediting.net/banners": null,
"learnspanishtoday.com/aff/img/banners": null,
"lecydre.com/proxy.png": null,
"legalbusinessonline.com/popup/albpartners.aspx": null,
"lens101.com/images/banner.jpg": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"letswatchsomething.com/images/filestreet_banner.jpg": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"licensing.biz/media/banners": null,
"limesurvey.org/images/banners": null,
"limetorrentlinkmix.com/rd18/dop.js": null,
"limetorrents.cc/static/images/download.png": null,
"linguee.com/banner": null,
"linkcentre.com/top_fp.php": null,
"linkfm.co.za/images/banners": null,
"linkmoon.net/banners": null,
"linksrank.com/links": null,
"linuxinsider.com/images/sda": null,
"linuxmint.com/img/sponsor": null,
"linuxsat-support.com/vsa_banners": null,
"littleindia.com/files/banners": null,
"live-proxy.com/hide-my-ass.gif": null,
"live-proxy.com/vectrotunnel-logo.jpg": null,
"livejasmin.com/freechat.php": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"livescore.in/res/image/bookmaker-list.png": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"livetv.ru/mb": null,
"livingscoop.com/vastload.php": null,
"logoopenstock.com/img/banners": null,
"logotv.com/content/skins": null,
"london2012.com/img/sponsors": null,
"london2012.com/imgml/partners/footer": null,
"lookbook.nu/show_leaderboard.html": null,
"lostrabbitmedia.com/images/banners": null,
"lowellsun.com/litebanner": null,
"lowendbox.com/wp-content/themes/leb/banners": null,
"lshunter.tv/images/bets": null,
"luckyshare.net/images/1gotlucky.png": null,
"luckyshare.net/images/2top.png": null,
"luckyshare.net/images/sda": null,
"lygo.com/scripts/catman": null,
"m-w.com/creative.php": null,
"macaudailytimes.com.mo/files/banners": null,
"macaunews.com.mo/images/stories/banners": null,
"machovideo.com/img/site/postimg2/rotate.php": null,
"macupdate.com/js/google_service.js": null,
"macworld.com/ads": null,
"madskristensen.net/discount2.js": null,
"mail.yahoo.com/mc/md.php": null,
"majorgeeks.com/images/mb-hb-2.jpg": null,
"majorgeeks.com/images/mg120.jpg": null,
"makeagif.com/parts/fiframe.php": null,
"malaysiakini.com/misc/banners": null,
"mangafox.com/media/game321": null,
"mangarush.com/xtend.php": null,
"mangaupdates.com/affiliates": null,
"manhattantimesnews.com/images/banners": null,
"manilatimes.net/images/banners": null,
"mapsofindia.com/widgets/tribalfusionboxadd.html": null,
"maravipost.com/images/banners": null,
"marengo-uniontimes.com/images/banners": null,
"marineterms.com/images/banners": null,
"marketintelligencecenter.com/images/brokers": null,
"marketnewsvideo.com/etfchannel/evfad1.gif": null,
"marketnewsvideo.com/mnvport160.gif": null,
"mashable.com/tripleclick.html": null,
"mathforum.org/images/tutor.gif": null,
"mauritiusnews.co.uk/images/banners": null,
"maxconsole.com/maxconsole/banners": null,
"mccont.com/campaign%20management": null,
"mccont.com/sda": null,
"mccont.com/takeover": null,
"mcjonline.com/filemanager/userfiles/banners": null,
"mcnews.com.au/banners": null,
"mcsesports.com/images/sponsors": null,
"mcvuk.com/static/banners": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"mechodownload.com/forum/images/affiliates": null,
"mediafire.com/images/rockmelt": null,
"mediafire.com/templates/linkto": null,
"mediafire.re/popup.js": null,
"mediafiretrend.com/ifx/ifx.php": null,
"mediafiretrend.com/turboflirt.gif": null,
"mediaspanonline.com/images/buy-itunes.png": null,
"mediaticks.com/bollywood.jpg": null,
"mediaticks.com/images/genx-infotech.jpg": null,
"mediaticks.com/images/genx.jpg": null,
"medicaldaily.com/views/images/banners": null,
"megashares.com/cache_program_banner.html": null,
"megauploadtrend.com/iframe/if.php": null,
"meizufans.eu/efox.gif": null,
"meizufans.eu/merimobiles.gif": null,
"meizufans.eu/vifocal.gif": null,
"merriam-webster.com/creative.php": null,
"messianictimes.com/images/4-13/reach.jpg": null,
"messianictimes.com/images/banners": null,
"messianictimes.com/images/Israel%20Today%20Logo.png": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"messianictimes.com/images/MJBI.org.gif": null,
"messianictimes.com/images/Word%20of%20Messiah%20Ministries1.png": null,
"meteovista.co.uk/go/banner": null,
"meteox.co.uk/bannerdetails.aspx": null,
"meteox.com/bannerdetails.aspx": null,
"metromedia.co.za/bannersys/banners": null,
"mfcdn.net/media/game321": null,
"mgnetwork.com/dealtaker": null,
"mi-pro.co.uk/banners": null,
"micast.tv/clean.php": null,
"michronicleonline.com/images/banners": null,
"mightyupload.com/popuu.js": null,
"mindfood.com/upload/images/wallpaper_images": null,
"miniclipcdn.com/images/takeovers": null,
"mirrorcreator.com/js/mpop.js": null,
"mirrorcreator.com/js/pu_ad.js": null,
"mixx96.com/images/banners": null,
"mizzima.com/images/banners": null,
"mmorpg.com/images/skins": null,
"mmosite.com/sponsor": null,
"mob.org/banner": null,
"mobilephonetalk.com/eurovps.swf": null,
"mochiads.com/srv": null,
"modhoster.com/image/U": null,
"money-marketuk.com/images/banners": null,
"moneyam.com/www": null,
"moneymakerdiscussion.com/mmd-banners": null,
"moneymedics.biz/upload/banners": null,
"monkeygamesworld.com/images/banners": null,
"morningstaronline.co.uk/offsite/progressive-listings": null,
"motorhomefacts.com/images/banners": null,
"mountainbuzz.com/attachments/banners": null,
"mousesteps.com/images/banners": null,
"movie4k.tv/e.js": null,
"moviewallpaper.net/js/mwpopunder.js": null,
"movizland.com/images/banners": null,
"movstreaming.com/images/edhim.jpg": null,
"movzap.com/aad.html": null,
"movzap.com/zad.html": null,
"mp3s.su/uploads/___/djz_to.png": null,
"mtbr.com/ajax/hotdeals": null,
"mtvnimages.com/images/skins": null,
"multiup.org/img/sonyoutube_long.gif": null,
"murdermysteries.com/banners-murder": null,
"musicremedy.com/banner": null,
"my-link.pro/rotatingBanner.js": null,
"myam1230.com/images/banners": null,
"myanimelist.cdn-dena.com/images/affiliates": null,
"mybroadband.co.za/news/wp-content/wallpapers": null,
"myfax.com/free/images/sendfax/cp_coffee_660x80.swf": null,
"myfpscheats.com/bannerimg.jpg": null,
"mygaming.co.za/news/wp-content/wallpapers": null,
"myproperty.co.za/banners": null,
"myshadibridalexpo.com/banner": null,
"mytyres.co.uk/simg/skyscrapers": null,
"myway.com/gca_iframe.html": null,
"mywot.net/files/wotcert/vipre.png": null,
"nairaland.com/importantfiles": null,
"namepros.com/images/backers": null,
"narrative.ly/ads": null,
"nation.sc/images/banners": null,
"nationmultimedia.com/home/banner": null,
"nationmultimedia.com/new/js/nation_popup.js": null,
"nativetimes.com/images/banners": null,
"naturalhealth365.com/images/ic-may-2014-220x290.jpg": null,
"naturalnews.com/Images/Root-Canal-220x250.jpg": null,
"naukimg.com/banner": null,
"naukri.com/banners2016": null,
"ncrypt.in/images/1.gif": null,
"ncrypt.in/images/a": null,
"ncrypt.in/images/useful": null,
"ncrypt.in/javascript/jquery.msgbox.min.js": null,
"neodrive.co/cam": null,
"nesn.com/img/nesn-nation/header-dunkin.jpg": null,
"nesn.com/img/sponsors": null,
"netsplit.de/links/rootado.gif": null,
"networkwestvirginia.com/uploads/user_banners": null,
"newafricanmagazine.com/images/banners": null,
"newalbumreleases.net/banners": null,
"newipnow.com/ad-js.php": null,
"news-record.com/app/deal": null,
"newsday.co.tt/banner": null,
"newsonjapan.com/images/banners": null,
"newsreview.com/images/promo.gif": null,
"newstrackindia.com/images/hairfallguru728x90.jpg": null,
"newsudanvision.com/images/banners": null,
"newsudanvision.com/images/Carjunctionadvert.gif": null,
"newsvine.com//jenga/widget": null,
"newsvine.com/jenga/widget": null,
"newverhost.com/css/onload.js": null,
"newverhost.com/css/pp.js": null,
"newvision.co.ug/banners": null,
"newvision.co.ug/rightsidepopup": null,
"nextgen-auto.com/images/banners": null,
"nextstl.com/images/banners": null,
"ngrguardiannews.com/images/banners": null,
"nigeriamasterweb.com/Masterweb/banners_pic": null,
"nigerianyellowpages.com/images/banners": null,
"niggasbelike.com/wp-content/themes/zeecorporate/images/b.jpg": null,
"nijobfinder.co.uk/affiliates": null,
"nirsoft.net/banners": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"nmap.org/shared/images/p": null,
"nodevice.com/images/banners": null,
"nogripracing.com/iframe.php": null,
"norwaypost.no/images/banners": null,
"novamov.com/images/download_video.jpg": null,
"nowgoal.com/images/foreign": null,
"nowwatchtvlive.co/revenuehits.html": null,
"nowwatchtvlive.com/revenuehits.html": null,
"nufc.com/forddirectbanner.js": null,
"numberempire.com/images/b": null,
"nutritionhorizon.com/content/banners": null,
"nuttynewstoday.com/images/hostwink.jpg": null,
"nuttynewstoday.com/images/percento-banner.jpg": null,
"nydailynews.com/img/sponsor": null,
"nydailynews.com/PCRichards": null,
"nymag.com/partners": null,
"nymag.com/scripts/skintakeover.js": null,
"nytimes.com/ads": null,
"nzbindex.nl/images/banners": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"nznewsuk.co.uk/banners": null,
"observer.com.na/images/banners": null,
"observer.org.sz/files/banners": null,
"observer.ug/images/banners": null,
"ocforums.com/adj": null,
"oilprice.com/images/banners": null,
"oilprice.com/images/sponsors": null,
"okccdn.com/media/img/takeovers": null,
"oldgames.sk/images/topbar": null,
"oload.tv/logpopup": null,
"on.net/images/gon_nodestore.jpg": null,
"onionstatic.com/sponsored": null,
"onlinenews.com.pk/onlinenews-admin/banners": null,
"onlineshopping.co.za/expop": null,
"openload.co/logpopup": null,
"opensubtitles.org/gfx/banners_campaigns": null,
"optics.org/banners": null,
"oraclebroadcasting.com/images/enerfood-300x90.gif": null,
"oraclebroadcasting.com/images/extendovite300.gif": null,
"oraclebroadcasting.com/images/hempusa_330.gif": null,
"originalfm.com/images/hotspots": null,
"ouo.io/js/pop.": null,
"outlookmoney.com/sharekhan_ad.jpg": null,
"overclock3d.net/img/pcp.jpg": null,
"ovfile.com/player/jwadplugin.swf": null,
"oyetimes.com/join/advertisers.html": null,
"ozy.com/modules/_common/ozy/pushdown": null,
"p2pnet.net/images": null,
"pacificnewscenter.com/images/banners": null,
"paisalive.com/include/popup.js": null,
"parade.com/images/skins": null,
"pardaphash.com/direct/tracker/add": null,
"parlemagazine.com/images/banners": null,
"pasadenajournal.com/images/banners": null,
"passageweather.com/links": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"pcmag.com/blogshome/logicbuy.js": null,
"pcpro.co.uk/images/skins": null,
"pcr-online.biz/static/banners": null,
"pedestrian.tv/_crunk/wp-content/files_flutter": null,
"penguin-news.com/images/banners": null,
"perezhilton.com/images/ask": null,
"peruthisweek.com/uploads/sponsor_image": null,
"petri.co.il/media": null,
"phillytrib.com/images/banners": null,
"phnompenhpost.com/images/stories/banner": null,
"phonearena.com/images/banners": null,
"phonebunch.com/images/flipkart_offers_alt.jpg": null,
"phoronix.com/phxforums-thread-show.php": null,
"photosupload.net/photosupload.js": null,
"phpbb.com/theme/images/bg_forumatic_front_page.png": null,
"phpbb.com/theme/images/hosting/hostmonster-downloads.gif": null,
"phpmotion.com/images/banners-webhosts": null,
"phuket-post.com/img/a": null,
"phuketgazette.net/banners": null,
"phuketwan.com/img/b": null,
"pickmeupnews.com/cfopop.js": null,
"piratefm.co.uk/resources/creative": null,
"pirateproxy.nl/inc/ex.js": null,
"pixhost.org/exc": null,
"pixhost.org/image/fik1.jpg": null,
"planecrashinfo.com/images/advertize1.gif": null,
"planetlotus.org/images/partners": null,
"play4movie.com/banner": null,
"playgames2.com/default160x160.php": null,
"playgames2.com/mmoout.php": null,
"playgames2.com/rand100x100.php": null,
"playhub.com/js/popup-wide.js": null,
"playtowerdefensegames.com/ptdg-gao-gamebox-homepage.swf": null,
"plsn.com/images/PLSN-Bg1.jpg": null,
"plunderguide.com/leaderboard-gor.html": null,
"pocketpcaddict.com/forums/images/banners": null,
"pokernews.com/b": null,
"pokernews.com/preroll.php": null,
"police-car-photos.com/pictures/sponsors": null,
"portlanddailysun.me/images/banners": null,
"porttechnology.org/images/partners": null,
"portugaldailyview.com/images/mrec": null,
"postadsnow.com/panbanners": null,
"power977.com/images/banners": null,
"powvideo.net/ban": null,
"praguepost.com/images/banners": null,
"prehackshub.com/js/popup-wide.js": null,
"prewarcar.com/images/banners": null,
"primewire.ag/additional_content.php": null,
"primewire.ag/load_link.php": null,
"primewire.guru/load_link.php": null,
"primewire.guru/pagetop.php": null,
"primewire.in/additional_content.php": null,
"primewire.in/load_link.php": null,
"pro-clockers.com/images/banners": null,
"project-for-sell.com/_google.php": null,
"projectfreetv.at/prom2.html": null,
"projectfreetv.ch/adblock": null,
"propakistani.pk/data/warid_top1.html": null,
"propakistani.pk/data/zong.html": null,
"propakistani.pk/wp-content/themes/propakistani/images/776.jpg": null,
"propertyeu.info/peu_storage_banners": null,
"proxy-list.org/img/isellsite.gif": null,
"proxy.org/af.html": null,
"proxy.org/ah.html": null,
"proxycape.com/blah.js": null,
"ps3crunch.net/forum/images/gamers": null,
"ptf.com/js/fdm_banner.js": null,
"ptf.com/js/rc_banner.js": null,
"publicdomaintorrents.info/grabs/hdsale.png": null,
"publicdomaintorrents.info/rentme.gif": null,
"publicdomaintorrents.info/srsbanner.gif": null,
"publichd.eu/images/direct.download.ico": null,
"publichd.eu/images/directdownload.png": null,
"pulsetv.com/banner": null,
"pumasrugbyunion.com/images/sponsors": null,
"punksbusted.com/images/ventrilo": null,
"pushsquare.com/wp-content/themes/pushsquare/skins": null,
"pv-tech.org/images/footer_logos": null,
"pv-tech.org/images/suntech_m2fbblew.png": null,
"q1075.com/images/banners": null,
"qatar-tribune.com/images/banners": null,
"queenshare.com/popx.js": null,
"quicksilverscreen.com/img/moviesforfree.jpg": null,
"quoteland.com/images/banner2.swf": null,
"racingpost.com/ads": null,
"radio1584.co.za/images/banners": null,
"radio4fm.com/images/background": null,
"radio786.co.za/images/banners": null,
"radio90fm.com/images/banners": null,
"radioloyalty.com/newPlayer/loadbanner.html": null,
"radiotimes.com/assets/images/partners": null,
"radiowave.com.na/images/banners": null,
"radiowavesforum.com/rw/radioapp.gif": null,
"rainbowpages.lk/images/banners": null,
"rapidgamez.com/images": null,
"rapidgator.net/images/banners": null,
"rapidgator.net/images/pics/button.png": null,
"rapidsafe.de/eislogo.gif": null,
"rapidshare.com/promo": null,
"rapidvideo.org/images/pl_box_rapid.jpg": null,
"rapidvideo.tv/images/pl.jpg": null,
"ratio-magazine.com/images/banners": null,
"ravchat.com/img/reversephone.gif": null,
"readingeagle.com/lib/dailysponser.js": null,
"realitytvworld.com/includes/rtvw-jscript.js": null,
"rednationonline.ca/Portals/0/derbystar_leaderboard.jpg": null,
"regnow.img.digitalriver.com/vendor/37587/ud_box": null,
"rejournal.com/images/banners": null,
"rejournal.com/users/blinks": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"relink.us/js/ibunkerslide.js": null,
"residentadvisor.net/images/banner": null,
"reuters.com/reuters_bootstrap.js": null,
"reviewcentre.com/cinergy-adv.php": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"rfu.com/js/jquery.jcarousel.js": null,
"richardroeper.com/assets/banner": null,
"riderfans.com/other": null,
"rightsidenews.com/images/banners": null,
"rlsbb.com/wp-content/uploads/izilol.gif": null,
"rlsbb.com/wp-content/uploads/smoke.jpg": null,
"rlslog.net/files/frontend.js": null,
"robinwidget.com/images/batman_banner.png": null,
"rockthebells.net/images/banners": null,
"rodfile.com/images/esr.gif": null,
"rom-freaks.net/popup.php": null,
"romereports.com/core/media/automatico": null,
"romereports.com/core/media/sem_comportamento": null,
"routes-news.com/images/banners": null,
"routesonline.com/banner": null,
"rsbuddy.com/campaign": null,
"rt.com/banner": null,
"rt.com/static/img/banners": null,
"rtcc.org/systems/sponsors": null,
"rtklive.com/marketing": null,
"runt-of-the-web.com/wrap1.jpg": null,
"russianireland.com/images/banners": null,
"rustourismnews.com/images/banners": null,
"sa4x4.co.za/images/banners": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"sacbee.com/static/dealsaver": null,
"sacommercialpropnews.co.za/files/banners": null,
"safelinks.eu/open.js": null,
"sagoodnews.co.za/templates/ubuntu-deals": null,
"saice.org.za/uploads/banners": null,
"sameip.org/images/froghost.gif": null,
"sams.sh/premium_banners": null,
"samsung.com/ph/nextisnow/files/javascript.js": null,
"sapeople.com/wp-content/uploads/wp-banners": null,
"sareunited.com/uploaded_images/banners": null,
"sat24.com/bannerdetails.aspx": null,
"satellites.co.uk/images/sponsors": null,
"satnews.com/images/MITEQ_sky.jpg": null,
"satnews.com/images/MSMPromoSubSky.jpg": null,
"savefrom.net/img/a1d": null,
"saveondish.com/banner2.jpg": null,
"saveondish.com/banner3.jpg": null,
"sbnation.com/campaigns_images": null,
"scenicreflections.com/dhtmlpopup": null,
"sceper.eu/wp-content/banners.min.js": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"scoopnest.com/content_rb.php": null,
"screen4u.net/templates/banner.html": null,
"screenafrica.com/jquery.jcarousel.min.js": null,
"screenlist.ru/dodopo.js": null,
"screenlist.ru/porevo.js": null,
"scribol.com/broadspring.js": null,
"scriptcopy.com/tpl/phplb/search.jpg": null,
"scriptmafia.org/banner.gif": null,
"sdancelive.com/images/banners": null,
"search-torrent.com/images/videox": null,
"search.ch/htmlbanner.html": null,
"search.triadcars.news-record.com/autos/widgets/featuredautos.php": null,
"searchtempest.com/clhimages/aocbanner.jpg": null,
"seatrade-cruise.com/images/banners": null,
"seclists.org/shared/images/p": null,
"sectools.org/shared/images/p": null,
"secureupload.eu/gfx/SecureUpload_Banner.png": null,
"secureupload.eu/js/poad.js": null,
"securitymattersmag.com/scripts/popup.js": null,
"sedoparking.com/images/js_preloader.gif": null,
"sedoparking.com/jspartner": null,
"seedboxes.cc/images/seedad.jpg": null,
"seeingwithsound.com/noad.gif": null,
"segmentnext.com/javascripts/interstitial.client.js": null,
"sendspace.com/images/shutter.png": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"serialzz.us/ad.js": null,
"sermonaudio.com/images/sponsors": null,
"sfltimes.com/images/banners": null,
"shanghaidaily.com/include/bettertraffic.asp": null,
"share-links.biz/get/cmm": null,
"sharebeast.com/topbar.js": null,
"sharephile.com/js/pw.js": null,
"sharesix.com/a/images/watch-bnr.gif": null,
"sharetera.com/images/icon_download.png": null,
"sharetera.com/promo.php": null,
"sharkscope.com/images/verts": null,
"shodanhq.com/images/s/acehackware-obscured.jpg": null,
"shop.sportsmole.co.uk/pages/deeplink": null,
"shopwiki.com/banner_iframe": null,
"show-links.tv/layer.php": null,
"showbusinessweekly.com/imgs/hed": null,
"showsport-tv.com/images/xtreamfile.jpg": null,
"shroomery.org/bimg": null,
"shroomery.org/images/shroomery.please.png": null,
"shroomery.org/images/www.shroomery.org.please.png": null,
"shtfplan.com/images/banners": null,
"siberiantimes.com/upload/banners": null,
"sicilianelmondo.com/banner": null,
"sickipedia.org/static/images/banners": null,
"sify.com/images/games/gadvt": null,
"siliconrepublic.com/fs/img/partners": null,
"silvergames.com/div/ba.php": null,
"sitedata.info/doctor": null,
"sitesfrog.com/images/banner": null,
"siteslike.com/js/fpa.js": null,
"sk-gaming.com/image/acersocialw.gif": null,
"sk-gaming.com/image/pts": null,
"skilouise.com/images/sponsors": null,
"skynews.com.au/elements/img/sponsor": null,
"skysports.com/images/skybet.png": null,
"slashgear.com/static/banners": null,
"slayradio.org/images/c64audio.com.gif": null,
"smartcompany.com.au/images/stories/sponsored-posts": null,
"smartname.com/scripts/google_afd_v2.js": null,
"smashingapps.com/banner": null,
"smh.com.au/images/promo": null,
"smile904.fm/images/banners": null,
"smn-news.com/images/banners": null,
"smn-news.com/images/flash": null,
"smoothjazznetwork.com/images/buyicon.jpg": null,
"smotrisport.com/ads": null,
"soccerlens.com/files1": null,
"soccervista.com/bahforgif.gif": null,
"soccervista.com/bonus.html": null,
"soccervista.com/sporting.gif": null,
"soccerway.com/img/betting": null,
"socialstreamingplayer.crystalmedianetworks.com//async/banner": null,
"sockshare.com/moo.php": null,
"sockshare.com/rev": null,
"socsa.org.za/images/banners": null,
"softcab.com/google.php": null,
"softonic.com/specials_leaderboard": null,
"softpedia-static.com/images/aff": null,
"softpedia-static.com/images/afg": null,
"soldierx.com/system/files/images/sx-mini-1.jpg": null,
"solomonstarnews.com/images/banners": null,
"solvater.com/images/hd.jpg": null,
"songs.pk/textlinks": null,
"songspk.link/textlinks": null,
"songspk.name/imagepk.gif": null,
"songspk.name/textlinks": null,
"sootoday.com/uploads/banners": null,
"sorcerers.net/images/aff": null,
"soundcloud.com/promoted": null,
"soundspheremag.com/images/banners": null,
"sourceforge.net/images/ban": null,
"southafricab2b.co.za/banners": null,
"southfloridagaynews.com/images/banners": null,
"sowetanlive.co.za/banners": null,
"speedtv.com.edgesuite.net/img/monthly/takeovers": null,
"speedvid.net/ad.htm": null,
"speedvideo.net/img/playerFk.gif": null,
"spicegrenada.com/images/banners": null,
"sportcategory.com/ads": null,
"spotflux.com/service/partner.php": null,
"spycss.com/images/hostgator.gif": null,
"squadedit.com/img/peanuts": null,
"st701.com/stomp/banners": null,
"stad.com/googlefoot2.php": null,
"standard.net/sites/default/files/images/wallpapers": null,
"standardmedia.co.ke/flash": null,
"startxchange.com/bnr.php": null,
"static.hltv.org//images/csgofasttakeover.jpg": null,
"static.hltv.org//images/gofastbg.png": null,
"static.hltv.org//images/gofastmar.jpg": null,
"steamanalyst.com/a/www": null,
"sternfannetwork.com/forum/images/banners": null,
"steroid.com/banner": null,
"sticker.yadro.ru/ad": null,
"stjohntradewindsnews.com/images/banners": null,
"stopforumspam.com/img/snelserver.swf": null,
"stopstream.com/ads": null,
"stream2watch.co/_frames/hd2.png": null,
"stream2watch.co/frames": null,
"stream2watch.co/images/hd1.png": null,
"stream2watch.co/images/hdhd.gif": null,
"stream2watch.me/600pick.png": null,
"stream2watch.me/900rev.html": null,
"stream2watch.me/900yahoo.html": null,
"stream2watch.me/ad.html": null,
"stream2watch.me/ad10.html": null,
"stream2watch.me/chat1.html": null,
"stream2watch.me/eadb.php": null,
"stream2watch.me/eadt.php": null,
"stream2watch.me/images/hd1.png": null,
"stream2watch.me/Los_Br.png": null,
"stream2watch.me/yield.html": null,
"streamcloud.eu/deliver.php": null,
"streamplay.to/images/videoplayer.png": null,
"streams.tv/js/bn5.js": null,
"streams.tv/js/pu.js": null,
"streams.tv/js/slidingbanner.js": null,
"stuff.tv/client/skinning": null,
"sun-fm.com/resources/creative": null,
"sunriseradio.com/js/rbanners.js": null,
"sunshineradio.ie/images/banners": null,
"superbike-news.co.uk/absolutebm/banners": null,
"supermarket.co.za/images/advetising": null,
"supermonitoring.com/images/banners": null,
"surfthechannel.com/promo": null,
"swagmp3.com/cdn-cgi/pe": null,
"swampbuggy.com/media/images/banners": null,
"swedishwire.com/images/banners": null,
"swiftco.net/banner": null,
"swoknews.com/images/banners": null,
"sydneyolympicfc.com/admin/media_manager/media/mm_magic_display": null,
"systemexplorer.net/sessg.php": null,
"sythe.org/clientscript/agold.png": null,
"tabloidmedia.co.za/images/signs2.swf": null,
"taipeitimes.com/js/gad.js": null,
"take40.com/images/takeover": null,
"talkers.com/imagebase": null,
"talkers.com/images/banners": null,
"talkphotography.co.uk/images/externallogos/banners": null,
"talkradioeurope.com/images/banners": null,
"talkradioeurope.net/images/banners": null,
"tampermonkey.net/bner": null,
"teamfourstar.com/img/918thefan.jpg": null,
"techexams.net/banners": null,
"techhive.com/ads": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"technewsworld.com/images/sda": null,
"techpowerup.com/images/bnnrs": null,
"teesoft.info/images/uniblue.png": null,
"tehrantimes.com/banner": null,
"tehrantimes.com/images/banners": null,
"tenmanga.com/files/js/site_skin.js": null,
"tennischannel.com/prud.jpg": null,
"tennisworldusa.org/banners": null,
"terafile.co/i/banners": null,
"textpattern.com/images/117.gif": null,
"thaivisa.com/promotions/banners": null,
"theartnewspaper.com/aads": null,
"theasiantoday.com/image/banners": null,
"theattractionforums.com/images/rbsbanners": null,
"thebankangler.com/images/banners": null,
"thebay.co.uk/banners": null,
"thebeat99.com/cmsadmin/banner": null,
"thebull.com.au/admin/uploads/banners": null,
"thebusinessdesk.com/assets/_files/banners": null,
"thecnj.com/images/hotel-banner.jpg": null,
"thecorrsmisc.com/10feet_banner.gif": null,
"thecorrsmisc.com/brokenthread.jpg": null,
"thecorrsmisc.com/msb_banner.jpg": null,
"thedailyherald.com/images/banners": null,
"thedailymash.co.uk/templates/mashtastic/gutters": null,
"thedailysheeple.com/images/banners": null,
"thedailywtf.com/fblast": null,
"theday.com/assets/images/sponsorlogos": null,
"thedirectory.co.zw/banners": null,
"thedomainstat.com/filemanager/userfiles/banners": null,
"theedinburghreporter.co.uk/hmbanner": null,
"thefrontierpost.com/media/banner": null,
"thegardener.co.za/images/banners": null,
"thehrdirector.com/assets/banners": null,
"theispguide.com/topbanner.asp": null,
"thejournal.ie/media/hpto": null,
"thelocal.com/scripts/fancybox": null,
"thelodownny.com/leslog/ads": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"themidweeksun.co.bw/images/banners": null,
"theminiforum.co.uk/images/banners": null,
"themis-media.com/media/global/images/cskins": null,
"themiscellany.org/images/banners": null,
"thenassauguardian.com/images/banners": null,
"thenewjournalandguide.com/images/banners": null,
"thenextweb.com/wp-content/plugins/tnw-siteskin/mobileys": null,
"theolympian.com/static/images/weathersponsor": null,
"theonion.com/ads": null,
"theorganicprepper.ca/images/banners": null,
"thepatriot.co.bw/images/banners": null,
"thepeak.fm/images/banners": null,
"thephuketnews.com/photo/banner": null,
"theplanetweekly.com/images/banners": null,
"theportugalnews.com/uploads/banner": null,
"thepowerhour.com/images/food_summit2.jpg": null,
"thepowerhour.com/images/karatbar1.jpg": null,
"thepowerhour.com/images/kcaa.jpg": null,
"thepowerhour.com/images/numanna.jpg": null,
"thepowerhour.com/images/rickssatellite_banner2.jpg": null,
"thepowerhour.com/images/youngevity.jpg": null,
"theradiomagazine.co.uk/banners": null,
"theradiomagazine.co.uk/images/bionics.jpg": null,
"therugbyforum.com/trf-images/sponsors": null,
"thestandard.com.hk/banners": null,
"thestkittsnevisobserver.com/images/banners": null,
"thesweetscience.com/images/banners": null,
"thetimes.co.uk/public/encounters": null,
"thetvdb.com/images/frugal.gif": null,
"thetvdb.com/images/jriver_banner.png": null,
"thevideo.me/cgi-bin/get_creatives.cgi": null,
"thevideo.me/creatives": null,
"thevideo.me/js/jsmpc.js": null,
"thevideo.me/js/jspc.js": null,
"thevideo.me/js/popup.min.js": null,
"thevideo.me/mba/cds.js": null,
"thevideo.me/player/offers.js": null,
"thewb.com/thewb/swf/tmz-adblock": null,
"thinkbroadband.com/uploads/banners": null,
"thunder106.com//wp-content/banners": null,
"ticketnetwork.com/images/affiliates": null,
"times-herald.com/pubfiles": null,
"times.co.sz/files/banners": null,
"timesnow.tv/googlehome.cms": null,
"timesofoman.com/siteImages/MyBannerImages": null,
"tindleradio.net/banners": null,
"toolslib.net/assets/img/a_dvt": null,
"topfriv.com/popup.js": null,
"torrent-finder.info/cont.html": null,
"torrent-finder.info/cont.php": null,
"torrent.cd/images/big_use.gif": null,
"torrent.cd/images/main_big_msoft.jpg": null,
"torrent.cd/images/sp": null,
"torrentbit.net/images/1click/button-long.png": null,
"torrentbox.sx/img/download_direct.png": null,
"torrentcrazy.com/img/wx.png": null,
"torrentcrazy.com/pnd.js": null,
"torrentdownloads.me/templates/new/images/download_button2.jpg": null,
"torrentdownloads.me/templates/new/images/download_button3.jpg": null,
"torrenteditor.com/img/graphical-network-monitor.gif": null,
"torrentfreak.com/images/torguard.gif": null,
"torrentfreak.com/images/vuze.png": null,
"torrentfunk.com/affprofslider.js": null,
"torrentfusion.com/FastDownload.html": null,
"torrentking.eu/js/script.packed.js": null,
"torrentproject.org/out": null,
"torrentroom.com/js/torrents.js": null,
"torrents.net/btguard.gif": null,
"torrents.net/wiget.js": null,
"torrentv.org/images/tsdd.jpg": null,
"torrentv.org/images/tsdls.jpg": null,
"torrentz2.eu/4puam.js": null,
"torrentz2.me/4puam.js": null,
"total-croatia-news.com/images/banners": null,
"totalcmd.pl/img/billboard_": null,
"totalcmd.pl/img/nucom.": null,
"totalcmd.pl/img/olszak.": null,
"totalguitar.net/images/tgMagazineBanner.gif": null,
"toucharcade.com/wp-content/themes/skin_zero/images/skin_assets/main_skin.jpg": null,
"toucharcade.com/wp-content/uploads/skins": null,
"toynews-online.biz/media/banners": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"tradewinds.vi/images/banners": null,
"traduguide.com/banner": null,
"trailrunnermag.com/images/takeovers": null,
"tribune.com.ng/images/banners": null,
"tribune242.com/pubfiles": null,
"tripadvisor.com/adp": null,
"triplehfm.com.au/images/banners": null,
"truck1.eu/_BANNERS_": null,
"trutv.com/includes/mods/iframes/mgid-blog.php": null,
"tsatic-cdn.net/takeovers": null,
"tsdmemphis.com/images/banners": null,
"tubeplus.me/resources/js/codec.js": null,
"tullahomanews.com/news/banners": null,
"tullahomanews.com/news/tn-popup.js": null,
"tune.pk/plugins/cb_tunepk/ads": null,
"turboimagehost.com/p.js": null,
"turboyourpc.com/images/affiliates": null,
"tusfiles.net/i/dll.png": null,
"tusfiles.net/images/tusfilesb.gif": null,
"tv4chan.com/iframes": null,
"tvsubtitles.net/banners": null,
"u.tv/images/misc/progressive.png": null,
"u.tv/images/sponsors": null,
"u.tv/utvplayer/jwplayer/ova.swf": null,
"ubuntugeek.com/images/dnsstock.png": null,
"ubuntugeek.com/images/od.jpg": null,
"ubuntugeek.com/images/ubuntu1.png": null,
"ujfm.co.za/images/banners": null,
"uk-mkivs.net/uploads/banners": null,
"ukbusinessforums.co.uk/adblock": null,
"ukcampsite.co.uk/banners": null,
"ultimate-guitar.com/_img/promo/takeovers": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"ultimatewindowssecurity.com/images/patchzone-resource-80x490.jpg": null,
"ultimatewindowssecurity.com/images/spale.swf": null,
"ultimatewindowssecurity.com/securitylog/encyclopedia/images/allpartners.swf": null,
"umbrelladetective.com/uploaded_files/banners": null,
"unblockedpiratebay.com/external": null,
"uniindia.com/eng/bannerbottom.php": null,
"uniindia.com/eng/bannerheader.php": null,
"uniindia.com/eng/bannerrightside.php": null,
"uniindia.com/eng/banners": null,
"uniindia.com/eng/bannertopright.php": null,
"uniindia.net/eng/banners": null,
"uniquefm.gm/images/banners": null,
"uploaded.net/js2/downloadam.js": null,
"uploaded.to/img/e/ad": null,
"uploading.com/static/banners": null,
"uploadlw.com/js/cash.js": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"uptobox.com/images/download.png": null,
"uptobox.com/images/downloaden.gif": null,
"urbanfonts.com/images/fonts_com": null,
"urbanvelo.org/sidebarbanner": null,
"urlcash.net/newpop.js": null,
"urlcash.org/abp": null,
"urlcash.org/banners": null,
"urlcash.org/newpop.js": null,
"usanetwork.com/_js/ad.js": null,
"uschess.org/images/banners": null,
"ustream.tv/takeover": null,
"uxmatters.com/images/sponsors": null,
"val.fm/images/banners": null,
"valleyplanet.com/images/banners": null,
"vasco.co.za/images/banners": null,
"vault.starproperty.my/widget": null,
"verizon.com/ads": null,
"verzend.be/images/download.png": null,
"viator.com/analytics/percent_mobile_hash.js": null,
"video2mp3.net/images/download_button.png": null,
"video44.net/gogo/qc.js": null,
"video44.net/gogo/yume-h.swf": null,
"videobash.com/images/playboy": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"videodorm.org/player/yume-h.swf": null,
"videodownloadtoolbar.com/fancybox": null,
"videogamesblogger.com/takeover.html": null,
"videolan.org/images/events/animated_packliberte.gif": null,
"videowood.tv/assets/js/popup.js": null,
"viewdocsonline.com/images/banners": null,
"vigilante.pw/img/partners": null,
"villagevoice.com/img/VDotDFallback-large.gif": null,
"vinaora.com/xmedia/hosting": null,
"vipbox.tv/blackwhite": null,
"vipbox.tv/js/layer.js": null,
"vipi.tv/ad.php": null,
"vistandpoint.com/images/banners": null,
"vodlocker.com/images/acenter.png": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"voicescalgary.com/images/leaderBoards": null,
"voicescalgary.com/images/stories/banners": null,
"voicesedmonton.com/images/leaderBoards": null,
"voicesedmonton.com/images/stories/banners": null,
"voicesottawa.com/images/leaderBoards": null,
"voicesottawa.com/images/stories/banners": null,
"voicestoronto.com/images/leaderBoards": null,
"voicestoronto.com/images/stories/banners": null,
"voicesvancouver.com/images/leaderBoards": null,
"voicesvancouver.com/images/stories/banners": null,
"vonradio.com/grfx/banners": null,
"vox-cdn.com/campaigns_images": null,
"vpsboard.com/display": null,
"waamradio.com/images/sponsors": null,
"wadldetroit.com/images/banners": null,
"wantedinmilan.com/images/banner": null,
"wantitall.co.za/images/banners": null,
"warriorforum.com/vbppb": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"washtimes.net/banners": null,
"watchcartoononline.com/pve.php": null,
"watchfomny.tv/Menu/A": null,
"watchfreemovies.ch/js/lmst.js": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"watchseries-online.se/jquery.js": null,
"watchseries.eu/images/affiliate_buzz.gif": null,
"watchseries.eu/images/download.png": null,
"watchseries.eu/js/csspopup.js": null,
"watchuseek.com/flashwatchwus.swf": null,
"watchuseek.com/media/clerc-final.jpg": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"watchuseek.com/media/wus-image.jpg": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"wbal.com/absolutebm/banners": null,
"wbj.pl/im/partners.gif": null,
"wctk.com/banner_rotator.php": null,
"wealthycashmagnet.com/upload/banners": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"weather365.net/images/banners": null,
"weatheroffice.gc.ca/banner": null,
"webdesignerdepot.com/wp-content/plugins/md-popup": null,
"webdesignerdepot.com/wp-content/themes/wdd2/fancybox": null,
"webhostingtalk.com/images/style/lw-160x400.jpg": null,
"webhostingtalk.com/images/style/lw-header.png": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"webstatschecker.com/links": null,
"weedwatch.com/images/banners": null,
"wegoted.com/uploads/memsponsor": null,
"wegoted.com/uploads/sponsors": null,
"wgfaradio.com/images/banners": null,
"whatismyip.com/images/VYPR__125x125.png": null,
"whatmobile.com.pk/banners": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"whatsabyte.com/images/Acronis_Banners": null,
"whatson.co.za/img/hp.png": null,
"whatsonnamibia.com/images/banners": null,
"whatsonstage.com/images/sitetakeover": null,
"whatsthescore.com/logos/icons/bookmakers": null,
"whdh.com/images/promotions": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"whitepages.ae/images/UI/FC": null,
"whitepages.ae/images/UI/LB": null,
"whitepages.ae/images/UI/MR": null,
"whitepages.ae/images/UI/SR": null,
"whitepages.ae/images/UI/SRA": null,
"whitepages.ae/images/UI/SRB": null,
"whitepages.ae/images/UI/WS": null,
"who.is/images/domain-transfer2.jpg": null,
"whoer.net/images/pb": null,
"whois.net/images/banners": null,
"whoownsfacebook.com/images/topbanner.gif": null,
"widih.org/banners": null,
"wiilovemario.com/images/fc-twin-play-nes-snes-cartridges.png": null,
"wikinvest.com/wikinvest/ads": null,
"winnfm.com/grfx/banners": null,
"wirenh.com/images/banners": null,
"witbankspurs.co.za/layout_images/sponsor.jpg": null,
"witteringsfromwitney.com/wp-content/plugins/popup-with-fancybox": null,
"wjie.org/media/img/sponsers": null,
"wjunction.com/images/constant": null,
"wksu.org/graphics/banners": null,
"wlcr.org/banners": null,
"wlrfm.com/images/banners": null,
"wnpv1440.com/images/banners": null,
"wnst.net/img/coupon": null,
"wolf-howl.com/wp-content/banners": null,
"worddictionary.co.uk/static//inpage-affinity": null,
"wordwebonline.com/img/122x36ccbanner.png": null,
"worldarchitecturenews.com/banner": null,
"worldarchitecturenews.com/flash_banners": null,
"worldometers.info/L300L.html": null,
"worldometers.info/L300R.html": null,
"worldometers.info/L728.html": null,
"worldradio.ch/site_media/banners": null,
"worldstagegroup.com/banner": null,
"worldstagegroup.com/worldstagenew/banner": null,
"wowhead.com/uploads/skins": null,
"wpcv.com/includes/header_banner.htm": null,
"wqah.com/images/banners": null,
"wqam.com/partners": null,
"wqxe.com/images/sponsors": null,
"wranglerforum.com/images/sponsor": null,
"wrcjfm.org/images/banners": null,
"wrlr.fm/images/banners": null,
"wsj.net/internal/krux.js": null,
"wttrend.com/images/hs.jpg": null,
"wunderground.com/geo/swfad": null,
"wvbr.com/images/banner": null,
"wwbf.com/b/topbanner.htm": null,
"xbitlabs.com/cms/module_banners": null,
"xbitlabs.com/images/banners": null,
"xbox-hq.com/html/images/banners": null,
"xoops-theme.com/images/banners": null,
"xscores.com/livescore/banners": null,
"xtremesystems.org/forums/brotator": null,
"yahoo.com/__darla": null,
"yahoo.com/darla": null,
"yahoo.com/livewords": null,
"yahoo.com/neo/darla": null,
"yahoo.com/sdarla": null,
"yahoo.com/ysmload.html": null,
"yamgo.mobi/images/banner": null,
"yavideo.tv/ajaxlog.txt": null,
"yellowpage-jp.com/images/banners": null,
"yellowpages.com.jo/uploaded/banners": null,
"yellowpages.com.lb/uploaded/banners": null,
"yellowpageskenya.com/images/laterals": null,
"yfmghana.com/images/banners": null,
"yorkshirecoastradio.com/resources/creative": null,
"yotv.co/class/adjsn3.js": null,
"youngrider.com/images/sponsorships": null,
"yourbittorrent.com/downloadnow.png": null,
"yourbittorrent.com/images/lumovies.js": null,
"yourfilehost.com/ads": null,
"yourindustrynews.com/ads": null,
"yourmuze.fm/images/audionow.png": null,
"yourmuze.fm/images/banner_ym.png": null,
"yourradioplace.com//images/banners": null,
"yourradioplace.com/images/banners": null,
"yourupload.com/rotate": null,
"yourwire.net/images/refssder.gif": null,
"youserials.com/i/banner_pos.jpg": null,
"youtube-mp3.org/acode": null,
"youtube.com/pagead": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/driba.html": null,
"youwatch.org/iframe1.html": null,
"youwatch.org/vod-str.html": null,
"yts.ag/images/vpnanim.gif": null,
"zambiz.co.zm/banners": null,
"zamimg.com/images/skins": null,
"zamimg.com/shared/minifeatures": null,
"zattoo.com/ads": null,
"zawya.com/ads": null,
"zawya.com/brands": null,
"zdnet.com/medusa": null,
"zeenews.com/ads": null,
"zeetvusa.com/images/CARIBBEN.jpg": null,
"zeetvusa.com/images/hightlow.jpg": null,
"zeetvusa.com/images/SevaWeb.gif": null,
"zeropaid.com/images": null,
"ziddu.com/images/140x150_egglad.gif": null,
"ziddu.com/images/globe7.gif": null,
"ziddu.com/images/wxdfast": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"zomobo.net/images/removeads.png": null,
"zoneradio.co.za/img/banners": null,
"zoomin.tv/decagonhandler": null,
"zootoday.com/pub/21publish/Zoo-navtop-poker.gif": null,
"zorrovpn.com/static/img/promo": null,
"zshares.net/fm.html": null,
"zurrieqfc.com/images/banners": null,
"kickass.cd/test.js": null,
"fitnesshe.co.za/images/abs.png": null,
"fitnessmag.co.za/images/abs.png": null,
"gannett-cdn.com/appservices/partner/sourcepoint/sp-mms-client.js": null,
"getdebrid.com/blocker.js": null,
"hindustantimes.com/res/js/ht-modified-script.js": null,
"vapingunderground.com/js/vapingunderground/fucking_adblock.js": null,
"anandabazar.com/js/anandabazar-bootstrap/custom.js": null,
"4fuckr.com/api.php": null,
"cloudzilla.to/cam/wpop.php": null,
"comicbookmovie.com/plugins/ads": null,
"filepost.com/default_popup.html": null,
"free-filehost.net/pop": null,
"fullonsms.com/blank.php": null,
"fullonsms.com/mixpop.html": null,
"fullonsms.com/quikr.html": null,
"fullonsms.com/quikrad.html": null,
"fullonsms.com/sid.html": null,
"gamezadvisor.com/popup.php": null,
"imagepearl.com/view": null,
"imageshack.us/ads": null,
"imageshack.us/newuploader_ad.php": null,
"imgcarry.com/includes/js/layer.js": null,
"military.com/data/popup/new_education_popunder.htm": null,
"multiupload.nl/popunder": null,
"rediff.com/uim/ads": null,
"subs4free.com/_pop_link.php": null,
"thevideo.me/mpaabp": null,
"torrentz.eu/p": null,
"virtualtourist.com/commerce/popunder": null,
"vodu.ch/play_video.php": null,
"watch-movies.net.in/popup.php": null,
"yasni.ca/ad_pop.php": null,
"ziddu.com/onclickpop.php": null,
"24porn7.com/24roll.html": null,
"24porn7.com/300.php": null,
"24porn7.com/banned": null,
"24porn7.com/ebanners": null,
"24porn7.com/float/float_adplib.js": null,
"24porn7.com/imads": null,
"24porn7.com/odd.php": null,
"24porn7.com/right3.php": null,
"24porn7.com/toonad": null,
"24video.net/din_new6.php": null,
"2adultflashgames.com/images/v12.gif": null,
"2adultflashgames.com/img": null,
"2adultflashgames.com/teaser/teaser.swf": null,
"3movs.com/contents/content_sources": null,
"4sex4.com/pd": null,
"4tube.com/tb/banner": null,
"5ilthy.com/porn.php": null,
"abc-celebs.com/spons": null,
"absoluporn.com/code/pub": null,
"adrive.com/images/fc_banner.jpg": null,
"adult-sex-games.com/images/promo": null,
"adultdvdtalk.com/studios": null,
"adultfilmdatabase.com/graphics/banners": null,
"adultfyi.com/images/banners": null,
"adultwork.com/images/AWBanners": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"alotporn.com/media/banners": null,
"amateur-desire.com/pics/724x90d.jpg": null,
"amateuralbum.net/affb.html": null,
"amateurfarm.net/layer.js": null,
"analpornpix.com/agent.php": null,
"analtubegirls.com/js/realamateurtube.js": null,
"angelshack.com/images/under-video.png": null,
"anon-v.com/neverlikedcocksmuch.php": null,
"anon-v.com/titswerentoiledup.php": null,
"anysex.com/b": null,
"anysex.com/content_sources": null,
"asexstories.com/010ads": null,
"asgayas.com/floater": null,
"asgayas.com/popin.js": null,
"asianpornmovies.com/images/banners": null,
"asspoint.com/images/banners": null,
"axatube.com/dos.html": null,
"babblesex.com/js/misc.js": null,
"babedrop.com/babelogger_images": null,
"babesandstars.com/images/a": null,
"babesandstars.com/thumbs/paysites": null,
"babeshows.co.uk/fvn53.jpg": null,
"babesmachine.com/html": null,
"bangyoulater.com/pages/aff.php": null,
"befuck.com/befuck_html": null,
"bellyboner.com/facebookchatlist.php": null,
"between-legs.com/banners2": null,
"bigboobs.hu/banners": null,
"bigxvideos.com/rec": null,
"blackonasianblog.com/uploads/banners": null,
"blackredtube.com/fadebox2.js": null,
"bonbonme.com/js/cams.js": null,
"bonbonme.com/js/dticash": null,
"bonbonme.com/js/rightbanner.js": null,
"bonbonsex.com/js/dl/bottom.js": null,
"bonbonsex.com/js/workhome.js": null,
"boobieblog.com/submityourbitchbanner3.jpg": null,
"boobieblog.com/TilaTequilaBackdoorBanner2.jpg": null,
"bralesscelebs.com/160x600hcp.gif": null,
"bralesscelebs.com/160x600ps.gif": null,
"bralesscelebs.com/320x240ps.gif": null,
"bravotube.net/dp.html": null,
"bunnylust.com/sponsors": null,
"camwhores.tv/banners": null,
"canadianhottie.ca/images/banners": null,
"celeb.gate.cc/banner": null,
"cfake.com/images/a": null,
"chanweb.info/en/adult/hc/local_include": null,
"chubby-ocean.com/banner": null,
"comdotgame.com/vgirl": null,
"crackwhoreconfessions.com/images/banners": null,
"creampietubeporn.com/ctp.html": null,
"creampietubeporn.com/porn.html": null,
"daporn.com/_p4.php": null,
"definebabe.com/db/images/leftnav/webcams2.png": null,
"definebabe.com/db/js/pcme.js": null,
"definebabe.com/sponsor": null,
"deliciousbabes.org/banner": null,
"deliciousbabes.org/media/banners": null,
"depic.me/banners": null,
"destroymilf.com/popup%20floater.js": null,
"devatube.com/img/partners": null,
"dirtypriest.com/sexpics": null,
"dixyporn.com/include": null,
"dominationtube.com/exit.js": null,
"downloadableporn.org/popaaa": null,
"dronporn.com/main-video-place.html": null,
"dronporn.com/tizer.html": null,
"drtuber.com/templates/frontend/white/js/embed.js": null,
"easypic.com/js/easypicads.js": null,
"eccie.net/buploads": null,
"eccie.net/eros": null,
"eegay.com/Scripts/nxpop.js": null,
"egoporn.com/themagic.js": null,
"egoporn.com/videotop.gif": null,
"epicwank.com/social/jquery.stp.min.js": null,
"eporner.com/cppb": null,
"eskimotube.com/kellyban.gif": null,
"exhentai.net/img/aaf1.gif": null,
"extreme-board.com/bannrs": null,
"fantasti.cc/_special": null,
"fastpic.ru/js_f2.jpg": null,
"fastpic.ru/js_h2.jpg": null,
"femdom-fetish-tube.com/popfemdom.js": null,
"filthyrx.com/images/porno": null,
"filthyrx.com/inline.php": null,
"filthyrx.com/rx.js": null,
"floppy-tits.com/iframes": null,
"fooktube.com/badges/pr": null,
"free-celebrity-tube.com/js/freeceleb.js": null,
"freebunker.com/includes/js/cat.js": null,
"freeimgup.com/xxx/content/system/js/iframe.html": null,
"freeones.com/images/freeones/sidewidget": null,
"freeporn.to/wpbanner": null,
"freepornvs.com/im.js": null,
"fuckuh.com/pr_ad.swf": null,
"funny-games.biz/banners": null,
"galleries-pornstar.com/thumb_top": null,
"gals4free.net/images/banners": null,
"gamesofdesire.com/images/banners": null,
"gapeandfist.com/uploads/thumbs": null,
"gayporntimes.com/img/GP_Heroes.jpg": null,
"gaytube.com/chacha": null,
"gggtube.com/images/banners": null,
"ghettotube.com/images/banners": null,
"girlfriendvideos.com/pcode.js": null,
"girlsfrombudapest.eu/banners": null,
"girlsfromprague.eu/banners": null,
"girlsintube.com/images/get-free-server.jpg": null,
"girlsnaked.net/gallery/banners": null,
"girlsofdesire.org/banner": null,
"girlsofdesire.org/media/banners": null,
"glamour.cz/banners": null,
"gloryholegirlz.com/images/banners": null,
"goldporntube.com/iframes": null,
"gotgayporn.com/Watermarks": null,
"grannysexforum.com/filter.php": null,
"h2porn.com/ab": null,
"h2porn.com/contents/content_sources": null,
"h2porn.com/js/etu_r.js": null,
"hanksgalleries.com/galleryimgs": null,
"hardcoresexgif.com/hcsg.js": null,
"hardcoresexgif.com/msn.js": null,
"hardsextube.com/preroll/getiton": null,
"hardsextube.com/testxml.php": null,
"hardsextube.com/zone.php": null,
"hawaiipornblog.com/post_images": null,
"hcomicbook.com/banner": null,
"hdporn.in/images/rec": null,
"hdporn.net/images/hd-porn-banner.gif": null,
"hdzog.com/contents/content_sources": null,
"hdzog.com/contents/cst": null,
"hellporno.com/iframes": null,
"hentai-foundry.com/themes/Hentai/images/hu/hu.jpg": null,
"hentaistream.com/out": null,
"hidefporn.ws/04.jpg": null,
"hidefporn.ws/05.jpg": null,
"hidefporn.ws/055.jpg": null,
"hidefporn.ws/img.png": null,
"hidefporn.ws/nitro.png": null,
"homeprivatevids.com/banner2.shtml": null,
"homeprivatevids.com/banners.shtml": null,
"hornygamer.com/images/promo": null,
"hornywhores.net/img/double.jpg": null,
"hornywhores.net/img/zevera_rec.jpg": null,
"hothag.com/img/banners": null,
"hotshame.com/hotshame_html": null,
"hotshame.com/iframes": null,
"hottestgirlsofmyspace.net/smallpics/300x200b.gif": null,
"hottestgirlsofmyspace.net/smallpics/fb-150x150.gif": null,
"hottubeclips.com/stxt/banners": null,
"hungangels.com/vboard/friends": null,
"hustler.com/backout-script": null,
"imagearn.com/img/picBanner.swf": null,
"imagefap.com/019ce.php": null,
"imagefap.com/ajax/uass.php": null,
"imagehyper.com/prom": null,
"imageporter.com/ro-7bgsd.html": null,
"imageporter.com/smate.html": null,
"imagepost.com/includes/dating": null,
"imagepost.com/stuff": null,
"imagesnake.com/includes/js/cat.js": null,
"imagesnake.com/includes/js/js.js": null,
"imagesnake.com/includes/js/layer.js": null,
"imagesnake.com/includes/js/pops.js": null,
"imagetwist.com/lj.js": null,
"imgbabes.com/element.js": null,
"imgbabes.com/ero-foo.html": null,
"imgbabes.com/ja.html": null,
"imgflare.com/exo.html": null,
"imghost.us.to/xxx/content/system/js/iframe.html": null,
"imgwet.com/aa": null,
"imperia-of-hentai.net/banner": null,
"inhumanity.com/cdn/affiliates": null,
"intporn.org/scripts/asma.js": null,
"iseekgirls.com/g/pandoracash": null,
"iseekgirls.com/js/fabulous.js": null,
"jailbaitgallery.com/banners300": null,
"jav-porn.net/js/popout.js": null,
"jav-porn.net/js/popup.js": null,
"javhub.net/img/r.jpg": null,
"javporn.in/clicunder.js": null,
"javstreaming.net/app/forad.js": null,
"justporno.tv/ad": null,
"keezmovies.com/iframe.html": null,
"kindgirls.com/banners2": null,
"konachan.com/images/bam": null,
"krasview.ru/resource/a.php": null,
"kuntfutube.com/kellyban.gif": null,
"lesbian.hu/banners": null,
"linksave.in/fopen.html": null,
"literotica.com/images/banners": null,
"literotica.com/images/lit_banners": null,
"live-porn.tv/adds": null,
"liveandchat.tv/bana-": null,
"lubetube.com/js/cspop.js": null,
"lucidsponge.pl/pop_": null,
"lukeisback.com/images/boxes": null,
"mansurfer.com/flash_promo": null,
"matureworld.ws/images/banners": null,
"maxjizztube.com/downloadfreemovies.php": null,
"meatspin.com/facebookchatlist.php": null,
"meatspin.com/images/fl.gif": null,
"merb.ca/banner": null,
"miragepics.com/images/11361497289209202613.jpg": null,
"mobilepornmovies.com/images/banners": null,
"monstercockz.com/cont": null,
"monstercockz.com/eds": null,
"monstertube.com/images/bottom-features.jpg": null,
"morebabes.to/morebabes.js": null,
"motherless.com/images/banners": null,
"mrskin.com/data/mrskincash": null,
"mrstiff.com/uploads/paysite": null,
"my-pornbase.com/banner": null,
"mydailytube.com/nothing": null,
"mygirlfriendvids.net/js/popall1.js": null,
"myslavegirl.org/follow/go.js": null,
"naked-sluts.us/prpop.js": null,
"namethatpornstar.com/topphotos": null,
"naughty.com/js/popJava.js": null,
"naughtyblog.org/b_load.php": null,
"naughtyblog.org/pr1pop.js": null,
"newcelebnipslips.com/nipslipop.js": null,
"niceyoungteens.com/mct.js": null,
"nonktube.com/brazzers": null,
"nonktube.com/nuevox/midroll.php": null,
"nonktube.com/popembed.js": null,
"novoporn.com/imagelinks": null,
"ns4w.org/images/promo": null,
"nude.hu/banners": null,
"nudebabes.ws/galleries/banners": null,
"nudeflix.com/ads/video-player": null,
"nudography.com/photos/banners": null,
"nuvid.com/videos_banner.html": null,
"oporn.com/js/wspop.js": null,
"pastime.biz/images/iloveint.gif": null,
"pastime.biz/images/interracial-porn.gif": null,
"perfectgirls.net/b": null,
"perfectgirls.net/exo": null,
"phncdn.com/images/banners": null,
"phncdn.com/images/premium": null,
"phncdn.com/images/skin": null,
"phncdn.com/mobile/js/interstitial-min.js": null,
"phun.org/phun/gfx/banner": null,
"pichunter.com/creatives": null,
"pichunter.com/deals": null,
"picsexhub.com/rec": null,
"picturedip.com/modalfiles/modal.js": null,
"picturedip.com/windowfiles/dhtmlwindow.css": null,
"picturescream.com/porn_movies.gif": null,
"picturescream.com/top_banners.html": null,
"picturevip.com/imagehost/top_banners.html": null,
"pimpandhost.com/images/pah-download.gif": null,
"pimpandhost.com/static/html/iframe.html": null,
"pink-o-rama.com/Longbucks": null,
"pink-o-rama.com/Royalcash": null,
"pinkems.com/images/buttons": null,
"pinkrod.com/iframes": null,
"pixhost.org/image/cu": null,
"pixhost.org/image/rotate": null,
"pixhost.org/js/jquery_show2.js": null,
"planetsuzy.org/kakiframe": null,
"playgirl.com/pg/media/prolong_ad.png": null,
"playpornx.net/pu": null,
"plumper6.com/images/ban_pp.jpg": null,
"porn-w.org/chili.php": null,
"porn-w.org/images/chs.gif": null,
"porn-w.org/images/cosy": null,
"porn-w.org/images/ls.gif": null,
"porn-w.org/images/zevera.png": null,
"porn.com/js/pu.js": null,
"porn8x.net/js/outtrade.js": null,
"porn8x.net/js/popup.js": null,
"pornalized.com/contents/content_sources": null,
"pornalized.com/js/adppornalized5.js": null,
"pornbanana.com/pornbanana/deals": null,
"pornbay.org/popup.js": null,
"pornbb.org/images/rotation": null,
"pornbus.org/includes/js/bgcont.js": null,
"pornbus.org/includes/js/cat.js": null,
"pornbus.org/includes/js/ex.js": null,
"pornbus.org/includes/js/exa.js": null,
"pornbus.org/includes/js/layer.js": null,
"porncor.com/sitelist.php": null,
"pornerbros.com/p_bnrs": null,
"pornfanplace.com/rec": null,
"porngals4.com/img/b": null,
"pornhub.com/catagories/costume": null,
"pornhub.com/channels/pay": null,
"pornhub.com/front/alternative": null,
"pornhub.com/jpg": null,
"pornhub.phncdn.com/images/campaign-backgrounds": null,
"pornhub.phncdn.com/misc/xml/preroll.xml": null,
"pornizer.com/_Themes/javascript/cts.js": null,
"pornmade.com/images/404vz.gif": null,
"pornmade.com/images/az.gif": null,
"pornmaturetube.com/content": null,
"pornmaturetube.com/content2": null,
"pornmaturetube.com/eureka": null,
"pornnavigate.com/feeds/delivery.php": null,
"pornoid.com/contents/content_sources": null,
"pornoid.com/pornoid_html": null,
"pornoinside.com/efpop.js": null,
"pornomovies.com/pop": null,
"pornorips.com/hwpop.js": null,
"pornosexxxtits.com/rec": null,
"pornoxo.com/tradethumbs": null,
"pornpause.com/fakevideo": null,
"pornper.com/mlr": null,
"pornreleasez.com/prpop.js": null,
"pornshare.biz/1.js": null,
"pornshare.biz/2.js": null,
"pornsharia.com/Images/Sponsors": null,
"pornslash.com/images/a.gif": null,
"pornslash.com/images/cbside.gif": null,
"pornslash.com/images/cbt.gif": null,
"pornslash.com/images/downicon.png": null,
"pornslash.com/images/pr.jpg": null,
"pornstarlabs.com/spons": null,
"pornstarterritory.com//images/bannernew.jpg": null,
"pornstreet.com/siteunder.js": null,
"porntalk.com/img/banners": null,
"porntalk.com/rec": null,
"porntube.com/adb": null,
"pornup.me/js/pp.js": null,
"pornwikileaks.com/adultdvd.com.jpg": null,
"pornxs.com/js/aab": null,
"pornxs.com/js/exo.js": null,
"pureandsexy.org/banner": null,
"puteros.com/publisecciones": null,
"pwpwpoker.com/images/banners": null,
"raincoatreviews.com/images/banners": null,
"rampant.tv/images/sexypics": null,
"realgfporn.com/js/popall.js": null,
"realgfporn.com/js/realgfporn.js": null,
"realhomesex.net/floater.js": null,
"realhomesex.net/pop": null,
"redtube.cc/images/bongacams.png": null,
"redtube.com/barelylegal": null,
"redtube.com/bestporn": null,
"redtube.com/nymphos": null,
"redtube.com/sexychicks": null,
"redtube.com/wierd": null,
"rextube.com/plug/iframe.asp": null,
"rikotachibana.org/wp-content/banner": null,
"rude.com/js/PopupWindow.js": null,
"rule34.xxx/r34.js": null,
"rusdosug.com/Fotos/Banners": null,
"russiansexytube.com/js/spc_banners_init.js": null,
"russiansexytube.com/js/video_popup.js": null,
"scorehd.com/banner": null,
"scorevideos.com/banner": null,
"seaporn.org/scripts/life.js": null,
"sensualgirls.org/banner": null,
"sensualgirls.org/media/banners": null,
"serveporn.com/images/a-en.jpg": null,
"serveporn.com/images/plug-in.jpg": null,
"sex-techniques-and-positions.com/123ima": null,
"sex3.com/if": null,
"sex3dtoons.com/im": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"sexmummy.com/float.htm": null,
"sexmummy.com/footer.htm": null,
"sexphoto.xxx/sites": null,
"sextube.com/lj.js": null,
"sextubebox.com/ab1.shtml": null,
"sextubebox.com/ab2.shtml": null,
"sexuhot.com/splayer.js": null,
"sexvideogif.com/msn.js": null,
"sexvideogif.com/svg.js": null,
"sexy-toons.org/interface/partenariat": null,
"sexy-toons.org/interface/pub": null,
"sexyandshocking.com/mzpop.js": null,
"sexyclips.org/banners": null,
"sexyclips.org/i/130x500.gif": null,
"sexyfuckgames.com/images/promo": null,
"sexyshare.net//banners": null,
"sexytime.com/img/sexytime_anima.gif": null,
"sharew.org/modalfiles": null,
"shemaletubevideos.com/images/banners": null,
"shooshtime.com/ads": null,
"shooshtime.com/images/chosenplugs": null,
"shy-cams.com/tube.js": null,
"signbucks.com/s/bns": null,
"signbucksdaily.com/data/promo": null,
"skimtube.com/kellyban.gif": null,
"slinky.com.au/banners": null,
"smutmodels.com/sponsors": null,
"socaseiras.com.br/arquivos/banners": null,
"socaseiras.com.br/banners.php": null,
"springbreaktubegirls.com/js/springpop.js": null,
"starcelebs.com/logos": null,
"stockingstv.com/partners": null,
"stolenvideos.net/stolen.js": null,
"submityourflicks.com/banner": null,
"sunporno.com/js/flirt/serve.js": null,
"taxidrivermovie.com/mrskin_runner": null,
"teensanalfactor.com/best": null,
"teensexcraze.com/awesome/leader.html": null,
"teentube18.com/js/realamateurtube.js": null,
"temptingangels.org/banner": null,
"temptingangels.org/media/banners": null,
"thefappeningblog.com/icloud9.html": null,
"thenipslip.com/GGWDrunkenAd.jpg": null,
"thenipslip.com/mfcbanner.gif": null,
"thenude.eu/affiliates": null,
"thenude.eu/images/sexart_sidebar.png": null,
"thenude.eu/media/mxg": null,
"theporncore.com/contents/content_sources": null,
"thinkexist.com/images/afm.js": null,
"thisav.com/js/thisav_pop.js": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"timtube.com/traffic.js": null,
"titsintops.com/intersitial": null,
"titsintops.com/rotate": null,
"tnaflix.com/banner": null,
"tube8.com/penthouse": null,
"tube8.com/sugarcrush": null,
"tubecup.com/contents/content_sources": null,
"tubecup.com/js/1.js": null,
"tubedupe.com/footer_four.html": null,
"tubedupe.com/side_two.html": null,
"turboimagehost.com/p1.js": null,
"twinsporn.net/images/delay.gif": null,
"twinsporn.net/images/free-penis-pills.png": null,
"ukrainamateurs.com/images/banners": null,
"unblockedpiratebay.com/static/img/bar.gif": null,
"unoxxx.com/pages/en_player_video_right.html": null,
"updatetube.com/js/fab.js": null,
"upornia.com/contents/content_sources": null,
"vibraporn.com/vg": null,
"vidgrab.net/adsbar.png": null,
"vidgrab.net/pads2.js": null,
"vivatube.com/upload/banners": null,
"voyeurhit.com/contents/content_sources": null,
"wank.to/partner": null,
"watch2porn.net/pads2.js": null,
"watchindianporn.net/js/pu.js": null,
"weberotic.net/banners": null,
"wegcash.com/click": null,
"wetpussygames.com/images/promo": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"wikiporno.org/header2.html": null,
"wikiporno.org/header21.html": null,
"woodrocket.com/img/banners": null,
"worldsex.com/c": null,
"wrenchtube.com/poppt.js": null,
"wunbuck.com/_odd_images/banners": null,
"wunbuck.com/iframes/aaw_leaderboard.html": null,
"xbabe.com/iframes": null,
"xbooru.com/block/adblocks.js": null,
"xbutter.com/js/pop-er.js": null,
"xhamster.com/ads": null,
"xogogo.com/images/latestpt.gif": null,
"xtravids.com/pop.php": null,
"xvideohost.com/hor_banner.php": null,
"xxvideo.us/bnr.js": null,
"xxvideo.us/playertext.html": null,
"xxxblink.com/rec": null,
"xxxhdd.com/contents/content_sources": null,
"xxxhdd.com/player_banners": null,
"xxxhdd.com/plugs-thumbs": null,
"xxxhost.me/xpw.gif": null,
"xxxkinky.com/pap.js": null,
"xxxlinks.es/xvideos.js": null,
"xxxporntalk.com/images": null,
"xxxymovies.com/js/win.js": null,
"yea.xxx/img/creatives": null,
"yobt.tv/js/ttu.js": null,
"yobt.tv/rec": null,
"youngpornvideos.com/images/bangbros": null,
"youngpornvideos.com/images/glamglam": null,
"youngpornvideos.com/images/mofoscash": null,
"youngpornvideos.com/images/teencash": null,
"youngpornvideos.com/images/webmasterdelightlinks": null,
"youngpornvideos.com/images/wmasterthecoolporn": null,
"youporn-hub.com/lcdscript.js": null,
"youporn-hub.com/newlcd.js": null,
"youporn.com/capedorset": null,
"youporn.com/watch_postroll": null,
"yourdailygirls.com/vanilla/process.php": null,
"yourdarkdesires.com/1.html": null,
"yourdarkdesires.com/2.html": null,
"yourdarkdesires.com/3.html": null,
"yourlust.com/im/onpause.html": null,
"yourlust.com/im/postroll.html": null,
"youtubelike.com/ftt2/toplists": null,
"youx.xxx/thumb_top": null,
"yporn.tv/uploads/flv_player/commercials": null,
"yporn.tv/uploads/flv_player/midroll_images": null,
"zazzybabes.com/misc/virtuagirl-skin.js": null,
"bitchcrawler.com": null,
"downloadableporn.org/xxx": null,
"eporner.com/pop.php": null,
"fantastube.com/track.php": null,
"h2porn.com/pu.php": null,
"hegansex.com/exo.php": null,
"imagebam.com/redirect_awe.php": null,
"pinporn.com/popunder": null,
"pornuppz.info/out.php": null,
"ymages.org/prepop.php": null,
"google-analytics.com/analytics.js": null,
"google-analytics.com/cx/api.js": null,
"google-analytics.com/ga_exp.js": null,
"google-analytics.com/internal/analytics.js": null,
"google-analytics.com/plugins": null,
"google-analytics.com/siteopt.js": null,
"googletagmanager.com/gtm.js": null,
"quantserve.com/api": null,
"quantserve.com/pixel": null,
"visiblemeasures.com/swf/as3/as3sohandler.swf": null,
"101apps.com/tracker.ashx": null,
"148.251.8.156/track.js": null,
"198.101.148.38/update_counter.php": null,
"208.91.157.30/viewtrack": null,
"4theclueless.com/adlogger": null,
"5251.net/stat.jsp": null,
"88.208.248.58/tracking": null,
"99widgets.com/counters": null,
"aao.org/aao/sdc/track.js": null,
"acces-charme.com/fakebar/track.php": null,
"ad.atdmt.com/c": null,
"ad.atdmt.com/e": null,
"ad.atdmt.com/i/img": null,
"ad.atdmt.com/m": null,
"ad.atdmt.com/s": null,
"addnow.com/tracker": null,
"addthis.com/at": null,
"addthis.com/live": null,
"addthis.com/red/p.png": null,
"addthiscdn.com/live": null,
"addthisedge.com/live": null,
"addtoany.com/menu/transparent.gif": null,
"adultmastercash.com/e1.php": null,
"affilired.com/analytic": null,
"afrigator.com/track": null,
"aiya.com.cn/stat.js": null,
"akamai.com/crs/lgsitewise.js": null,
"akanoo.com/tracker": null,
"alexa.com/traffic": null,
"alipay.com/service/clear.png": null,
"allanalpass.com/track": null,
"alooma.io/track": null,
"alphasitebuilder.co.za/tracker": null,
"amatomu.com/link/log": null,
"amatomu.com/log.php": null,
"amazonaws.com/amacrpr/crpr.js": null,
"amazonaws.com/cdn.barilliance.com": null,
"amazonaws.com/fstrk.net": null,
"amazonaws.com/g.aspx": null,
"amazonaws.com/initialize": null,
"amazonaws.com/js/reach.js": null,
"amazonaws.com/ki.js": null,
"amazonaws.com/new.cetrk.com": null,
"amazonaws.com/searchdiscovery-satellite-production": null,
"amazonaws.com/statics.reedge.com": null,
"amazonaws.com/wgntrk": null,
"aolanswers.com/wtrack": null,
"aolcdn.com/js/mg2.js": null,
"aolcdn.com/omniunih_int.js": null,
"api.awe.sm/stats": null,
"api.choicestream.com/instr/ccm": null,
"app.cdn-cs.com/__t.png": null,
"app.pendo.io/data/ptm.gif": null,
"appliedsemantics.com/images/x.gif": null,
"appspot.com/api/track": null,
"asterpix.com/tagcloudview": null,
"atdmt.com/action": null,
"atdmt.com/iaction": null,
"atdmt.com/jaction": null,
"atdmt.com/mstag": null,
"atom-data.io/session/latest/track.html": null,
"autoline-top.com/counter.php": null,
"aweber.com/form/displays.htm": null,
"b5media.com/bbpixel.php": null,
"bhphotovideo.com/imp": null,
"bidsystem.com/ppc/sendtracker.aspx": null,
"bing.com/action": null,
"bitgravity.com/b.gif": null,
"blinkx.com/thirdparty/iab": null,
"blogblog.com/tracker": null,
"bobparsons.com/image.aspx": null,
"brandaffinity.net/icetrack": null,
"bravenet.com/counter": null,
"break.com/apextracker": null,
"break.com/break/js/brktrkr.js": null,
"breakingburner.com/stats.html": null,
"breakmedia.com/track.jpg": null,
"browserscope.org/user/beacon": null,
"canada.com/js/analytics": null,
"carambo.la/analytics": null,
"carambo.la/logging": null,
"cdnma.com/apps/capture.js": null,
"cdnplanet.com/static/rum/rum.js": null,
"citygridmedia.com/tracker": null,
"citysearch.com/tracker": null,
"clickchatsold.com/d0": null,
"cloudapp.net/l": null,
"cloudfront.net/abw.js": null,
"cloudfront.net/analytics.js": null,
"cloudfront.net/analyticsengine": null,
"cloudfront.net/bti": null,
"cloudfront.net/code/keen-2.1.0-min.js": null,
"cloudfront.net/esf.js": null,
"cloudfront.net/js/ca.js": null,
"cloudfront.net/js/reach.js": null,
"cloudfront.net/khp.js": null,
"cloudfront.net/log.js": null,
"cloudfront.net/performable": null,
"cloudfront.net/powr.js": null,
"cloudfront.net/pt1x1.gif": null,
"cloudfront.net/rc.js": null,
"cloudfront.net/rum/bacon.min.js": null,
"cloudfront.net/sentinel.js": null,
"cloudfront.net/sso.js": null,
"cloudfront.net/track.html": null,
"cloudfront.net/trackb.html": null,
"cloudfront.net/tracker.js": null,
"cloudfront.net/zephyr.js": null,
"cnevids.com/metrics": null,
"cnpapers.com/scripts/library": null,
"comic-rocket.com/metrics.js": null,
"compendiumblog.com/js/stats.js": null,
"creativecdn.com/pix": null,
"crm-vwg.com/tracker": null,
"crowdfactory.com/tracker": null,
"cumulus-cloud.com/trackers": null,
"d27s92d8z1yatv.cloudfront.net/js/jquery.jw.analitycs.js": null,
"d2nq0f8d9ofdwv.cloudfront.net/track.js": null,
"d3qxef4rp70elm.cloudfront.net/m.js": null,
"data.fotorama.io": null,
"daylogs.com/counter": null,
"dealerfire.com/analytics": null,
"deb.gs/track": null,
"delivra.com/tracking": null,
"delvenetworks.com/player/plugins/analytics": null,
"demandmedia.com/wm.js": null,
"desert.ru/tracking": null,
"digimedia.com/pageviews.php": null,
"directnews.co.uk/feedtrack": null,
"disqus.com/stats.html": null,
"dmcdn.net/behavior": null,
"dn-net.com/cc.js": null,
"dtym7iokkjlif.cloudfront.net/dough": null,
"early-birds.fr/tracker": null,
"ecustomeropinions.com/survey/nojs.php": null,
"elb.amazonaws.com/partner.gif": null,
"elb.amazonaws.com/small.gif": null,
"email-edg.paypal.com/o": null,
"emarketeer.com/tracker": null,
"embedly.com/widgets/xcomm.html": null,
"epromote.co.za/track": null,
"eventful.com/apps/generic": null,
"eviesays.com/js/analytics": null,
"evri.com/analytics": null,
"facebook.com/ai.php": null,
"facebook.com/audience_network": null,
"facebook.com/brandlift.php": null,
"facebook.com/common/scribe_endpoint.php": null,
"facebook.com/email_open_log_pic.php": null,
"facebook.com/fr/u.php": null,
"facebook.com/js/conversions/tracking.js": null,
"facebook.com/offsite_event.php": null,
"facebook.com/rtb_impression": null,
"facebook.com/rtb_video": null,
"facebook.com/tr": null,
"fairfax.com.au/js/track": null,
"filesonic.com/referral": null,
"fitanalytics.com/metrics": null,
"flashi.tv/histats.php": null,
"flex.msn.com/mstag": null,
"fliqz.com/metrics": null,
"followistic.com/widget/stat": null,
"footballmedia.com/tracking": null,
"foxcontent.com/tracking": null,
"ftimg.net/js/log.js": null,
"gatehousemedia.com/wickedlocal/ip.js": null,
"geckofoot.com/gfcounterimg.aspx": null,
"geckofoot.com/gfvisitormap.aspx": null,
"geni.us/snippet.js": null,
"github.com/notifications/beacon": null,
"glam.com/cece/agof": null,
"glam.com/ctagsimgcmd.act": null,
"glam.com/jsadimp.gif": null,
"goaww.com/stats.php": null,
"godaddy.com/js/gdwebbeacon.js": null,
"googleusercontent.com/tracker": null,
"gotdns.com/track/blank.aspx": null,
"gotmojo.com/track": null,
"gowatchit.com/analytics.js": null,
"grabnetworks.com/beacons": null,
"gstatic.com/gadf/ga_dyn.js": null,
"gubagoo.com/modules/tracking": null,
"h2porn.com/new-hit": null,
"hasbro.com/includes/js/metrics": null,
"hgcdn.net": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"hqq.tv/js/counters.js": null,
"hubspot.com/analytics": null,
"hubspot.com/cs/loader-v2.js": null,
"hubspot.com/tracking": null,
"i.s-microsoft.com/wedcs/ms.js": null,
"icbdr.com/images/pixel.gif": null,
"imgfarm.com/images/trk/myexcitetr.gif": null,
"imghostsrc.com/counter.php": null,
"impi.tv/trackvideo.aspx": null,
"ind.sh/view.php": null,
"infogr.am/logger.php": null,
"inphonic.com/tracking": null,
"inq.com/tagserver/logging": null,
"inq.com/tagserver/tracking": null,
"installiq.com/Pixels": null,
"intensedebate.com/remotevisit.php": null,
"intensedebate.com/widgets/blogstats": null,
"interestsearch.net/videoTracker.js": null,
"internetfuel.com/tracking": null,
"intuitwebsites.com/tracking": null,
"jobvite.com/analytics.js": null,
"join-safe.com/tracking": null,
"kbb.com/partner": null,
"keywee.co/analytics.js": null,
"lederer.nl/incl/stats.js.php": null,
"legacy.com/globalscripts/tracking": null,
"lela.com/api/v2/tracking.js": null,
"letv.com/cloud_pl": null,
"lightboxcdn.com/static/identity.html": null,
"lijit.com/ip.php": null,
"lijit.com/res/images/wijitTrack.gif": null,
"lingows.appspot.com/page_data": null,
"link.indiegogo.com/img": null,
"linkbucks.com/visitScript": null,
"linkedin.com/emimp": null,
"linkwithin.com/pixel.png": null,
"list-manage.com/track": null,
"livefyre.com/libs/tracker": null,
"livefyre.com/tracking": null,
"liverail.com/track": null,
"location3.com/analytics": null,
"ltassrv.com/track": null,
"luminate.com/track": null,
"magnify.net/decor/track": null,
"mail-app.com/pvtracker": null,
"mandrillapp.com/track": null,
"mangomolo.com/tracking": null,
"mansion.com/mts.tracker.js": null,
"mapquestapi.com/logger": null,
"mashery.com/analytics": null,
"maxmind.com/geoip": null,
"mbsvr.net/js/tracker": null,
"media-imdb.com/twilight": null,
"mediabong.com/t": null,
"mediabong.net/t": null,
"meebo.com/cim/sandbox.php": null,
"merchenta.com/track": null,
"mkcms.com/stats.js": null,
"mochiads.com/clk": null,
"msecnd.net/scripts/a/ai.0.js": null,
"mtvnservices.com/metrics": null,
"museter.com/track.php": null,
"mxmfb.com/rsps/img": null,
"myfreecams.com/mfc2/lib/o-mfccore.js": null,
"mymarketing.co.il/Include/tracker.js": null,
"mysociety.org/track": null,
"mzbcdn.net/mngr/mtm.js": null,
"nastydollars.com/trk": null,
"navlink.com/__utmala.js": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"neon-lab.com/neonbctracker.js": null,
"netne.net/stats": null,
"nitropay.com/nads": null,
"nsdsvc.com/scripts/action-tracker.js": null,
"nspmotion.com/tracking": null,
"nude.hu/html/track.js": null,
"o.aolcdn.com/js/mg1.js": null,
"oddcast.com/event.php": null,
"odnaknopka.ru/stat.js": null,
"onescreen.net/os/static/pixels": null,
"onsugar.com/static/ck.php": null,
"ora.tv/j/ora_evttracking.js": null,
"pageturnpro.com/tracker.aspx": null,
"pair.com/itero/tracker_ftc": null,
"pcrl.co/js/jstracker.min.js": null,
"phncdn.com/js/ssig_helper.js": null,
"piano-media.com/auth/index.php": null,
"piano-media.com/bucket/novosense.swf": null,
"piano-media.com/uid": null,
"pixel.indieclicktv.com/annonymous": null,
"pixhosting.com/ct/jct.php": null,
"platform.twitter.com/impressions.js": null,
"pornhost.com/count_hit_player.php": null,
"poweredbyeden.com/widget/tracker": null,
"ppx.com/tracking": null,
"pricespider.com/impression": null,
"print2webcorp.com/mkt3/_js/p2w_tracker.js": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"propelplus.com/track": null,
"proxify.com/xyz.php": null,
"publicbroadcasting.net/analytics": null,
"qq.com/heatmap": null,
"quisma.com/tracking": null,
"rackcdn.com/easie.js": null,
"rackcdn.com/icon2.gif": null,
"rackcdn.com/knotice.api.js": null,
"rackcdn.com/stf.js": null,
"rbl.ms/res/users/tracking": null,
"readcube.com/tracking": null,
"reevoo.com/track": null,
"reevoo.com/track_url": null,
"reverbnation.com/widgets/trk": null,
"ria.ru/js/counter.js": null,
"royalecms.com/statistics.php": null,
"salesforce.com/sfga.js": null,
"saymedia.com/latest/tetrapak.js": null,
"scribol.com/traffix/widget_tracker": null,
"searchmaestros.com/trackpoint": null,
"sendtonews.com/player/loggingajax.php": null,
"shareaholic.com/partners.js": null,
"shareholder.com/track": null,
"shareit.com/affiliate.html": null,
"shoplocal.com/it.ashx": null,
"sinajs.cn/open/analytics": null,
"skimresources.com/api/ref-banners.js": null,
"skysa.com/tracker": null,
"slidesharecdn.com/images/1x1.gif": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"sohu.com/stat": null,
"southafricahome.com/statsmodulev2": null,
"spaceprogram.com/webstats": null,
"sparklit.com/counter": null,
"spot.im/analytics/analytics.js": null,
"spot.im/api/tracker": null,
"stats.screenresolution.org/get.php": null,
"stileproject.com/vhtk": null,
"su.pr/hosted_js": null,
"sulia.com/papi/sulia_partner.js": null,
"sumo.com/apps/heatmaps": null,
"sumome.com/api/event": null,
"sumome.com/apps/heatmaps": null,
"survey.io/log": null,
"swiftypecdn.com/cc.js": null,
"swiftypecdn.com/te.js": null,
"synergizeonline.net/trackpoint": null,
"tagcdn.com/pix": null,
"technorati.com/technoratimedia-pixel.js": null,
"techweb.com/beacon": null,
"themesltd.com/hit-counter": null,
"themesltd.com/online-users-counter": null,
"thepornstarlist.com/lo/lo/track.php": null,
"thespringbox.com/analytics": null,
"thismoment.com/tracking": null,
"thron.com/shared/plugins/tracking": null,
"tinyurl.com/pixel.gif": null,
"tmgrup.com.tr/Statistic": null,
"topix.net/t6track": null,
"totallylayouts.com/hit-counter": null,
"totallylayouts.com/online-users-counter": null,
"touchcommerce.com/tagserver/logging": null,
"tout.com/tracker.js": null,
"traq.li/tracker": null,
"trumba.com/et.aspx": null,
"trustpilot.com/stats": null,
"trustsquare.net/trafficmonitor": null,
"twitter.com/jot.html": null,
"twitter.com/oct.js": null,
"twitter.com/scribe": null,
"ultimatebootcd.com/tracker": null,
"v.giantrealm.com/players/stats.swf": null,
"vast.com/vimpressions.js": null,
"veeseo.com/tracking": null,
"ventunotech.com/beacon": null,
"video.google.com/api/stats": null,
"video.msn.com/report.aspx": null,
"videoplaza.com/proxy/distributor": null,
"videopress.com/plugins/stats": null,
"vindicosuite.com/track": null,
"vindicosuite.com/tracking": null,
"vindicosuite.com/xumo/swf": null,
"virgingames.com/tracker": null,
"visual.ly/track.php": null,
"vivociti.com/images": null,
"vizury.com/analyze": null,
"vk.com/videostats.php": null,
"voxmedia.com/beacon-min.js": null,
"voxmedia.com/pickup.js": null,
"vpoweb.com/counter.php": null,
"vwdealerdigital.com/cdn/sd.js": null,
"w3track.com/newtrk": null,
"weather.ca/counter.gif": null,
"web-soft.in/counters": null,
"webvoo.com/wt/Track.aspx": null,
"webworx24.co.uk/123trace.php": null,
"webzel.com/counter": null,
"whosread.com/counter": null,
"widgeo.net/tracking.php": null,
"widgetbox.com/syndication/track": null,
"widgethost.com/pax/counter.js": null,
"widgetserver.com/metrics": null,
"widgetserver.com/t": null,
"wondershare.es/jslibs/track.js": null,
"wpdigital.net/metrics": null,
"wsf.com/tracking": null,
"wsj.net/MW5/content/analytics/hooks.js": null,
"wvnetworkmedia.org/min": null,
"yellowbrix.com/images/content/cimage.gif": null,
"yimg.com/wi/ytc.js": null,
"ywxi.net/meter": null,
"zapcdn.space/zapret.js": null,
"zemanta.com/usersync/outbrain": null,
"zoover.co.uk/tracking": null,
"123rf.com/tk": null,
"1e400.net/tracking.js": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"3dcartstores.com/3droi/monstertrack.asp": null,
"4hds.com/js/camstats.js": null,
"4info.com/alert/listeners": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"a.huluad.com/beacons": null,
"abc.net.au/counters": null,
"abplive.in/analytics": null,
"accountnow.com/SyslogWriter.ashx": null,
"accuradio.com/static/track": null,
"accuterm.com/data/stat.js": null,
"aclu.org/aclu_statistics_image.php": null,
"acura.ca/_Global/js/includes/tracker.js": null,
"ad2links.com/lpajax.php": null,
"adapd.com/addon/upixel": null,
"adidas.com/analytics": null,
"adroll.com/pixel": null,
"advancedmp3players.co.uk/support/visitor/index.php": null,
"agendize.com/analytics.js": null,
"agoda.net/js/abtest/analytics.js": null,
"akamaihd.net/pixelkabam": null,
"alibi.com/tracker.gif": null,
"allafrica.com/img/static/s_trans_nc.gif": null,
"allcarpictures.com/stat": null,
"allexperts.com/px": null,
"allmovieportal.com/hostpagescript.js": null,
"amazon.com/gp/yourstore/recs": null,
"amazonaws.com/beacon/vtpixpc.gif": null,
"amcnets.com/cgi-bin/true-ip.cgi": null,
"amy.gs/track": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"any.gs/track": null,
"aol.ca/track": null,
"aol.co.uk/track": null,
"aol.com/articles/traffic": null,
"aol.com/beacons": null,
"aol.com/master": null,
"aol.com/metrics": null,
"aol.com/track": null,
"applegate.co.uk/javascript/dcs/track.js": null,
"appspot.com/tracking": null,
"ashleymadison.com/app/public/track.p": null,
"asianblast.com/statx": null,
"askmen.com/tracking": null,
"astrology.com/visits": null,
"atlantis.com/_scripts/tsedge/pagemarker.gif": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"autoblog.com/traffic": null,
"autobytel.com/content/shared/markerfile.bin": null,
"autosite.com/scripts/markerfile.bin": null,
"autotrader.co.uk/page-tracking": null,
"aviva.co.uk/metrics": null,
"azfamily.com/images/pixel.gif": null,
"baidu.com/js/log.js": null,
"bandstores.co.uk/tracking/scripts": null,
"barclaycard.co.uk/cs/static/js/esurveys/esurveys.js": null,
"bbc.co.uk/cbbc/statstracker": null,
"bbc.co.uk/click/img": null,
"bbc.co.uk/zaguk.gif": null,
"bbci.co.uk/archive_stats": null,
"bermudasun.bm/stats": null,
"bestofmedia.com/i/tomsguide/a.gif": null,
"bestofmedia.com/sfp/js/boomerang": null,
"beyond.com/common/track/trackgeneral.asp": null,
"bing.com/widget/metrics.js": null,
"birthvillage.com/watcher": null,
"blackplanet.com/images/shim.gif": null,
"blick.ch/stats": null,
"bluenile.ca/track": null,
"bluenile.co.uk/track": null,
"bluenile.com/track": null,
"boards.ie/timing.php": null,
"boats.com/images/tracking": null,
"brandrepublic.com/session-img": null,
"branica.com/counter.php": null,
"bridgetrack.com/site": null,
"bridgetrack.com/track": null,
"brightcove.com/1pix.gif": null,
"broadbandchoices.co.uk/track.js": null,
"bulgari.com/bulgari/wireframe_script/BulgariGa.js": null,
"business.com/images2/anal.gif": null,
"businessinsider.com/tracker.js": null,
"buto.tv/track": null,
"buzzamedia.com/js/track.js": null,
"buzzurl.jp/api/counter": null,
"caller.com/metrics": null,
"capitalone.com/tracker": null,
"cardstore.com/affiliate.jsp": null,
"cartoonnetwork.com/tools/js/clickmap": null,
"cbc.ca/g/stats": null,
"cbox.ws/box/relay.swf": null,
"cbsimg.net/js/cbsi/dw.js": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"cellstores.com/tracking": null,
"cert.org/images/1pxinv.gif": null,
"chanel.com/js/flashtrack.js": null,
"channel4.com/foresee_c4": null,
"charter.com/static/scripts/mock/tracking.js": null,
"cheapsalesconsulting.com/adaptive.php": null,
"china.com/statistic.js": null,
"chron.com/javascript/cider": null,
"click.news.imdb.com/open.aspx": null,
"cloudfront.net/amznUrchin.js": null,
"cloudfront.net/bbc-filter.js": null,
"cloudfront.net/m/princess/ae.js": null,
"cloudfront.net/m/princess/ae.live.js": null,
"cloudfront.net/vis_opt.js": null,
"cloudfront.net/vis_opt_no_jquery.js": null,
"codecguide.com/stats.js": null,
"codeweblog.com/js/count.js": null,
"collarity.com/ucs/tracker.js": null,
"collegehumor.com/track.php": null,
"commercialappeal.com/metrics": null,
"computershopper.com/wsgac": null,
"cooliris.com/shared/stats": null,
"cosmopolitan.co.za/rest/track": null,
"courierpress.com/metrics": null,
"cracked.com/tracking": null,
"crackle.com/tracking": null,
"creativecommons.org/elog": null,
"crowdignite.com/img/l.gif": null,
"crunchsports.com/tracking_fetchinfo.aspx": null,
"current.com/tracking.htm": null,
"customerservicejobs.com/common/track": null,
"cybercoders.com/js/tracker.js": null,
"cyberlink.com/analytics": null,
"dailyfinance.com/tmfstatic/vs.gif": null,
"dailymail.co.uk/tracking": null,
"dailymotion.com/logger": null,
"dailymotion.com/track": null,
"dainikbhaskar.com/tracking": null,
"deadspin.com/at.js.php": null,
"dealnews.com/lw/ul.php": null,
"debtconsolidationcare.com/affiliate/tracker": null,
"dell.com/metrics": null,
"depositfiles.com/stats.php": null,
"designtaxi.com/tracker.php": null,
"destructoid.com/img2.phtml": null,
"dictionary.com/track": null,
"displaymate.com/cgi-bin/stat": null,
"docstoc.com/metrics": null,
"domainit.com/scripts/track.js": null,
"domaintools.com/tracker.php": null,
"drpeterjones.com/stats": null,
"dump8.com/js/stat.php": null,
"dvdempire.com/images/empty2.asp": null,
"dyo.gs/track": null,
"eafyfsuh.net/track": null,
"ebay-us.com/fp": null,
"economist.com/geoip.php": null,
"ectnews.com/shared/missing.gif": null,
"edvantage.com.sg/site/servlet/tracker.jsp": null,
"egg.com/rum/data.gif": null,
"ehow.com/services/jslogging/log": null,
"engadget.com/traffic": null,
"eporner.com/stats": null,
"everythinggirl.com/assets/tracker": null,
"eweek.com/hqxapi": null,
"ex.ua/counter": null,
"exalead.com/search/pixel-ref": null,
"examiner.com/sites/all/modules/custom/ex_stats": null,
"exchangeandmart.co.uk/js/ga.js": null,
"experiandirect.com/javascripts/tracking.js": null,
"experts-exchange.com/pageloaded.jsp": null,
"ez.no/statjs": null,
"facebook.com/ct.php": null,
"facebook.com/search/web/instrumentation.php": null,
"facebook.com/xti.php": null,
"fanfiction.net/eye": null,
"fanhow.com/script/tracker.js": null,
"fantasticfiction.co.uk/cgi-bin/checker.cgi": null,
"farecompare.com/trackstar": null,
"fark.net/imagesnoc": null,
"farmville.com/trackaction.php": null,
"fastexercise.com/logging.js": null,
"favicon.co.uk/stat": null,
"fc2.com/counter.php": null,
"fc2.com/counter_img.php": null,
"fccbrea.org/javascript/stats.js": null,
"filmlinks4u.net/twatch/jslogger.php": null,
"financeglobe.com/Visit": null,
"flickr.com/beacon_client_api_timings.gne": null,
"flickr.com/beacon_page_timings.gne": null,
"flipkart.com/bbeacon.php": null,
"flixist.com/img2.phtml": null,
"flybmi.com/livetrack": null,
"fncstatic.com/static/all/js/geo.js": null,
"foodnavigator.com/tracker": null,
"fool.com/tracking": null,
"forbesimg.com/assets/js/forbes/fast_pixel.js": null,
"ford.com/ngtemplates/ngassets/com/forddirect/ng/newMetrics.js": null,
"ford.com/ngtemplates/ngassets/ford/general/scripts/js/galleryMetrics.js": null,
"foxadd.com/addon/upixel": null,
"foxtel.com.au/cms/fragments/corp_analytics": null,
"freaksofcock.com/track": null,
"free-tv-video-online.me/resources/js/counter.js": null,
"freean.us/track": null,
"freebiesms.com/tracker.aspx": null,
"fujifilm.com/js/shared/analyzer.js": null,
"furk.net/counter.yadro.ru": null,
"galleries.bz/track": null,
"gamefront.com/wp-content/plugins/tracker": null,
"gamerdeals.net/aggbug.aspx": null,
"gamesgames.com/WebAnalysis": null,
"gamespot.com/cgi/chkpt.php": null,
"geico.com/vs/track2.js": null,
"giganews.com/images/rpp.gif": null,
"gigya.com/js/gigyaGAIntegration.js": null,
"globes.co.il/shared/s.ashx": null,
"go.com/stat": null,
"godaddy.com/image.aspx": null,
"godaddy.com/pageevents.aspx": null,
"googlelabs.com/log": null,
"gosanangelo.com/metrics": null,
"groupon.com/analytic": null,
"hanksgalleries.com/stxt/counter.php": null,
"haxx.ly/counter": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"helium.com/javascripts/helium-beacons.js": null,
"heraldtimesonline.com/js/tk.js": null,
"heroku.com/track.js": null,
"herold.at/images/stathbd.gif": null,
"higheredjobs.com/ClickThru": null,
"honda.ca/_Global/js/includes/tracker.js": null,
"hoseasons.co.uk/tracking/js.html": null,
"hostelbookers.com/track/request": null,
"hostels.com/includes/lb.php": null,
"hostels.com/includes/thing.php": null,
"hothardware.com/stats": null,
"hotnews.ro/pageCount.htm": null,
"howcast.com/images/h.gif": null,
"howtogeek.com/public/stats.php": null,
"hrblock.com/includes/pixel": null,
"huffingtonpost.com/geopromo": null,
"huffingtonpost.com/include/geopromo.php": null,
"huffingtonpost.com/traffic": null,
"hulkshare.com/ajax/tracker.php": null,
"hulkshare.com/stats.php": null,
"hulu.com/beaconservice.swf": null,
"hulu.com/google_conversion_video_view_tracking.html": null,
"hwscdn.com/analytics.js": null,
"i-am-bored.com/cad.asp": null,
"i.walmartimages.com/i/icon": null,
"iafrica.com/php-bin/iac/readcnt.php": null,
"ibm.com/common/stats": null,
"ibtimes.com/player/stats.swf": null,
"icq.com/search/js/stats.js": null,
"ign.com/global/analytics/drones.js": null,
"iheart.com/tracking": null,
"image.providesupport.com/cmd": null,
"images.military.com/pixel.gif": null,
"imgur.com/albumview.gif": null,
"imgur.com/imageview.gif": null,
"imgur.com/lumbar.gif": null,
"independentmail.com/metrics": null,
"infogr.am/js/metrics.js": null,
"infomine.com/imcounter.js": null,
"infoq.com/scripts/tracker.js": null,
"infusionextreme.com/tracker": null,
"ino.com/img/sites/mkt/click.gif": null,
"intensedebate.com/empty.php": null,
"intercom.io/gtm_tracking": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"ipetitions.com/img.php": null,
"irs.gov/js/irs_reporting_cookie.js": null,
"ixs1.net/s": null,
"jakpost.net/jptracker": null,
"javhd.com/click": null,
"jetsetter.com/tracker.php": null,
"jeuxjeux2.com/stats.php": null,
"jobthread.com/js/t.js": null,
"jobthread.com/t": null,
"joins.com/hc.aspx": null,
"kickass.cd/analytics.js": null,
"kitsapsun.com/metrics": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"kloth.net/images/pixel.gif": null,
"knoxnews.com/metrics": null,
"kyte.tv/flash/MarbachMetricsOmniture.swf": null,
"kyte.tv/flash/MarbachMetricsProvider.swf": null,
"lancasteronline.com/javascript/ga.php": null,
"landrover.com/system/logging": null,
"latimes.com/images/pixel.gif": null,
"legalmatch.com/scripts/lmtracker.js": null,
"lendingtree.com/javascript/tracking.js": null,
"letitbit.net/atercattus/letitbit/counter": null,
"letitbit.net/counter": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"life.com/sm-stat": null,
"link.codeyear.com/img": null,
"linkbucks.com/track": null,
"linkedin.com/analytics": null,
"lipsy.co.uk/_assets/images/skin/tracking": null,
"livedoor.com/counter": null,
"livejournal.com/ljcounter": null,
"livestrong.com/services/jslogging": null,
"livesupport.zol.co.zw/image_tracker.php": null,
"log.player.cntv.cn/stat.html": null,
"logmein.com/scripts/Tracking": null,
"lolbin.net/stats.php": null,
"lovefilm.com/api/ioko/log": null,
"lovefilm.com/lovefilm/images/dot.gif": null,
"luxurylink.com/t/hpr.php": null,
"mail.advantagebusinessmedia.com/open.aspx": null,
"matchesfashion.com/js/Track.js": null,
"mayoclinic.org/js/tracker.js": null,
"mealime.com/assets/mealytics.js": null,
"meduza.io/stat": null,
"mercent.com/js/tracker.js": null,
"merchantcircle.com/static/track.js": null,
"merck.com/js/mercktracker.js": null,
"met-art.com/visit.js": null,
"metro.us/api/trackPage": null,
"metroweekly.com/tools/blog_add_visitor": null,
"mf2fm.com/php/stats.php": null,
"microsoft.com/blankpixel.gif": null,
"microsoft.com/click": null,
"microsoft.com/collect": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"microsoft.com/getsilverlight/scripts/Tracker.js": null,
"microsoft.com/library/svy": null,
"microsoft.com/LTS/default.aspx": null,
"miniurls.co/track": null,
"mod.uk/js/tracker.js": null,
"modernsalon.com/includes/sc_video_tracking.js": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"monkeyquest.com/monkeyquest/static/js/ga.js": null,
"mortgage101.com/tracking": null,
"mov-world.net/counter": null,
"mozilla.com/js/track.js": null,
"msn.com/ro.aspx": null,
"msn.com/tracker": null,
"multiply.com/common/dot_clear.gif": null,
"myanimelist.net/static/logging.html": null,
"myfitnesspal.com/assets/mfp_localytics.js": null,
"myspace.com/beacon": null,
"myspace.com/isf.gif": null,
"mytravel.co.uk/thomascooktrack.gif": null,
"nabble.com/static/analytics.js": null,
"naplesnews.com/metrics": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"nationalgeographic.com/stats/ax": null,
"nationalpayday.com/1pix.gif": null,
"naughtydog.com/beacon": null,
"naukrigulf.com/logger": null,
"ncsoft.com/tracker.js": null,
"net-a-porter.com/intl/trackpage.nap": null,
"netmag.co.uk/matchbox/traffic": null,
"netzero.net/account/event.do": null,
"news.cn/webdig.js": null,
"news.com.au/track": null,
"news.com.au/tracking": null,
"news9.com/beacon": null,
"newsarama.com/common/track.php": null,
"newsletter.mybboard.net/open.php": null,
"newstatesman.com/js/NewStatesmanSDC.js": null,
"nick.com/common/images/spacer.gif": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"nih.gov/share/scripts/survey.js": null,
"nike.com/cms/analytics-store-desktop.js": null,
"nj.com/cgi-bin/stats": null,
"nj.com/dhtml/stats": null,
"noip.com/images/em.php": null,
"nola.com/cgi-bin/stats": null,
"nola.com/dhtml/stats": null,
"nova.pub/track.php": null,
"nydailynews.com/tracker.js": null,
"nysun.com/tracker.js": null,
"nyt.com/js/mtr.js": null,
"nytimes.com/js/mtr.js": null,
"nzbsrus.com/tracker": null,
"offers.keynote.com/wt": null,
"ok.co.uk/tracking": null,
"olark.com/track": null,
"oodle.co.uk/event/track-first-view": null,
"oodle.com/js/suntracking.js": null,
"optimizely.com/js/geo.js": null,
"osalt.com/js/track.js": null,
"oscars.org/scripts/wt_include1.js": null,
"oscars.org/scripts/wt_include2.js": null,
"ostkcdn.com/js/p13n.js": null,
"pages03.net/WTS/event.jpeg": null,
"pajamasmedia.com/stats": null,
"papajohns.com/index_files/activityi.html": null,
"paper.li/javascripts/analytics.js": null,
"pardot.com/pd.js": null,
"paypal.com/webapps/beaconweb": null,
"pbsrc.com/common/pixel.png": null,
"pcp001.com/media/globalPixel.js": null,
"pepsi.com/js/pepsi_tracking.js": null,
"photobucket.com/ss/open.php": null,
"photobucket.com/track": null,
"picbucks.com/track": null,
"pixazza.com/track": null,
"play.com/analytics": null,
"play.com/sitetrak": null,
"playboy.com/libs/analytics": null,
"playlist.com/scripts/remote_logger.js": null,
"playserver1.com/analytics": null,
"playstation.com/beacon": null,
"plentyoffish.com/tracking.js": null,
"pokernews.com/track-views.php": null,
"porndoo.com/lib/ajax/track.php": null,
"presstv.ir/stat": null,
"pricegrabber.com/analytics.php": null,
"princetonreview.com/logging": null,
"projop.dnsalias.com/intranet-crm-tracking": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"ps-deals.com/aggbug.aspx": null,
"pubarticles.com/add_hits_by_user_click.php": null,
"puritan.com/images/pixels": null,
"qbn.com/media/static/js/ga.js": null,
"questionmarket.com/adsc": null,
"questionmarket.com/static": null,
"quickmeme.com/tracker": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"racingbase.com/tracking_fetchinfo.aspx": null,
"racinguk.com/images/home_sponsors": null,
"radio-canada.ca/lib/TrueSight/markerFile.gif": null,
"rakuten-static.com/com/rat": null,
"rambler.ru/cnt": null,
"razor.tv/site/servlet/tracker.jsp": null,
"reachlocal.com/js/tracklandingpage.js": null,
"realitytvworld.com/images/pixel.gif": null,
"recomendedsite.com/addon/upixel": null,
"redding.com/metrics": null,
"redtube.com/_status/pix.php": null,
"redtube.com/_status/pixa.php": null,
"redtube.com/js/track.js": null,
"redtube.com/pix.php": null,
"redtube.com/stats": null,
"reference.com/track": null,
"rent.com/track/visit": null,
"reporter-times.com/js/tk.js": null,
"reporternews.com/metrics": null,
"resellerclub.com/helpdesk/visitor/index.php": null,
"retrevo.com/m/vm/tracking": null,
"reuters.com/tracker": null,
"rightmove.co.uk/ps/images/logging/timer.gif": null,
"ringcentral.com/misc/se_track.asp": null,
"rismedia.com/tracking.js": null,
"rkdms.com/order.gif": null,
"rkdms.com/sid.gif": null,
"rottentomatoes.com/tracking": null,
"rte.ie/player/playertracker.js": null,
"rumble.com/l": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"s-msn.com/br/gbl/js/2/report.js": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"sabah.com.tr/Statistic": null,
"sabah.com.tr/StatisticImage": null,
"sabc.co.za/SABC/analytics": null,
"sap.com/global/ui/js/trackinghelper.js": null,
"sasontnwc.net/track": null,
"satellite-tv-guides.com/stat": null,
"sciencedaily.com/blank.htm": null,
"sciencedaily.com/cache.php": null,
"scoop.co.nz/images/pixel.gif": null,
"scribol.com/traffix-tracker.gif": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"scripts.snowball.com/scripts/images/pixy.gif": null,
"sdc.com/sdcdata.js": null,
"search.usa.gov/javascripts/stats.js": null,
"searchenginewatch.com/utils/article_track": null,
"seatgeek.com/tracker.gif": null,
"securepaynet.net/image.aspx": null,
"selfip.org/counter": null,
"sex-flow.com/js/error.js": null,
"sharecast.com/counter.php": null,
"shopautoweek.com/js/modules/tracker.js": null,
"shopify.com/track.js": null,
"shoplocal.com/dot_clear.gif": null,
"shopping.com/pixel": null,
"shopsubmit.co.uk/visitor.ashx": null,
"shoutcast.com/traffic": null,
"shvoong.com/images/spacer.gif": null,
"siberiantimes.com/counter": null,
"similarsites.com/sbbgate.aspx": null,
"sinaimg.cn/unipro/pub": null,
"singer22-static.com/stat": null,
"sitemeter.com/meter.asp": null,
"skypeassets.com/i/js/jquery/tracking.js": null,
"skyrock.net/img/pix.gif": null,
"skyrock.net/js/stats_blog.js": null,
"skyrock.net/stats": null,
"slack.com/clog/track": null,
"slacker.com/beacon/page": null,
"slashdot.org/images/js.gif": null,
"slashgear.com/stats": null,
"slide.com/tracker": null,
"smartname.com/scripts/cookies.js": null,
"snakesworld.com/cgi-bin/hitometer": null,
"socialcodedev.com/pixel": null,
"socialstreamingplayer.crystalmedianetworks.com/tracker": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"sofascore.com/geoip.js": null,
"soonnight.com/stats.htm": null,
"sourceforge.net/images/mlopen_post.html": null,
"sovereignbank.com/utils/track.asp": null,
"speakertext.com/analytics": null,
"spinback.com/spinback/event/impression": null,
"spinmedia.com/clarity.min.js": null,
"spinmediacdn.com/clarity.min.js": null,
"sporcle.com/adn/yaktrack.php": null,
"squidoo.com/track": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"staticlp.com/analytics": null,
"staticworld.net/pixel.gif": null,
"statravel.co.uk/static/uk_division_web_live/Javascript/wt_gets.js": null,
"stickpage.com/counter.php": null,
"storenvy.com/tracking": null,
"streetdirectory.com/tracking": null,
"streetfire.net/flash/trackingutility.swf": null,
"streetfire.net/handlers/logstreamfileimpression.ashx": null,
"stuff.co.nz/track": null,
"sublimevideo.net/_.gif": null,
"sugarvine.com/inc/tracking.asp": null,
"suite101.com/tracking": null,
"sun.com/share/metrics": null,
"surinenglish.com/acceso.php": null,
"sysomos.com/track": null,
"t.hulu.com/beacon": null,
"t3.com/js/trackers.js": null,
"tacobell.com/tb_files/js/tracker.js": null,
"targetspot.com/track": null,
"tarot.com/stats": null,
"tcpalm.com/metrics": null,
"tdwaterhouse.ca/includes/javascript/rtesurvey.js": null,
"tfl.gov.uk/tfl-global/scripts/stats-config.js": null,
"tfl.gov.uk/tfl-global/scripts/stats.js": null,
"theconversation.com/javascripts/lib/content_tracker_hook.js": null,
"thecreatorsproject.com/tracker.html": null,
"thefreedictionary.com/x/tp.ashx": null,
"thegameslist.com/wb/t.gif": null,
"thejc.com/metatraffic2": null,
"theolivepress.es/cdn-cgi/cl": null,
"thesaurus.com/track": null,
"theseforums.com/track": null,
"theweek.com/decor/track": null,
"tickco.com/track.js": null,
"tidaltv.com/Ping.aspx": null,
"timesrecordnews.com/metrics": null,
"tinypic.com/track.php": null,
"topix.com/t6track": null,
"torrentz.ph/ping": null,
"tottenhamhotspur.com/media/javascript/google": null,
"toyota.com/analytics": null,
"tracking.gfycat.com/viewCount": null,
"trade-it.co.uk/counter": null,
"trb.com/hive/swf/analytics.swf": null,
"trialpay.com/mi": null,
"tripadvisor.com/uvpages/page_moniker.html": null,
"trivago.com/tracking": null,
"trove.com/identity/public/visitor": null,
"trovus.co.uk/tracker": null,
"trowel.twitch.tv": null,
"truste.com/common/js/ga.js": null,
"tsn.ua/svc/video/stat": null,
"tubeplus.me/geoip.php": null,
"tubepornclassic.com/js/111.js": null,
"tubxporn.com/track.php": null,
"turn.com/js/module.tracking.js": null,
"turnsocial.com/track": null,
"tv-links.eu/qtt_spacer.gif": null,
"tvshark.com/stats.js": null,
"twitch.tv/track": null,
"twitter.com/scribes": null,
"twitvid.com/api/tracking.php": null,
"twitvid.com/mediaplayer/players/tracker.swf": null,
"u.tv/utvplayer/everywhere/tracking.aspx": null,
"ucoz.com/stat": null,
"ulogin.ru/stats.html": null,
"ultimedia.com/deliver/statistiques": null,
"unrulymedia.com/loader-analytics.html": null,
"upornia.com/js/0818.js": null,
"urbanlist.com/event/track-first-view": null,
"usps.com/survey": null,
"uts-rss.crystalmedianetworks.com/track.php": null,
"validome.org/valilogger/track.js": null,
"vator.tv/tracking": null,
"vbs.tv/tracker.html": null,
"vcstar.com/metrics": null,
"venere.com/common/js/track.js": null,
"victoriassecret.com/m/a.gif": null,
"video.msn.com/frauddetect.aspx": null,
"video.syfy.com/lg.php": null,
"videopremium.tv/dev/tr.js": null,
"villarenters.com/inttrack.aspx": null,
"viralnova.com/track.php": null,
"viralogy.com/javascript/viralogy_tracker.js": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"vixy.net/fb-traffic-pop.js": null,
"vmware.com/files/include/ga": null,
"vodpod.com/stats": null,
"vogue.co.uk/_/logic/statistics.js": null,
"voyeurhit.com/js/a2210.js": null,
"vzaar.com/libs/stats": null,
"walletpop.com/track": null,
"wallpaperstock.net/partners.js": null,
"washingtonpost.com/rw/sites/twpweb/js/init/init.track-header-1.0.0.js": null,
"washingtonpost.com/wp-stat/analytics": null,
"watch-series.to/analytics.html": null,
"wavescape.mobi/rest/track": null,
"wcnc.com/g/g/button": null,
"weather.com/pagelet/metrics": null,
"webcamgalore.com/aslog.js": null,
"webmonkey.com/js/stats": null,
"weeklyblitz.net/tracker.js": null,
"wellness.com/proxy.asp": null,
"wikio.com/shopping/tracking/hit.jsp": null,
"wikipedia.org/beacon": null,
"windowsphone.com/scripts/siteTracking.js": null,
"wired.com/ecom": null,
"wired.com/js/stats": null,
"wired.com/tracker.js": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"worldreviewer.com/_search/tracker.png": null,
"wovencube.com/track": null,
"wunderground.com/tag.php": null,
"wwe.com/sites/all/modules/wwe/wwe_analytics": null,
"xda-cdn.com/analytics.js": null,
"xhcdn.com/js/track.min.js": null,
"yahoo.com/_td_api/beacon": null,
"yahoo.com/beacon": null,
"yahoo.com/neo/ygbeacon": null,
"yahoo.com/perf.gif": null,
"yahoo.com/track": null,
"yellowpages.com/images/li.gif": null,
"yellowpages.com/proxy/envoy": null,
"yellowpages.com/proxy/turn_tags": null,
"younewstv.com/js/easyxdm.min.js": null,
"yourfilehost.com/counter.htm": null,
"youronlinechoices.com/activity": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"youtube-nocookie.com/robots.txt": null,
"yyv.co/track": null,
"zappos.com/onload.cgi": null,
"zawya.com/zscripts/ajaxztrack.cfm": null,
"zedo.com/img/bh.gif": null,
"zoomin.tv/impressions": null,
"zoomin.tv/impressionsplayers": null,
"zvents.com/partner_json": null,
"zytpirwai.net/track": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"expressen.se/static/scripts/s_code.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"lexus.com/lexus-share/js/tracking_omn/s_code.js": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"mercuryinsurance.com/static/js/s_code.js": null,
"michaelkors.com/common/js/extern/omniture/s_code.js": null,
"mnginteractive.com/live/omniture/sccore_NEW_JRC.js": null,
"navyfederal.org/js/s_code.js": null,
"nyteknik.se/ver02/javascript/2012_s_code_global.js": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"philly.com/includes/s_code.js": null,
"playstation.com/pscomauth/groups/public/documents/webasset/community_secured_s_code.js": null,
"sephora.com/javascripts/analytics/wa2.js": null,
"sltrib.com/csp/mediapool/sites/Shared/assets/csp/includes/omniture/SiteCatalystCode_H_17.js": null,
"vitacost.com/Javascripts/s_code.js": null,
"vmware.com/files/templates/inc/s_code_my.js": null,
"radio-canada.ca/omniture/omni_stats_base.js": null,
"watchseries.to/piwik.js": null };
var bad_da_hostpath_exact_flag = 4252 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 2002 rules:
var bad_da_hostpath_regex = `ad.*/jstag^
doubleclick.net/xbbe/creative/vast
04stream.com/pop*.js
advanced-intelligence.com/banner
akamai.net^*/pics.drugstore.com/prodimg/promo/
alexa.com^*/promotebuttons/
allposters.com^*/banners/
alluremedia.com.au^*/campaigns/
amazonaws.com^*/player_request_*/get_affiliate_
anonym.to/*findandtry.com
aol.co.uk^*/cobrand.js
aolcdn.com/os/music/img/*-skin.jpg
apnonline.com.au/img/marketplace/*_ct50x50.gif
arntrnassets.mediaspanonline.com^*_HP_wings_
berush.com/images/semrush_banner_
berush.com/images/whorush_120x120_
bijk.com^*/banners/
bitshare.com^*/banner/
blindferret.com/images/*_skin_
bosh.tv/hdplugin.
break.com^*/partnerpublish/
bullguard.com^*/banners/
buy.com^*/affiliate/
byzoo.org/script/tu*.js
camelmedia.net^*/banners/
cashmakingpowersites.com^*/banners/
catholicweb.com^*/banners/
centralmediaserver.com^*_side_bars.jpg
chriscasconi.com/nostalgia_ad.
clicksure.com/img/resources/banner_
cnhionline.com^*/rtj_ad.jpg
colorlabsproject.com^*/banner_
content.ad/Scripts/widget*.aspx
continent8.com^*/bannerflow/
coxnewsweb.com^*/ads/
creativecdn.com/creatives
d2kbaqwa2nt57l.cloudfront.net/br
dennis.co.uk^*/siteskins/
dev-cms.com^*/promobanners/
disqus.com/listPromoted
dreamstime.com/refbanner-
dynw.com/banner
ebaystatic.com/aw/signin/ebay-signin-toyota-
ebaystatic.com^*/motorswidgetsv2.swf
ebladestore.com^*/banners/
echineselearning.com^*/banner.jpg
edgecastcdn.net^*.barstoolsports.com/wp-content/banners/
esport-betting.com^*/betbanner/
extras.mnginteractive.com^*/todaysdeals.gif
facebook.com^*/instream/vast.xml
fantasyplayers.com/templates/banner_code.
fatburningfurnace.com^*/fbf-banner-
fileserver1.net/download
fncstatic.com^*/business-exchange.html
fortune5minutes.com^*/banner_
freecycle.org^*/sponsors/
frontpagemag.com^*/bigadgendabookad.jpg
frontsight.com^*/banners/
furiousteam.com^*/external_banner/
fyiwashtenaw.com/remote_widget
gamestop.com^*/aflbanners/
gemini.yahoo.com^*^syndication^
gmstatic.net^*/amazonbadge.png
gmstatic.net^*/itunesbadge.png
goadv.com^*/ads.js
googlesyndication.com^*/domainpark.cgi
googlesyndication.com^*/simgad/
gotraffic.net^*/sponsors/
haymarket-whistleout.s3.amazonaws.com/*_ad.html
hitleap.com/assets/banner-
hubbarddeals.com^*/promo/
hubbardradio.com^*/my_deals.php
i.lsimg.net^*/sides_clickable.
i.lsimg.net^*/takeover/
images-amazon.com/images/*/associates/widgets/
infomarine.gr^*/images/banners/
iselectmedia.com^*/banners/
iypcdn.com^*/bgbanners/
iypcdn.com^*/otherbanners/
iypcdn.com^*/ypbanners/
kaango.com/fecustomwidgetdisplay
keep2share.cc/images/i/00468x0060-
king.com^*/banners/
kurtgeiger.com^*/linkshare/
lastlocation.com/images/banner
leadsleap.com/images/banner_
lego.com^*/affiliate/
letmewatchthis.ru/movies/linkbottom
liutilities.com^*/affiliate/
llnwd.net/o28/assets/*-sponsored-
longtailvideo.com*/ltas.swf
longtailvideo.com^*/yume-h.swf
longtailvideo.com^*/yume.swf
lp.longtailvideo.com^*/adaptv*.swf
luckygunner.com^*/banners/
magicmembers.com/img/mgm-125x125
mb-hostservice.de/banner_
mdpcdn.com^*/gpt/
mediaspanonline.com^*-Takeover-
mediaspanonline.com^*-Takeover_
moneycontrol.co.in^*PopUnder.js
mosso.com^*/banners/
mrc.org/sites/default/files/uploads/images/Collusion_Banner
msnbcmedia.msn.com^*/sponsors/
multisitelive.com^*/banner_
multivizyon.tv^*/flysatbanner.swf
nanobrokers.com/img/banner_
nanoinvestgroup.com/images/banner*.gif
nesgamezone.com/syndicate
nettvplus.com/images/banner_
nocookie.net^*/wikiasearchads.js
nzpages.co.nz^*/banners/
onecache.com/banner_
oovoo.com^*/banners/
organicprospects.com^*/banners/
oriongadgets.com^*/banners/
osobnosti.cz/images/casharena_
ownx.com^*/banners/
pokersavvy.com^*/banners/
popeoftheplayers.eu/ad
pro-gmedia.com^*/skins/
radiotown.com/splash/images/*_960x600_
rapidgator.net/images/pics/*_300%D1%85250_
realwritingjobs.com^*/banners/
rethinkbar.azurewebsites.net^*/ieflyout.js
roshantv.com/adad.
s-assets.tp-cdn.com/widgets/*/vwid/*.html
sailthru.com^*/horizon.js
schenkelklopfer.org^*pop.js
secureserver.net^*/event
shaadi.com^*/get-banner.php
shaadi.com^*/get-html-banner.php
shop4tech.com^*/banner/
shorte.st^*/referral_banners/
simplifydigital.co.uk^*/widget_premium_bb.htm
site5.com/creative/*/234x60.gif
sitegrip.com^*/swagbucks-
speedbit.com^*-banner1-
speedppc.com^*/banners/
sponsorandwin.com/images/banner-
srwww1.com^*/affiliate/
static.multiplayuk.com/images/w/w-
staticworld.net/images/*_skin_
streamtheworld.com/ondemand/creative
structuredchannel.com/sw/swchannel/images/MarketingAssets/*/BannerAd
subliminalmp3s.com^*/banners/
supersport.com/content/2014_Sponsor
supersport.com/content/Sponsors
surf100sites.com/images/banner_
survivaltop50.com/wp-content/uploads/*/Survival215x150Link.png
swimg.net^*/banners/
talkfusion.com^*/banners/
thaiforlove.com/userfiles/affb-
themis-media.com^*/sponsorships/
tigerdirect.com^*/affiliate_
tmbattle.com/images/promo_
townnews.com^*/dealwidget.css
townnews.com^*/upickem-deals.js
tremormedia.com/embed/js/*_ads.js
tremormedia.com^*/tpacudeoplugin46.swf
tremormedia.com^*_preroll_
tribktla.files.wordpress.com/*-639x125-sponsorship.jpg
tribwgnam.files.wordpress.com^*reskin2.
turbotrafficsystem.com^*/banners/
turner.com^*/ads/
turner.com^*/promos/
twivert.com/external/banner234x60.
u-loader.com/image/hotspot_
ukrd.com/image/*-160x133.jpg
ukrd.com/image/*-160x160.png
ultimatewebtraffic.info/images/fbautocash
uniblue.com^*/affiliates/
usenetbucket.com^*-banner/
vpn4all.com^*/banner/
vpnxs.nl/images/vpnxs_banner
walmartimages.com^*/HealthPartner_
watch-free-movie-online.net/adds-
website.ws^*/banners/
worldcdn.net^*/banners/
xingcloud.com^*/uid_
xrad.io^*/hotspots/
yachting.org^*/banner/
yahoo.net^*/ads/
yimg.com/gemini/pr/video_
yimg.com^*/quickplay_maxwellhouse.png
yimg.com^*/sponsored.js
ynet.co.il^*/ynetbanneradmin/
ziffstatic.com/jst/zdsticky.
ziffstatic.com/jst/zdvtools.
193.34.134.18^*/banners/
193.34.134.74^*/banners/
213.174.140.76^*/ads/
79.120.183.166^*/banners/
91.83.237.41^*/banners/
blogspot.com^*/ad.jpg
cdn.epom.com^*/940_250.gif
ddstatic.com^*/banners/
ero-advertising.com^*/banners/
escortbook.com/banner_
hdpornphotos.com/images/728x180_
hdpornphotos.com/images/banner_
hentaijunkie.com^*/banners/
mofomedia.nl/pop-*.js
paydir.com/images/bnr
pop6.com/javascript/im_box-*.js
pornstarnetwork.com^*_660x70.jpg
saboom.com.pccdn.com^*/banner/
steadybucks.com^*/banners/
thumbs.vstreamcdn.com^*/slider.html
tubefck.com^*/adawe.swf
viorotica.com^*/banners/
vodconcepts.com^*/banners/
youfck.com^*/adawe.swf
100jamz.com^*-wallpaper-ad-
1023xlc.com/upload/*_background_
1043thefan.com^*_Sponsors/
1077thebone.com^*/banners/
1430wnav.com/images/300-
1430wnav.com/images/468-
22lottery.com/images/lm468
24hourwristbands.com/*.googleadservices.com/
2giga.link/jsx/download*.js
360haven.com/forums/*.advertising.com/
4fuckr.com/static/*-banner.
5min.com^*/banners/
911tabs.com/img/bgd_911tabs_
911tabs.com/img/takeover_app_
947.co.za^*-branding.
977rocks.com/images/300-
abduzeedo.com^*/mt-banner.jpg
aboutmyip.com/images/Ad0
abovetopsecret.com/160_
abovetopsecret.com/300_
abovetopsecret.com/728_
absolutcheats.com/images/changemy*.gif
absolutewrite.com^*_468x60banner.
absolutewrite.com^*_ad.jpg
activewin.com/images/*_ad.gif
activewin.com^*/blaze_static2.gif
adamvstheman.com/wp-content/uploads/*/AVTM_banner.jpg
adifferentleague.co.uk^*/mcad.png
adpost.com/bannerserver.g.
adsl2exchanges.com.au/images/spintel
adswikia.com^*banner
adswikia.com^*display300x250
advanced-television.com^*/banners/
adz.lk^*_ad.
affiliatesynergy.com^*/banner_
afloat.ie^*/banners/
africaonline.com.na^*/banners/
ahashare.com/cpxt_
allhiphop.com/site_resources/ui-images/*-conduit-banner.gif
allkpop.com^*/takeover/
allmovie.com^*/affiliate_
allmovieportal.com/dynbanner.
allmusic.com^*_affiliate_
allmyvideos.net/js/ad_
allmyvideos.net^*/pu.js
allthelyrics.com^*/popup.js
ambriefonline.com^*/banners/
amd.com/publishingimages/*/master_
americanfreepress.net/assets/images/Banner_
androidpolice.com/wp-content/*/images/das/
anilinkz.com/img/leftsponsors.
anilinkz.com/img/rightsponsors
anilinkz.tv/kwarta-
annistonstar.com/leaderboard_banner
anvisoft.com^*/anviad.jpg
appleinsider.com^*/ai_front_page_google_premium.js
aps.dz^*/banners/
arenabg.com^*/banners/
arenadb.net^*/banners/
armorgames.com/assets/*_skin_
armorgames.com/backup_
armorgames.com^*/banners/
armorgames.com^*/site-skins/
armorgames.com^*/siteskin.css
aroundosceola.com/banner-
arsenal-mania.com/images/backsplash_
arstechnica.net/public/shared/scripts/da-
askbobrankin.com/awpopup*.js
attitude.co.uk/images/Music_Ticket_Button_
audioz.download^*/partners/
autoworld.co.za^*/ads/
aviationweek.com^*/leader_board.htm
badongo.com^*_banner_
baixartv.com/img/bonsdescontos.
bbc.co.uk^*/bbccom.js
bcdb.com^*/banners.pl
beingpc.com^*/banners/
bellanaija.com^*/wp-banners/
benchmarkreviews.com^*/banners/
bestvpn.com/wp-content/uploads/*/mosttrustedname_260x300_
bitcoinist.net/wp-content/*/630x80-bitcoinist.gif
bitcoinist.net/wp-content/uploads/*_250x250_
bitcoinreviewer.com/wp-content/uploads/*/banner-luckybit.jpg
bitminter.com/images/info/spondoolies
bizarremag.com/images/skin_
blackchronicle.com/images/Banners-
blacklistednews.com/images/*banner
blbclassic.org/assets/images/*banners/
blogsmithmedia.com^*_skin.
blogsmithmedia.com^*_skin_
bloomberg.com^*/banner.js
bolandrugby.com/images/sponsors.
break.com^*/marketguide-
brecorder.com^*/banners/
breitlingsource.com/images/govberg*.jpg
brownfieldonline.com^*/banners/
bsvc.ebuddy.com/bannerservice/tabsaww
btdigg.org/images/btguard
bundesliga.com^*/_partner/
busiweek.com^*/banners/
bustocoach.com/*/banner_
bustocoach.com/*_banner/
buy-n-shoot.com/images/banners/banner-
buy.com/*/textlinks.aspx
bvibeacon.com^*/banners/
c-sharpcorner.com^*/banners/
caladvocate.com/images/banner-
calguns.net/images/ads
canalboat.co.uk^*/bannerImage.
canalboat.co.uk^*/Banners/
canindia.com^*_banner.png
cannabisjobs.us/wp-content/uploads/*/OCWeedReview.jpg
capitolfax.com/wp-content/*ad.
capitolfax.com/wp-content/*Ad_
cardsharing.info/wp-content/uploads/*/ALLS.jpg
carpoint.com.au^*/banner.gif
carsguide.com.au/images/uploads/*_bg.
cbfsms.com^*-banner.gif
ccfm.org.za^*/sads/
cd1025.com/www/img/btn-
cdcovers.cc/images/external/toolbar
cdmagurus.com/img/*.gif
cdn.turner.com^*/groupon/
ceforum.co.uk/images/misc/PartnerLinks
celebstoner.com/assets/images/img/sidebar/*/freedomleaf.png
ceoexpress.com/inc/ads
ceylontoday.lk^*/banner/
chinadaily.com.cn/s
chronicle.lu/images/Sponsor_
churchmilitant.com^*/ad-
churchnewssite.com^*-banner1.
churchnewssite.com^*/banner-
churchnewssite.com^*/bannercard-
ciao.com^*/price_link/
citationmachine.net/images/gr_
city1016.ae/wp-content/*-Skin_
citybeat.co.uk^*/ads/
citywire.co.uk/wealth-manager/marketingcampaign
citywirecontent.co.uk^*/cw.oas.dx.js
classic97.net^*/banner/
classicfeel.co.za^*/banners/
clubhyper.com/images/hannantsbanner_
cms.myspacecdn.com^*/splash_assets/
cnet.com/imp
cnettv.com.edgesuite.net^*/ads/
cnn.com/ad-
cnn.net^*/lawyers.com/
coastweek.com/banner_
cocomment.com/banner
coinwarz.com/content/images/genesis-mining-eth-takeover-
coloradomedicalmarijuana.com/images/sidebar/banner-
complaintsboard.com/img/banner-
complexmedianetwork.com^*/takeovers/
complexmedianetwork.com^*/toolbarlogo.png
computerandvideogames.com^*/promos/
constructionreviewonline.com^*730x90
constructionreviewonline.com^*banner
coolmath.net/*-medrect.html
coolsport.tv/adtadd.
coolsport.tv/lshadd.
copblock.org/wp-content/uploads/*/covert-handcuff-key-AD-
copdfoundation.org^*/images/sponsors/
cops.com^*/copbanner_
cphpost.dk^*/banners/
cricruns.com/images/hioxindia-
crunchyroll.*/vast
cruzine.com^*/banners/
cryptocoinsnews.com/wp-content/uploads/*/7281.gif
cryptocoinsnews.com/wp-content/uploads/*/728_
cryptocoinsnews.com/wp-content/uploads/*/ccn.png
cryptocoinsnews.com/wp-content/uploads/*/cloudbet_
cryptocoinsnews.com/wp-content/uploads/*/xbt-social.png
cryptocoinsnews.com/wp-content/uploads/*/xbt.jpg
cryptocoinsnews.com/wp-content/uploads/*_300x400_
crystalmedianetworks.com^*-180x150.jpg
csgobackpack.net/653x50.
custompcreview.com/wp-content/*-bg-banner.jpg
d-addicts.com^*/banner/
d.imwx.com/js/wx-a21-plugthis-
daily-mail.co.zm^*/sbt.gif
daily-mail.co.zm^*/side_strip.
daily-mail.co.zm^*/singapore_auto.
daily-mail.co.zm^*_1170x120.
daily-mail.co.zm^*_270x312.
daily-mail.co.zm^*_banner.
daily-sun.com^*/banner/
dailyblogtips.com/wp-content/uploads/*.gif
dailyherald.com^*/contextual.js
dailyhome.com/leaderboard_banner
dailymail.co.uk^*/promoboxes/
dailymirror.lk/media/images/Nawaloka-
dailynews.co.zw^*-takeover.
dailynews.gov.bw^*/banner_
dailynews.lk^*/webadz/
dailywritingtips.com^*/publisher2.gif
darknet.org.uk/images/acunetix_
davesite.com^*/aff/
ddccdn.com/js/google_
deccanchronicle.com^*-banner-
deccanchronicle.com^*-searchquad-300100.swf
deccanchronicle.com^*/shaadi.com/
deepdotweb.com/wp-content/uploads/*/allserviceslogo.gif
deepdotweb.com/wp-content/uploads/*/banner.gif
deepdotweb.com/wp-content/uploads/*/billpayhelp2.png
deepdotweb.com/wp-content/uploads/*/free_ross.jpg
deepdotweb.com/wp-content/uploads/*/helix.gif
defensereview.com^*_banner_
desiretoinspire.net^*/mgbanner.gif
detroitindependent.net/images/ad_
digitalreality.co.nz^*/360_hacks_banner.gif
digitaltveurope.net/wp-content/uploads/*_wallpaper_
digzip.com^*baner.swf
dippic.com/images/banner
dispatch.com^*/dpcpopunder.js
distrowatch.com^*-*.gif
distrowatch.com^*/3cx.png
distrowatch.com^*/advanced-admin.
dl4all.com^*/hotfile.gif
dnsstuff.com/dnsmedia/images/*_banner.jpg
dnsstuff.com/dnsmedia/images/ft.banner.
dogechain.info/content/img/a
dominicantoday.com^*/banners/
dota-trade.com/img/branding_
drivearchive.co.uk/images/amazon.
driverdb.com^*/banners/
drivereasy.com/wp-content/uploads/*/sidebar-DriverEasy-buy.jpg
dustcoin.com^*/image/ad-
dvdvideosoft.com^*/banners/
dwarfgames.com/pub/728_top.
earthlink.net^*/promos/
eastonline.eu/images/eng_banner_
ebaystatic.com/aw/pics/signin/*_signInSkin_
ebookshare.net^*/streamdirect160x600_
ebuddy.com/web_banners_
eco-business.com^*/site_partners/
economist.com.na^*/banners/
egamer.co.za^*-background-
ehow.com/media/ad.html^
elocallink.tv^*/showgif.php
environmental-finance.com^*banner
environmental-finance.com^*rotate.gif
epictv.com/sites/default/files/290x400_
eq2flames.com/images/styles/eq2/images/banner
esportlivescore.com/img/fano_
esportlivescore.com/img/fanobet_
esportlivescore.com/img/vitalbet.
essayinfo.com/img/125x125_
essayscam.org^*/ads.js
eteknix.com/wp-content/uploads/*skin
eteknix.com/wp-content/uploads/*Takeover
euphonik.dj/img/sponsors-
eurodict.com/images/banner_
european-rubber-journal.com/160x600px_
euroweb.com^*/banner/
eventful.com/tools/click/url
everythingsysadmin.com^*_sw_banner120x600_
eweek.com^*/sponsored-
exchangerates.org.uk/images/150_60_
exchangerates.org.uk/images/200x200_
expertreviews.co.uk^*/skins/
express.co.uk^*/sponsored/
ezmoviestv.com^*/ad-for-ezmovies.png
facenfacts.com^*/ads/
fastcompany.com/sites/*/interstitial.js
feed-the-beast.com^*/gamevox.png
feiwei.tv^*/sandbox.html
fever.fm^*/campaigns/
fhm.com^*_banner.png
file.org^*/images/promo/
fileflyer.com/img/dap_banner_
filerio.in^*/jquery.interstitial.
files.wordpress.com/*-reskin.
filespazz.com^*/copyartwork_side_banner.gif
financialsamurai.com/wp-content/uploads/*/sliced-alternative-10000.jpg
findthebest-sw.com/sponsor_event
finextra.com^*/leaderboards/
firingsquad.com^*/sponsor_row.gif
firsttoknow.com^*/page-criteo-
flameload.com/onvertise.
flatpanelshd.com/pictures/*banner
flopturnriver.com*/banners/
fncstatic.com^*/sponsored-by.gif
footballtradedirectory.com^*banner
forbbodiesonly.com*/vendorbanners/
foreignersinuk.co.uk^*/banner/
forumimg.ipmart.com/swf/ipmart_forum/banner
foxandhoundsdaily.com/wp-content/uploads/*-AD.gif
foxbusiness.com/html/google_homepage_promo
foxsoccer2go.com/namedImage/*/backgroundSkin.jpg
free-torrents.org^*/banners/
free-tv-video-online.me/episode-buttom-
free-tv-video-online.me/season-side-
freeroms.com/bigbox_
freeroms.com/skyscraper_
freetv-video.ca^*/popover-load-js.php
freeworldgroup.com/banner
ftlauderdalewebcam.com/images/*webcambanner
ftlauderdalewebcam.com^*-WebCamBannerFall_
fudzilla.com^*/banners/
fullrip.net/images/download-
fulltv.tv/pub_
gadgetshowlive.net^*/banners/
galatta.com^*/bannerimages/
galatta.com^*/banners/
gallerynova.se^*/jquery.bpopup.min.js
gallerysense.se/site/getBannerCode
gamblinginsider.com^*/partner_events.php
gamecopyworld.com^*/vg_160x120_
gameplanet.co.nz^*-takeover.jpg
gamersbook.com^*/banners/
gameserpent.com/kit*.php
gameserpent.com/vc*.php
gamesforwork.com^*/dropalink_small.gif
gameshark.com^*/pageskin-
gamingcentral.in^*/banner_
ganool.com/wp-content/uploads/*/Javtoys300250..gif
ganool.com/wp-content/uploads/*/matrix303.gif
gawkerassets.com^*/background.jpg
gelbooru.com*/frontend*.js
generalfiles.me^*/download_sponsored.
geocities.yahoo.*/js/sq.
gestetnerupdates.com^*/chesed-shel-emes-600x75.gif
gestetnerupdates.com^*/eagle-sewer.gif
gestetnerupdates.com^*/Gestetner-Miles.gif
gestetnerupdates.com^*/perfect-auto-collision_banner.gif
gethigh.com/wp-content/uploads/*/pass_a_drug_test_get_high_banner.jpg
getreading.co.uk/static/img/bg_takeover_
getthekick.eu^*/banners/
gfi.com/blog/wp-content/uploads/*-BlogBanner
girlsgames.biz/games/partner*.php
gizmochina.com^*/kingsing-t8-advert.jpg
glam.com^*/affiliate/
glamourviews.com/home/zones
go4up.com^*/download-buttoned.png
goal.com^*/branding/
gocdkeys.com/images/*_400x300_
gocdkeys.com/images/bg_
gold-prices.biz^*_400x300.gif
golf365.co.za^*/site-bg-
golf365.com^*/site-bg-
goodanime.net/images/crazy*.jpg
gopride.com^*/banners/
gov-auctions.org^*/banner/
gq.co.za^*/sitetakeover/
gr8.cc/addons/banners^
grapevine.is/media/flash/*.swf
greatandhra.com/images/*_ga_
gumtree.com^*/dart_wrapper_
gunfreezone.net^*_ad.jpg
guns.ru^*/banner/
guns.ru^*/banners/
hancinema.net/images/banner_
hancinema.net/images/watch-now
happierabroad.com/Images/banner
hardwareheaven.com/wp-content/*_skin_
hawaiireporter.com^*/upandruningy.jpg
hawaiireporter.com^*/winnerscampad.jpg
hd-bb.org^*/dl4fbanner.gif
hdtvtest.co.uk^*/pricerunner.php
healthfreedoms.org/assets/swf/320x320_
hearse.com^*/billboards/
heatworld.com/images/*_83x76_
helsinkitimes.fi^*/banners/
heraldm.com^*/banner/
heraldsun.com.au^*/images/sideskins-
heyjackass.com/wp-content/uploads/*_300x225_
hostratings.co.uk/zeepeel.
hotfile.com^*/banners/
hotfilesearch.com/includes/images/mov_
hothardware.com^*_staticbanner_*.jpg
howwe.biz/mgid-
howwemadeitinafrica.com^*/dhl-hdr.gif
hqfooty.tv/ad
hulkshare.com^*/adsmanager.js
hulkshare.oncdn.com^*/removeads.
hurriyetdailynews.com/images/*_100x250_
i-tech.com.au^*/banner/
i.i.com.com/cnwk.1d/*/tt_post_dl.jpg
i3investor.com^*/offer_
i3investor.com^*/partner/
icydk.com^*/title_visit_sponsors.
iddin.com/img/chatwing_banner.
iddin.com/img/chatwing_banner_
idesitv.com^*/loadbanners.
ifilm.com/website/*-skin-
iimg.in^*-banner-
iimg.in^*/sponsor_
iloveim.com/cadv
images-amazon.com/images/*/browser-scripts/da-
images-amazon.com/images/*/browser-scripts/dae-
images-amazon.com^*/marqueepushdown/
images.globes.co.il^*/fixedpromoright.
images.mmorpg.com/images/*skin
images.sharkscope.com/acr/*_Ad-
imageshack.us/images/contests/*/lp-bg.jpg
imagesnake.com^*/oc.js
imagevenue.com/interstitial.
imgburn.com/images/ddigest_
imgcarry.com^*/oc.js
impactradio.co.za^*/banners/
independent.co.uk^*/partners/
indianexpress.com^*/banner/
info.break.com^*/sponsors/
infoq.com^*/banners/
informationng.com^*-Leaderboard.
informe.com/img/banner_
inquirer.net/wp-content/themes/news/images/wallpaper_
insidebutlercounty.com/images/100-
insidebutlercounty.com/images/160-
insidebutlercounty.com/images/180-
insidebutlercounty.com/images/200-
insidebutlercounty.com/images/300-
insidebutlercounty.com/images/468-
inspirefirst.com^*/banners/
irctctourism.com/ttrs/railtourism/Designs/html/images/tourism_right_banners/*DealsBanner_
ironmagazine.com^*/banners.php
irv2.com/forums/*show_banner
isitdownrightnow.com/graphics/speedupmypc*.png
israelidiamond.co.il^*/bannerdisplay.aspx
itv.com/adexplore/*/config.xml
iwebtool.com^*/bannerview.php
ixquick.nl/graphics/banner_
jango.com/assets/promo/1600x1000-
javascript-coder.com^*/form-submit-larger.jpg
javascript-coder.com^*/make-form-without-coding.png
jdownloader.org^*/smbanner.png
jewishexponent.com^*/banners/
jewishnews.co.uk^*banner
jewishtribune.ca^*/banners/
johngaltfla.com/wordpress/wp-content/uploads/*/jmcs_specaialbanner.jpg
johngaltfla.com/wordpress/wp-content/uploads/*/TB2K_LOGO.jpg
jozikids.co.za/uploadimages/*_140x140_
jozikids.co.za/uploadimages/140x140_
justsomething.co/wp-content/uploads/*-250x250.
kansascity.com/images/touts/ds_
keenspot.com/images/headerbar-
keepvid.com/images/ilivid-
keepvid.com/images/winxdvd-
kentonline.co.uk/weatherimages/sponsor_
kexp.org^*/sponsor-
kexp.org^*/sponsoredby.
keygen-fm.ru/images/*.swf
kfog.com^*/banners/
kitco.com^*/banners/
kitguru.net/wp-content/uploads/*-Skin.
kjlhradio.com^*/banners/
klav1230am.com^*/banners/
knbr.com^*/banners/
knowfree.net^*/ezm125x125.gif
knssradio.com^*/banners/
kongregate.com/images/help_devs_*.png
krapps.com^*-banner-
ktradionetwork.com^*/banners/
lagacetanewspaper.com^*/banners/
laliga.es/img/patrocinadores-
lancasteronline.com^*/done_deal/
lawprofessorblogs.com/responsive-template/*advert.
lawprofessors.typepad.com/responsive-template/*advert.jpg
learn2crack.com/wp-content/*-336x280.jpg
letitbit.net/images/other/inst_forex_
lfcimages.com^*/partner-
lfcimages.com^*/sponsor-
lfgcomic.com/wp-content/uploads/*/PageSkin_
lifeinqueensland.com/images/156x183a_
linkis.com/index/ln-event
linksafe.info^*/mirror.png
lionsrugby.co.za^*/sponsors.
lmgtfy.com/s/images/ls_
localdirectories.com.au^*/bannerimages/
loleasy.com^*/adsmanager.js
londonstockexchange.com^*/fx.gif
luxury4play.com^*/ads/
macblurayplayer.com/image/amazon-
macintouch.com/images/amaz_
macintouch.com/images/owc_
maciverse.mangoco.netdna-cdn.com^*banner
macobserver.com^*/deal_brothers/
macworld.co.uk^*/textdeals/
mailinator.com/images/abine/leaderboard-
mailinator.com^*/clickbanner.jpg
majorgeeks.com/images/*_336x280.jpg
majorgeeks.com/images/download_sd_
majorgeeks.com^*/banners/
malaysiabay.org^*/creative.js
malaysiabay.org^*creatives.php
mangareader.net/images/800-x-100
mani-admin-plugin.com^*/banners/
manicapost.com^*/banners/
manxradio.com^*/banners_
marijuanapolitics.com/wp-content/*-ad.
marijuanapolitics.com/wp-content/uploads/*/icbc1.png
marijuanapolitics.com/wp-content/uploads/*/icbc2.png
marketingpilgrim.com/wp-content/uploads/*/trackur.com-
marketingupdate.co.za/temp/banner_
marketplace.org^*/support_block/
maxgames.com^*/sponsor_
maxkeiser.com^*-banner-
mcstatic.com^*/billboard_
media-imdb.com/images/*/mptv_banner_
media-imdb.com^*/affiliates/
media-imdb.com^*/zergnet-
media.abc.go.com^*/callouts/
mediafire.com^*/rockmelt_tabcontent.jpg
mediaupdate.co.za/temp/banner_
mediaweek.com.au/storage/*_234x234.jpg
meetic.com/js/*/site_under_
menafn.com^*/banner_
mensxp.com^*/banner/
merriam-webster.com^*/accipiter.js
messianictimes.com/images/1-13/ba_mhfinal_
metradar.ch^*/banner_
mfcdn.net/media/*left
mfcdn.net/media/*right
miamiherald.com^*/dealsaver/
miamiherald.com^*/teamfanshop/
mikejung.biz/images/*/728x90xLiquidWeb_
milanounited.co.za/images/sponsor_
mixfm.co.za/images/banner
mlb.com/images/*_videoskin_*.jpg
mmoculture.com/wp-content/uploads/*-background-
mmorpg.com/images/*_hots_r0.jpg
mmorpg.com/images/mr_ss_
monitor.co.ug/image/view/*/120/
monitor.co.ug/image/view/*/468/
morefree.net/wp-content/uploads/*/mauritanie.gif
movie2kto.ws/popup
mp3.li/images/md_banner_
mp3li.net^*banner
mp3skull.com/call_banner_exec_new.
msw.ms^*/jquery.MSWPagePeel-
muchmusic.com/images/*-skin.png
muchmusic.com^*/leaderboard_frame_obiwan.html
multiupload.biz/r_ads2
music.yahoo.com/get-free-html
musicmaza.com/bannerdyn
musicplayon.com/banner
mustangevolution.com/images/300x100_
mustangevolution.com^*/banner/
mustangevolution.com^*/banners/
muthafm.com^*/partners.png
mygaming.co.za^*/partners/
mymusic.com.ng/images/supportedby
mypbrand.com/wp-content/uploads/*banner
mypremium.tv^*/bpad.htm
myspacecdn.com/cms/*_skin_
mysubtitles.com^*_banner.jpg
naij.com^*/branding/
nation.lk^*/banners/
nation.sc/images/pub
nationalreview.com/images/display_300x600-
nationalturk.com^*/banner
nciku.com^*banner
ncrypt.in/images/banner
ndtv.com/widget/conv-tb
ndtv.com^*/banner/
neowin.net/images/atlas/aww
nesn.com/img/nesn-nation/bg-
netupd8.com^*/ads/
newoxfordreview.org/banners/ad-
news-leader.com^*/banner.js
news.com.au^*/images/*-bg.jpg
newsbusters.org^*/banners/
newscdn.com.au^*/aldi/
newsonjapan.com^*/banner/
nextbigwhat.com/wp-content/uploads/*ccavenue
nfl.com/assets/images/hp-poweredby-
nfl.com^*/page-background-image.jpg
nichepursuits.com/wp-content/uploads/*/long-tail-pro-banner.gif
nigeriafootball.com/img/affiliate_
nmimg.net/css/takeover_
nosteam.ro^*/gamedvprop.js
notalwaysromantic.com/images/banner-
notdoppler.com^*-promo-siteskin.
notebook-driver.com/wp-content/images/banner_
nu2.nu^*_banner.
nufc.com^*/The%20Gate_NUFC.com%20banner_%2016.8.13.gif
nydailynews.com^*-reskin-
oanda.com/wandacache/wf-banner-
omgpop.com/dc
oncyprus.com^*/banners/
one-delivery.co.uk^*/sensitivedating.png
onlinekeystore.com/skin1/images/side-
opednews.com^*/iframe.php
opencurrency.com/wp-content/uploads/*-aocs-sidebar-commodity-bank.png
optimum.net/utilities/doubleclicktargeting
originalweedrecipes.com/wp-content/uploads/*-Medium.jpg
orissadiary.com/img/*-banner.gif
oteupload.com/images/iLivid-download-
outlookindia.com/image/banner_
ozqul.com^*/webbanners.png
pagesinventory.com/_data/img/*_125x400_
paktribune.com^*/banner
pandora.com^*/mediaserverPublicRedirect.jsp
paris-update.com^*/banners/
pcpro.co.uk/images/*_siteskin
pcpro.co.uk^*/pcprositeskin
pcworld.co.nz^*_siteskin_
pcworld.com/images/*_vidmod_316x202_
pe.com^*/biice2scripts.js
pechextreme.com^*/banner.
pechextreme.com^*/banners/
petri.co.il/wp-content/uploads/banner1000x75_
petri.co.il/wp-content/uploads/banner700x475_
pettube.com/images/*-partner.
pgatour.com^*/featurebillboard_
phantom.ie^*/banners/
phnompenhpost.com^*/banner_
photo.net/equipment/pg-160^
phuketgazette.net^*/banners/
pitchero.com^*/toolstation.gif
planetradiocity.com^*banner
playgames2.com/ban300-
pleasurizemusic.com^*/banner/
pocket-lint.com/images/bytemarkad.
pocketnow.com*/embeded-adtional-content/
pogo.com/v/*/js/ad.js
policeprofessional.com/files/banners-
policeprofessional.com/files/pictures-
politicalwire.com/images/*-sponsor.jpg
pons.eu^*/lingeniobanner.swf
pornevo.com/events_
portcanaveralwebcam.com/images/ad_
portevergladeswebcam.com^*-Ad.jpg
portevergladeswebcam.com^*-WebCamBannerFall_
portmiamiwebcam.com/images/sling_
positivehealth.com^*/TopicbannerAvatar/
poststar.com^*/dealwidget.php
power1035fm.com^*/banners/
powerbot.org^*/ads/
pqarchiver.com^*/utilstextlinksxml.js
preppersmallbiz.com/wp-content/uploads/*/PSB-Support.jpg
prepperwebsite.com/wp-content/uploads/*-250x250.jpg
prepperwebsite.com/wp-content/uploads/*/250x250-
prepperwebsite.com/wp-content/uploads/*/apmgoldmembership250x250.jpg
prepperwebsite.com/wp-content/uploads/*/DeadwoodStove-PW.gif
prepperwebsite.com/wp-content/uploads/*/FME-Red-CAP.jpg
prepperwebsite.com/wp-content/uploads/*/jihad.jpg
prepperwebsite.com/wp-content/uploads/*/PW-Ad.jpg
prepperwebsite.com/wp-content/uploads/*/tsepulveda-1.jpg
prepperwebsite.com/wp-content/uploads/*_250x150.png
prepperwebsite.com/wp-content/uploads/*_250x250.jpg
primewire.ag/js/jquery*.js
prisonplanet.com^*banner
privateproperty.co.za^*/siteTakeover/
professionalmuscle.com/*banner
profitconfidential.com/wp-content/themes/PC-child-new/images/*_banners_
profitconfidential.com/you-may-also-like
propakistani.pk/wp-content/*/warid.jpg
proxy-youtube.net/mih_
proxy-youtube.net/myiphide_
publicityupdate.co.za/temp/banner_
publicradio.org^*/banners/
punch.cdn.ng^*/wp-banners/
punchng.com^*/wp-banners/
putlocker.is/images/banner
qiksilver.net^*/banners/
qualityhealth.com^*/banner.jsp
quickmeme.com/media/rostile
race-dezert.com/images/wrap-
racinguk.com/images/site/foot_
racketboy.com/images/racketboy_ad_
radioreference.com^*_banner_
rapidfiledownload.com^*/btn-input-download.png
rapidlibrary.com/baner*.png
rapidlibrary.com/banner_*.png
rapidtvnews.com^*BannerAd.
ratemystrain.com/files/*-300x250.
rawstory.com^*/ads/
raysindex.com/wp-content/uploads/*/dolmansept2012flash.swf
rc.feedsportal.com/r/*/rc.img
readynutrition.com^*/banners/
redpepper.org.uk/ad-
regmender.com^*/banner336x280.
rejournal.com^*/images/homepage/
replacementdocs.com^*/popup.js
reuters.com/reuters_gpt_bootstrap*.js
rghost.ru/download/a/*/banner_download_
ringostrack.com^*/amazon-buy.gif
robhasawebsite.com^*/amazon-
robhasawebsite.com^*/shop-amazon.
rocksound.tv/images/uploads/*-rocksound-1920x1000_
rocktelevision.com^*_banner_
rockthebells.net/images/bot_banner_
roseindia.net^*/banners/
rpgwatch.com^*/banner/
rtklive.com^*/marketing
rugbyweek.com^*/sponsors/
s.imwx.com^*/wx-a21-plugthis.js
s.yimg.com^*/audience/
saabsunited.com/wp-content/uploads/*-banner-
saabsunited.com/wp-content/uploads/*-banner.
saabsunited.com/wp-content/uploads/*_banner_
saabsunited.com/wp-content/uploads/180x460_
saabsunited.com/wp-content/uploads/ban-
saabsunited.com/wp-content/uploads/werbung-
saf.org/wp-content/uploads/*/theGunMagbanner.png
saf.org/wp-content/uploads/*/women_guns192x50.png
samoaobserver.ws^*/banner/
samoatimes.co.nz^*/banner468x60/
sarugbymag.co.za^*-wallpaper2.
satopsites.com^*/banners/
sawlive.tv/ad
saysuncle.com^*ad.jpg
seatguru.com/deals
secureupload.eu/images/soundcloud_
secureupload.eu/images/wpman_
sexmummy.com/avnadsbanner.
sfbaytimes.com/img-cont/banners
sgtreport.com/wp-content/uploads/*-180x350.
sgtreport.com/wp-content/uploads/*/180_350.
sgtreport.com/wp-content/uploads/*/180x350.
sgtreport.com/wp-content/uploads/*_Side_Banner.
sgtreport.com/wp-content/uploads/*_Side_Banner_
shadowpool.info/images/banner-
shanghaiexpat.com^*/wallpaper_
share-links.biz^*/hisp.gif
share-links.biz^*/hs.gif
sherdog.com/index/load-banner
shop.com/cc.class/dfp
shopping.stylelist.com/widget
shoutmeloud.com^*/hostgator-
showstreet.com/banner.
sify.com^*/gads_
silverdoctors.com^*/Silver-Shield-2015.jpg
siteslike.com/images/celeb
sk-gaming.com/image/takeover_
skymetweather.com^*/googleadds/
skyvalleychronicle.com/999/images/ban
slacker.com^*/ads.js
smartearningsecrets.com^*/FameThemes.png
smartmoney.net^*-sponsor-
snopes.com^*/casalebanner.asp
soccerway.com/buttons/120x90_
sockshare.com^*_728.php
someecards.com^*/images/skin/
soundcloud.com/audio-ad
soundtracklyrics.net^*_az.js
sourcefed.com/wp-content/uploads/*/netflix4.jpg
spartoo.eu/footer_tag_iframe_
speroforum.com/images/sponsor_
ssl-images-amazon.com/images/*/browser-scripts/da-
ssl-images-amazon.com^*/dacx/
stagnitomedia.com/view-banner-
startribune.com/circulars/advertiser_
static-economist.com^*/timekeeper-by-rolex-medium.png
static.nfl.com^*-background-
staticneo.com/neoassets/iframes/leaderboard_bottom.
staticworld.net/images/*_pcwskin_
strategypage.com^*_banner
stream2watch.co^*_ad_
stream2watch.me/ed
student-jobs.co.uk/banner.
stv.tv/img/player/stvplayer-sponsorstrip-
succeed.co.za^*/banner_
sulekha.com^*/bannerhelper.html
sulekha.com^*/sulekhabanner.aspx
suntimes.com^*/banners/
surfmusic.de/anz
surfmusic.de/banner
swimnews.com^*/banner_
sxc.hu/img/banner
taiwannews.com.tw/etn/images/banner_
tastro.org/x/ads*.php
taxsutra.com^*/banner/
tdfimg.com/go/*.html
techinsider.net/wp-content/uploads/*-300x500.
techradar.com^*/img/*_takeover_
techsupportforum.com^*/banners/
techtarget.com^*/leaderboard.html
techtree.com^*/jquery.catfish.js
teesupport.com/wp-content/themes/ts-blog/images/cp-
telegraphindia.com^*/banners/
telegraphindia.com^*/hoabanner.
templatesbox.com^*/banners/
theactivetimes.net^*/featured_partners/
theaquarian.com^*/banners/
theburningplatform.com/wp-content/uploads/*_180x150.gif
thecatholicuniverse.com^*-ad.
thecatholicuniverse.com^*-advert-
thecatholicuniverse.com^*-banner-
thecenturion.co.za^*/banners/
thechive.files.wordpress.com^*-wallpaper-
thecitizen.co.tz^*/banners/
thecommonsenseshow.com/siteupload/*/ad-iodine.jpg
thecommonsenseshow.com/siteupload/*/ad-nutritionrecharge.jpg
thecommonsenseshow.com/siteupload/*/ad-rangerbucket.jpg
thecommonsenseshow.com/siteupload/*/ad-survivalapril2017.jpg
thecommonsenseshow.com/siteupload/*/adamerigeddon2016dvd.jpg
thecommonsenseshow.com/siteupload/*/adnumana350x250-1.jpg
thecommonsenseshow.com/siteupload/*/adsqmetals.jpg
thecommonsenseshow.com/siteupload/*/hagmannbook.jpg
thecommonsenseshow.com/siteupload/*/nightvisionadnew.jpg
thecommonsenseshow.com/siteupload/*/numanna-hoiz400x100.jpg
thecommonsenseshow.com/siteupload/*/panama-300-x-250.jpg
thecommonsenseshow.com/siteupload/*/trekkerportablewater.jpg
thecompassionchronicles.com/wp-content/uploads/*-banner-
thecompassionchronicles.com/wp-content/uploads/*-banner.
thecsuite.co.uk^*/banners/
thedailymeal.com^*_sponsoredby.png
thedailymeal.net^*/featured_partners/
thedailypaul.com/images/amzn-
thedailystar.net^*/400-x-120-pixel.jpg
thedailystar.net^*/Animation-200-X-30.gif
thedailystar.net^*/aritel-logo.jpg
thedailystar.net^*/footer-sticky-add/
thedailystar.net^*/scbbd.gif
theenglishgarden.co.uk^*/bannerImage.
thehealthcareblog.com/files/*/American-Resident-Project-Logo-
thehealthcareblog.com/files/*/athena-300.jpg
thehealthcareblog.com/files/*/THCB-Validic-jpg-opt.jpg
thehighstreetweb.com^*/banners/
thehindu.com/multimedia/*/sivananda_sponsorch_
theindependentbd.com^*/banner/
thejointblog.com/wp-content/uploads/*-235x
thejointblog.com^*/dablab.gif
thelakewoodscoop.com^*banner
theleader.info/banner
theliberianjournal.com/flash/banner
themittani.com/sites/*-skin
thenationonlineng.net^*/banners/
thenonleaguefootballpaper.com^*/image-non-league.jpeg
thenonleaguefootballpaper.com^*/Lovell-Soccer.jpg
thepeninsulaqatar.com^*/banners/
thepreparednessreview.com/wp-content/uploads/*/250x125-
thepreparednessreview.com/wp-content/uploads/*_175x175.jpg
thepreparednessreview.com/wp-content/uploads/*_185x185.jpg
thesentinel.com^*/banners/
thessdreview.com/wp-content/uploads/*/930x64_
thessdreview.com^*-bg-banner-
thessdreview.com^*/owc-full-banner.jpg
thestandard.com.ph^*/banner/
thesundaily.my/sites/default/files/twinskyscrapers
thesurvivalistblog.net^*-banner-
thewindowsclub.com^*/banner_
thinkingwithportals.com/images/*-skyscraper.
thirdage.com^*_banner.php
time4hemp.com/wp-content/uploads/*-ad.
time4hemp.com/wp-content/uploads/*-vertical.
time4hemp.com/wp-content/uploads/*/cannafo.jpg
time4hemp.com/wp-content/uploads/*/dakine420.png
time4hemp.com/wp-content/uploads/*/dynamic_banner_
time4hemp.com/wp-content/uploads/*/gorillabanner728.gif
time4hemp.com/wp-content/uploads/*/herbies-1.gif
time4hemp.com/wp-content/uploads/*/Johnson-Grow-Lights.gif
time4hemp.com/wp-content/uploads/*/Judge-Lenny-001.jpg
time4hemp.com/wp-content/uploads/*/scrogger.gif
time4hemp.com/wp-content/uploads/*/sensi2.jpg
time4hemp.com/wp-content/uploads/*/WeedSeedShop.jpg
timesofoman.com^*/banner/
timestalks.com/images/sponsor-
tinyurl.com/firefox_banner_
tmz.vo.llnwd.net^*/images/*skin
toonova.com/images/site/front/xgift-
topalternate.com/assets/sponsored_links-
torrent.cd/images/banner-
torrentz.*/mgid/
toshiba.com^*/bookingpromowidget/
toshiba.com^*/toshibapromowidget/
totalguitar.net/images/*_125X125.jpg
toucharcade.com/wp-content/themes/*_background_*.jpg
townhall.com^*/ads/
trackitdown.net/skins/*_campaign/
tracksat.com^*/banners/
tripadvisor.com^*/skyscraper.jpg
trucknetuk.com^*/sponsors/
trucktrend.com^*_160x200_
trunews.com^*/Webbanner.jpg
trustedreviews.com/mobile/widgets/html/promoted-phones
tubehome.com/imgs/undressme
turboimagehost.com/300*.html^
turboimagehost.com/728*.html^
turboimagehost.com/b300.
turboimagehost.com/b300_
turboimagehost.com/b728.
turboimagehost.com/b728_
tvducky.com/imgs/graboid.
ukfindit.com/images/*_125x125.gif
ultimate-guitar.com/_img/bgd/bgd_main_
upload.ee/image/*/B_descarga_tipo12.gif
uploadcore.com/images/*-Lad.jpg
uploadcore.com/images/*-mad.jpg
uploadcore.com/images/*-Rad.png
uploadlw.com^*/download-now
uploadlw.com^*/download_button.gif
urbanchristiannews.com/ucn/sidebar-
urethanes-technology-international.com^*/banners/
urlcash.net/random*.php
urlgone.com^*/banners/
usatodayhss.com/images/*skin
uvnc.com/img/housecall.
vanityfair.com/custom/ebook-ad-bookbiz
vcdq.com^*/ad.html
verzing.com/popup
vfs-uk-in.com/images/webbanner-
vidds.net/pads*.js
video.abc.com^*/ads/
video44.net/gogo/a_d_s.
videogamer.com/videogamer*/skins/
videogamesblogger.com^*/scripts/takeover.js
videopediaworld.com/nuevo/plugins/midroll.
videos.com/click
videos.mediaite.com/decor/live/white_alpha_60.
videositeprofits.com^*/banner.jpg
videowood.tv/ads
videowood.tv/pop2
vidhog.com/images/download_banner_
vidvib.com/vidvibpopa.
vidvib.com/vidvibpopb.
vipbox.tv/js/layer-
virginislandsthisweek.com/images/336-
virginislandsthisweek.com/images/728-
virtual-hideout.net/banner
vitalfootball.co.uk^*/partners/
vitalmtb.com/assets/ablock-
vitalmtb.com/assets/vital.aba-
vondroid.com/site-img/*-adv-ex-
walshfreedom.com^*-300x250.
walshfreedom.com^*/liberty-luxury.png
wardsauto.com^*/pm_doubleclick/
washtimes.com/js/dart.
watchcartoononline.com/inc/siteskin.
watchcartoononline.com^*/530x90.
watchuseek.com/media/*-banner-
watchuseek.com/media/*_250x250
watchuseek.com/media/1900x220_
watchuseek.com/media/banner_
watchwwelive.net^*/big_ban.gif
watchwwelive.net^*/long_ban2.jpg
waterford-today.ie^*/banners/
wavelengthcalculator.com/banner
way2sms.com/w2sv5/js/fo_
wbgo.org^*/banners/
wearetennis.com/img/common/bnp-logo-
wearetennis.com/img/common/logo_bnp_
webmastercrunch.com^*/hostgator300x30.gif
webnewswire.com/images/banner
weei.com^*_banner.jpg
weekendpost.co.bw^*/banner_
werlv.com^*banner
whatismyip.com/images/vyprvpn_
whatmyip.co/images/speedcoin_
whatsnewonnetflix.com/assets/blockless-ad-
whispersinthecorridors.com/banner
whistleout.com.au/imagelibrary/ads/wo_skin_
whoer.net/images/vlab50_
whoer.net/images/vpnlab20_
wikinvest.com/wikinvest/images/zap_trade_
wildtangent.com/leaderboard
windowsitpro.com^*/roadblock.
winpcap.org/assets/image/banner_
winsupersite.com^*/roadblock.
wipfilms.net^*/amazon.png
wipfilms.net^*/instant-video.png
wired.com/images/xrail/*/samsung_layar_
wjunction.com/images/468x60
wjunction.com/images/rectangle
worthofweb.com/images/wow-ad-
wp.com/wp-content/themes/vip/tctechcrunch/images/tc_*_skin.jpg
wpdaddy.com^*/banners/
wrc.com/img/sponsors-
wrko.com/sites/wrko.com/files/poll/*_285x95.jpg
wunderground.com^*/wuss_300ad2.php
xboxgaming.co.za^*/images/background/
yahoo.com/contextual-shortcuts
yahoo.com^*/eyc-themis
yamivideo.com^*/download_video.jpg
yarisworld.com^*/banners/
yasni.*/design/relaunch/gfx/elitepartner_
yimg.com/cv/*/billboard/
yimg.com/cv/*/config-object-html5billboardfloatexp.js
yimg.com^*/flash/promotions/
yimg.com^*/yad.html
ynaija.com^*/ad.
youconvertit.com/_images/*ad.png
yourepeat.com/revive_wrapper
yourepeat.com^*/skins/
yourmovies.com.au^*/side_panels_
youtube.com/get_midroll_info
yp.mo^*/ads/
yudu.com^*_intro_ads
zanews.co.za^*/banners/
zap2it.com/wp-content/themes/overmind/js/zcode-
zbc.co.zw^*/banners/
zigzag.co.za/images/oww-
zombiegamer.co.za/wp-content/uploads/*-skin-
zootoday.com/pub/21publish/Zoo-navtop-casino_
zoover.*/shared/bannerpages/darttagsbanner.aspx
zophar.net/files/tf_
hindustantimes.com/res/js/ht-script
nintendolife.com^*/adblock.jpg
techweb.com/adblocktrack
ytconv.net/site/adblock_detect
3xupdate.com^*/ryushare.gif
3xupdate.com^*/ryushare2.gif
3xupdate.com^*/ryusharepremium.gif
adult-profit-files.com/banner
alotporn.com^*/js/oopopw.js
amadorastube.com^*/banner_
amateur-desire.com/pics/sm_
amateur-streams.com^*/popup.js
andtube.com/ban_
arionmovies.com/*/popup.php
babepicture.co.uk^*banner
babeshows.co.uk^*banner
badjojo.com/js/scripts-
bangyoulater.com/images/banners_
befuck.com/js/adpbefuck
between-legs.com^*/banners/
bigxvideos.com/js/focus.*.js
bigxvideos.com/js/pops2.
bigxvideos.com/js/popu.
bralesscelebs.com/*banner
cameltoe.com^*/banners/
celeb.gate.cc/misc/event_*.js
celebritypink.com/bannedcelebs-
coolmovs.com/js/focus.*.js
creepshots.com^*/250x250_
damimage.com^*/DocaWedrOJPPx.png
data18.com^*/banners/
drtuber.com^*/aff_banner.swf
dusttube.com/pop*.js
empireamateurs.com/images/*banner
eporner.com/pjsall-*.js
eroprofile.com/js/pu*.js
extremetube.com/player_related
fapdick.com/uploads/1fap_
fapdick.com/uploads/fap_
fileshare.ro^*/dhtmlwindow.js
fleshbot.com/wp-content/themes/fbdesktop_aff/images/af
freebunker.com^*/ex.js
freebunker.com^*/exa.js
freebunker.com^*/layer.js
freebunker.com^*/oc.js
freebunker.com^*/pops.js
freebunker.com^*/raw.js
freeporninhd.com/images/cbside.
freeporninhd.com/images/cbzide.
fux.com/assets/adblock
gayporntimes.com^*/Bel-Ami-Mick-Lovell-July-2012.jpeg
gayporntimes.com^*/CockyBoys-July-2012.jpg
girlfriendvideos.com/ad
girlsfromprague.eu^*468x
gspcdn.com^*/banners/
hcomicbook.com^*_banner1.gif
hdporn.in/js/focus.*.js
hdporn.in/js/pops2.
hentai-foundry.com/themes/*Banner
hentaistream.com/wp-includes/images/bg-
hentaistream.com/wp-includes/images/mofos/webcams_
heraldnetdailydeal.com/widgets/DailyDealWidget300x250
hgimg.com/js/beacon.
hidefporn.ws/client
hollyscoop.com/sites/*/skins/
hollywoodoops.com/img/*banner
hotdevonmichaels.com^*/pf_640x1001.jpg
hotdevonmichaels.com^*/streamate2.jpg
hotdevonmichaels.com^*/wicked.gif
hotdylanryder.com^*/Big-Tits-Like-Big-Dicks.jpg
hotdylanryder.com^*/dylan_350x250_01.jpg
hotdylanryder.com^*/iframes_174.jpg
hotdylanryder.com^*/pf_640x100.jpg
hotdylanryder.com^*/wicked.gif
hotkellymadison.com^*/kelly1.jpg
hotkellymadison.com^*/kelly4.jpg
hotkellymadison.com^*/km_300x300.gif
hotkellymadison.com^*/pf_640x100.jpg
hotsashagrey.com^*/Anabolic.jpg
hotsashagrey.com^*/New_Sensations-1091.gif
hotsashagrey.com^*/PeterNorth-800x350.jpg
hotsashagrey.com^*/squ-fantasygirlsasha-001.gif
hotsashagrey.com^*/throated.jpg
hotshame.com/js/adphotshame
imagecarry.com/down
imagecarry.com/top
imagedunk.com^*_imagedunk.js
imagefruit.com^*/pops.js
imageshack.us^*/bannng.jpg
imagetwist.com/imagetwist*.js
imgbabes.com^*/splash.php
imgflare.com^*/splash.php
indexxx.com^*/banners/
intporn.com^*/21s.js
intporn.com^*/asma.js
iseekgirls.com/rotating_
iseekgirls.com^*/banners/
kaotic.com^*/popnew.js
kyte.tv/flash/MarbachAdvertsDartInstream.
monstertube.com/images/access_
monstertube.com/images/vjoin.
monstertube.com/images/vjoin_
morazzia.com^*/banners/
mp3musicengine.com/bearshare_logo.
mp3musicengine.com/images/freewatchtv1.
myhentai.tv/popsstuff.
niceyoungteens.com/ero-advertising
ns4w.org/images/vod_
nudevista.com/_/exo_
nudevista.com/_/pp.
nudevista.com/_/teasernet
nudevista.com^*/nv-com.min.js
oasisactive.com^*/oasis-widget.html
onhercam.tv^*/banners/
openjavascript.com/jtools/jads.
pastime.biz^*/personalad*.jpg
phncdn.com/iframe
phncdn.com/images/*_skin.
phncdn.com/images/*_skin_
phncdn.com/images/premium_
picp2.com/img/putv
picsexhub.com/js/pops.
picsexhub.com/js/pops2.
picxme.com/js/pops.
pimpandhost.com/static/i/*-pah.jpg
pink-o-rama.com/Blazingbucks
pink-o-rama.com/Brothersincash
pink-o-rama.com/Fuckyou
pink-o-rama.com/Karups
pink-o-rama.com/Nscash
pink-o-rama.com/Privatecash
pixhost.org/image/tmp/linksnappy_
pnet.co.za/jobsearch_iframe_
poguide.com/cdn/images/ad*.gif
porn.com/assets/partner_
porn4down.com^*/ryuvuong.gif
pornalized.com/pornalized_html/closetoplay_
pornarchive.net/images/cb
pornbb.org/adsnov.
pornbb.org/images/your_privacy
pornbraze.com^*/popupbraze.js
pornfanplace.com/js/pops.
pornmade.com/images/cb
pornmaturetube.com/show_adv.
pornoid.com/iframes/bottom
pornoid.com/js/adppornoid
pornomovies.com/js/1/login_bonus
pornorips.com^*/rda.js
pornorips.com^*/rotate*.php
pornper.com^*/pp.js
pornsharia.com^*/adppornsharia.js
pornsharia.com^*/exo-
pornsharia.com^*/js/pcin.js
pornsharing.com/App_Themes/pornsharianew/js/adppornsharia*.js
pornsharing.com/App_Themes/pornsharingnew/js/adppornsharia*.js
pornstarterritory.com^*/alsbanner
pornxs.com/js/files/jasminNew
purelynsfw.com^*/banners/
purepornvids.com/randomadseb.
purpleporno.com/pop*.js
pwpwpoker.com/images/*/strip_poker_
queermenow.net/blog/wp-content/uploads/*-Banner
queermenow.net/blog/wp-content/uploads/*/banner
redtube.com^*/banner/
redtubefiles.com^*/banner/
redtubefiles.com^*/skins/
russiasexygirls.com/wp-content/uploads/*/727x90
russiasexygirls.com/wp-content/uploads/*/cb_
sex-techniques-and-positions.com/banners
sex.com/images/*/banner_
sexpornimg.com/css/images/banner
sexseeimage.com^*/banner.gif
sexuhot.com/images/xbanner
sexvines.co/images/cp
sexyandfunny.com/images/totem
sillusions.ws^*/pr0pop.js
sillusions.ws^*/vpn-banner.gif
socaseiras.com.br/banner_
static.flabber.net^*background
t-51.com^*/banners/
tabletporn.com/images/pinkvisualpad-
the-analist.info^*150-150
the-analist.info^*150sq
the-analist.info^*150x150
the-feeding-tube.com^*/Topbanner.php
thehun.net^*/banners/
thenewporn.com/js/adpthenewporn
thepornomatrix.com/images/1-
twofuckers.com/brazzers
uflash.tv^*/affiliates/
updatetube.com/js/adpupdatetube
videos.com^*/jsp.js
vidgrab.net/images/adsbar
viralporn.com^*/popnew.js
vrsmash.com^*/script.min.js
vstreamcdn.com^*/ads/
watch8x.com/JS/rhpop_
whozacunt.com/images/*-300x250.
whozacunt.com/images/*_300x200_
whozacunt.com/images/banner_
x3xtube.com/banner_rotating_
xcritic.com/images/buy-
xcritic.com/images/rent-
xcritic.com/images/watch-
xcritic.com/img/200x150_
xfanz.com^*_banner_
xhcdn.com^*/ads_
xxvideo.us/ad728x15
xxxblink.com/js/pops.
xxxfile.net^*/netload_premium.gif
xxxgames.biz^*/sponsors/
youaresogay.com/*.html
yumymilf.com^*/banners/
yuvutu.com^*/banners/
adclear.*/acc
b.*/click
click.*/open.aspx
email.*/blankpixel.gif
gdyn.*/1.gif
tracking.*/beacon/
google-analytics.com/collect
google-analytics.com/gtm/js
google-analytics.com/internal/collect^
google-analytics.com/r/collect^
5min.com/flashcookie/StorageCookieSWF_
9fine.ru/js/counter.
9msn.com.au^*/tracking/
actonservice.com^*/tracker/
adchemy-content.com^*/tracking.js
admission.net^*/displaytracker.js
akamai.net/chartbeat.
akamai.net^*/sitetracking/
amazonaws.com/analytics.
amazonaws.com^*.kissinsights.com/
amazonaws.com^*.kissmetrics.com/
amazonaws.com^*/pageviews
aol.com/ping
appspot.com/stats
areyouahuman.com/kitten
azureedge.net/track
bit.ly/stats
bitgravity.com^*/tracking/
bitmovin.com/impression
bizrate-images.co.uk^*/tracker.js
bizrate-images.com^*/tracker.js
bizrate.co.uk/js/survey_
bizrate.com^*/survey_
bumpin.com^*/analytics.html
capture.bi.movideo.com/dc
capture.camify.com/dc
centerix.ru^*/count.msl
click.email.*/open.aspx
cloudfront.net*/keywee.min.js
cloudfront.net*/sp.js
cloudfront.net*/tracker.js
cloudfront.net*/trk.js
cloudfront.net/autotracker
cloudfront.net/dough/*/recipe.js
cloudfront.net/track
cnetcontent.com/log
cnzz.com/stat.
communicatorcorp.com^*/conversiontracking.js
content.cpcache.com^*/js/ga.js
creativecdn.com/tags
custom.search.yahoo.co.jp/images/window/*.gif
customerlobby.com/ctrack-
d1ivexoxmp59q7.cloudfront.net^*/live.js
d2d5uvkqie1lr5.cloudfront.net^*/analytics-
d2d5uvkqie1lr5.cloudfront.net^*/analytics.
dealer.com^*/tracker/
dealer.com^*/tracking/
dmdentertainment.com^*/video_debug.gif
ebaystatic.com^*/tracking_RaptorheaderJS.js
ecustomeropinions.com^*/i.php
edgesuite.net^*/googleanalyt
els-cdn.com^*/analytics.js
emihosting.com^*/tracking/
facebook.com*/impression.php
facebook.com/tr
fastly.net/collect
feed.informer.com/fdstats
flixster.com^*/analytics.
freecurrencyrates.com/statgif.
freedom.com^*/analytic/
freedom.com^*/analytics/
fwix.com^*/trackclicks_
fyre.co^*/tracking/
gamegecko.com/gametrack
gigya.com^*/cimp.gif
glam.com^*/log.act
goadv.com^*/track.js
googleapis.com^*/gen_204
googlecode.com^*/tracker.js
gowatchit.com^*/tracking/
gravity.com^*/beacons/
grymco.com^*/event
gstatic.com/gen_204
hellobar.com/ping
hornymatches.com^*/visit.php
hypercomments.com/widget/*/analytics.html
images-amazon.com^*/1x1_trans.gif
images-amazon.com^*/Analytics-
images-amazon.com^*/AnalyticsReporter-
imageshack.us^*/thpix.gif
insnw.net/assets/dsc/dsc.fingerprint-
instagram.com/logging_client_events
kaltura.com^*/statisticsPlugin.swf
kiwari.com^*/impressions.asp
kununu.com^*/tracking/
l-host.net/etn/omnilog
leadpages.net^*/tracking.js
legacy.com^*/unicaclicktracking.js
ligatus.com/script/viewtracker-
livefyre.com^*/tracker.js
livefyre.com^*/tracking/
longtailvideo.com^*/yourlytics-
lsimg.net^*/vs.js
mail.ebay.com/img/*.gif
mail.ru/grstat
mail.ru/k
mantisadnetwork.com/sync
maxmind.com^*/geoip.js
maxmind.com^*/geoip2.js
mcssl.com^*/track.ashx
mediaite.com^*/track/
mixpanel.com/track
modules.ooyala.com^*/analytics-
mysdcc.sdccd.edu^*/.log/
nativly.com^*/track
netalpaca.com/beacon
netbiscuits.net^*/analytics/
neulion.vo.llnwd.net^*/track.js
ns-cdn.com^*/ns_vmtag.js
ocp.cnettv.com^*/Request.jsp
ooyala.com/3rdparty/comscore_
ooyala.com/sas/analytics
ooyala.com/verify
outbrain.com^*/widgetStatistics.js
partypoker.com^*/tracking-
paypalobjects.com^*/pixel.gif
piano-media.com/ping
player.ooyala.com/errors/report
plugins.longtailvideo.com/googlytics
plugins.longtailvideo.com/yourlytics
purevideo.com^*/pvshim.gif
pussy.org^*/track.php
qq.com/stats
qualtrics.com^*/metrics
rackcdn.com^*/analytics.js
realtidbits.com^*/analytics.js
reevoo.com^*/track/
relap.io^*/head.js
replyat.com/gadgetpagecounter*.asp
richrelevance.com/rrserver/tracking
ru4.com/click
sendtonews.com^*/data_logging.php
shareaholic.com/analytics_
sharethis.com/increment_clicks
sharethis.com/pageviews
signup.advance.net^*affiliate
spread.ly^*/statistics.php
statking.net^*/count.js
streamads.com/view
synapsys.us^*/tracker.js
thron.com^*/trackingLibrary.swf
timeinc.net^*/peopleas2artracker_v1.swf
tinypass.com^*/track
totallylayouts.com^*/users-online-counter/online.js
totallylayouts.com^*/visitor-counter/counter.js
turner.com^*/1pixel.gif
twimg.com/jot
twitter.com/i/jot
upcat.custvox.org/survey/*/countOpen.gif
uservoice.com^*/track.js
vanilladev.com/analytics.
vapedia.com^*/largebanner.
virginmedia.com^*/analytics/
vizual.ai^*/click-stream-event
webvoo.com^*/logtodb.
wetpaint.com^*/track
widgetserver.com^*/image.gif
widgetserver.com^*/quantcast.swf
wikinvest.com^*/errorlogger.php
woolik.com^*^tracker^
yandex.ru/cycounter
ypcdn.com/*/webyp
zemanta.com^*/pageview.js
3dmark.com^*/ruxitbeacon
9msn.com.au^*.tracking.udc.
abc.net.au^*/stats/
accuratefiles.com/stat
adidas.com^*/analytics/
adprimemedia.com^*/video_report/attemptAdReport.php
adprimemedia.com^*/video_report/videoReport.php
airbnb.*/tracking/
akamai.net^*/button.clickability.com/
alarabiya.net/track_content_
alarabiya.net^*/googleid.js
alibaba.com/js/beacon_
alicdn.com/js/aplus_*.js
alicdn.com^*/log.js
aliexpress.com/js/beacon_
allvoices.com/track_page
amazon.*/action-impressions/
amazon.*/ajax/counter
amazon.*/record-impressions
amazon.*/uedata/
amazon.*/uedata
amazon.com/gp/forum/email/tracking
amazon.com^*/amazon-clicks/
amazon.com^*/vap-metrics/
amazonaws.com^*/pzyche.js
amazonsupply.com/uedata
analytics.omgpop.com/log
anntaylor.com/webassets/*/page_code.js
anp.se/track
ap.org^*/webtrendsap_hosted.js
applifier.com/users/tracking
archive.org^*/analytics.js
associatedcontent.com/action_cookie
atlantafalcons.com/wp-content/*/metrics.js
audible.com^*/uedata/
autopartswarehouse.com/thirdparty/tracker
avg.com^*/stats.js
avira.com/site/datatracking
baidu.com/ecom
barneys.com^*/__analytics-tracking
bbc.co.uk/analytics
bbc.co.uk^*/linktrack.js
bbc.co.uk^*/livestats.js
bbc.co.uk^*/livestats_v1_1.js
bbc.co.uk^*/tracker.js
bbci.co.uk^*/analytics.js
beacons.vessel-static.com/xff
beacons.vessel-static.com^*/pageView
bhg.com^*/tracking-data
bidz.com/contentarea/BidzHomePixel
bing.com/partner/primedns
bing.com^*/GLinkPing.aspx
biosphoto.com^*/stats/
bits.wikimedia.org/geoiplookup
blekko.com/a/track
blinkbox.com/tracking
blinkist.com/t
blip.tv/engagement
bloxcms.com^*/tracker.js
booking.com/js_tracking
businessinsider.com^*/track.js
buzzfeed.com^*/tracker.js
carmagazine.co.uk^*/tracking.js
cars.com^*/analytics.js
cartoonnetwork.com^*/brandcma.js
cbs.com/assets/js/*AdvCookie.js
cbslocal.com^*/cbs1x1.gif
cctv.com^*/SnoopStat
cheezburger.com/api/visitor
chelseafc.com^*/tracking.js
cjtube.com/tp/*.php
cl.ly/metrics
climatedesk.org*/pixel.gif
commentarymagazine.com^*/track.asp
computing.co.uk^*/webtrends.js
cooksunited.co.uk/counter*.php
creativecommons.org^*/triples
crunchyroll.com/tracker
crunchyroll.com^*/breadcrumb.js
ct.cnet.com/opens
ctscdn.com/content/tracking-
dailymotion.com/track-
dailymotion.com^*/analytics.js
dailymotion.com^*/tag.gif
data.ninemsn.com.au/*GetAdCalls
datehookup.com/strk/dateadvertreg
db.com^*/stats.js
deadspin.com^*/trackers.html
dell.com/images/global/js/s_metrics*.js
digitalchocolate.com/event/track
digitalriver.com^*/globaltracking
divxden.com^*/tracker.js
dsm.com^*/searchenginetracking.js
dw.de^*/run.dw
easy2.com^*/logging/
edgecastcdn.net^*/pixel_1.png
ednetz.de/api/public/socialmediacounter.
email.aol.com/cgi-bin*/flosensing
engadget.com/click
espncdn.com^*.tracking.js
etonline.com/media/*/ctvconviva.swf
euroleague.tv^*/tracking.js
exelate.com/pixel
f-secure.com^*/wtsdc.js
facebook.com/ajax/*/log.php
facebook.com/ajax/*logging.
facebook.com/friends/requests/log_impressions
facebook.com^*/impression_logging/
fantom-xp.org^*/toprefs.php
financialstandardnews.com^*/webstats/
flipboard.com/usage
flipkart.com/ajaxlog/visitIdlog
forbes.com^*/track.php
foursquare.com^*/logger
foursquare.com^*/wtrack
freebase.com/log
freecause.com^*.png
freedownloadscenter.com^*/empty.gif
freemeteo.com^*/log.asp
freemeteo.com^*/searchlog.asp
frontdoor.com/_track
frstatic.net^*/tracking.js
ft.com^*/ft-tracking.js
gawker.com^*/trackers.html
general-files.com/stat
general-search.com/stat
geovisites.com^*/geouser.js
github.com/_private/browser/stats
github.com/_stats
gizmodo.com^*/trackers.html
glamourmagazine.co.uk^*/LogPageView
globester.com^*/track.js
go.com/globalelements/utils/tracking
go.com^*/analytics.js
google.*/api/sclk
google.*/client_204
google.*/gen204
google.*/gwt/x/ts
google.*/log204
google.*/logxhraction
google.com/appserve/mkt/img/*.gif
google.com/log
google.com/reader/logging
google.com/stream_204
google.com^*/dlpageping
google.com^*/log
google.com^*/urchin_post.js
google.com^*/viewerimpressions
gorillanation.com^*/flowplayer.ganalytics.swf
groupon.com/tracking
holiday-rentals.co.uk/thirdparty/tag
holiday-rentals.co.uk^*/tracking-home.html
homeaway.com^*/tracking-home.html
hp.com^*/bootstrap/metrics.js
huffingtonpost.com/click
huffingtonpost.com/ping
hulu.com/beacon/v3/error
hulu.com/beacon/v3/playback
hulu.com/watch/*track.url-1.com
hulu.com^*/external_beacon.swf
hulu.com^*/plustracking/
hulu.com^*/potentialbugtracking/bigdropframes
hulu.com^*/potentialbugtracking/contentplaybackresume
hulu.com^*/potentialbugtracking/dropframes
hulu.com^*/recommendationTracking/tracking
hulu.com^*/sitetracking/
huluim.com^*/sitetracking/
hwscdn.com^*/brands_analytics.js
id.google.*/verify/*.gif
images-amazon.com^*/ClientSideMetricsAUIJavascript*.js
imdb.com/video/*/metrics_
imdb.com/video/*metrics
indeed.com/rpc/preccount
indiatimes.com/trackjs10.
informer.com/statistic
insidesoci.al/track
instructables.com/counter
instyle.co.uk^*/tracking.js
io9.com^*/trackers.html
jalopnik.com^*/trackers.html
jezebel.com^*/trackers.html
joins.com^*/JTracker.js
jtv.com^*/__analytics-tracking
kayak.com/k/redirect/tracking
kelkoo.co.uk/kk_track
kelkoo.co.uk^*/tracker/
kelkoo.com/kk_track
killerstartups.com^*/adsensev
kodakgallery.com^*/analytics_
kotaku.com^*/trackers.html
lendingtree.com/forms/eventtracking
lifehacker.com^*/trackers.html
likes.com/api/track_pv
linguee.com*/white_pixel.gif
link.ex.fm/img/*.gif
linkedin.com^*/tracker.gif
list.ru/counter
livestation.com^*/akamaimediaanalytics.swf
livestation.com^*/statistics.swf
livestream.com^*/analytics/
lm.pcworld.com/db/*/1.gif
lovefilm.com^*/lf-perf-beacon.png
lucidchart.com/analytics_
ly.lygo.com^*/jquery.lycostrack.js
mail.ru/counter
maps.nokia.com^*/tracking.c.js
marriott.com^*/mi_customer_survey.js
mastercard.com^*/Analytics/
mate1.com^*/iframe/pixel/
mate1.com^*/reg.logging.js
media-imdb.com^*/adblock.swf
mediaplex.com^*/universal.html
metacafe.com^*/statsrecorder.php
microsoft.com^*/bimapping.js
microsoft.com^*/surveytrigger.js
miniclip.com^*/swhsproxy.swf
miniusa.com^*/trackDeeplink.gif
mirror.co.uk^*/stats/
moneysupermarket.com^*/ProphetInsert.js
mozilla.net^*/webtrends/
mp3lyrics.org^*/cnt.php
msecnd.net^*/wt.js
msn.com/script/tracking*.js
msn.com^*/report.js
msn.com^*/track.js
msnbc.msn.com^*/analytics.js
mto.mediatakeout.com/viewer
nationmobi.com/*/analyse.php
nature.com^*/marker-file.nocache
nbcnews.com^*/analytics.js
nbcudigitaladops.com/hosted/js/*_com.js
nbcudigitaladops.com/hosted/js/*_com_header.js
netlog.com/track
newegg.com/tracking
news-leader.com^*/analytics.js
ninemsn.com.au^*.tracking.udc.
nola.com/content/*/tracklinks.js
novatech.co.uk^*/tracking
novell.com^*/metrics.js
nydailynews.com^*/tracker.js
nymag.com^*/analytics.js
nyse.com^*/stats/
nzonscreen.com/track_video_item
nzpages.co.nz^*/track.js
nzs.com/sliscripts_
officelivecontent.com^*/Survey/
okcupid.com/poststat
oload.tv/log
openload.co/log
optionsxpress.com^*/tracking.js
papajohns.com/index_files/activityi_data/ct-*.js
pch.com^*/scripts/Analytics/
pch.com^*/SpectrumAnalytics.js
pcmag.com^*/analytics.js
peacocks.co.uk^*/analytics.js
pearltrees.com/s/track
perezhilton.com^*/stat/
perfectmarket.com/pm/track
petersons.com^*/trackBeta.asp
petersons.com^*/trackFunctionsBeta.asp
photobucket.com^*/tracklite.php
popcap.com^*/interstitial_zones.js
pornhd.com/api/user/tracking
porntube.com^*/track
potterybarn.com/pbimgs/*/external/thirdparty.js
potterybarnkids.com/pkimgs/*/external/thirdparty.js
priceline.com^*/beaconHandler
priceline.com^*/impression/
prudential.com^*/metrics_1px.gif
pw.org/sites/all/*/ga.js
ralphlauren.com^*/icg.metrics.js
rangers.co.uk^*/tracking.js
rarefilmfinder.com^*/cnt-gif1x1.php
real.com^*/track.htm
redditmedia.com/gtm/jail
redtube.com/trackimps
redtube.com/trackplay
redtube.com^*/jscount.php
refinery29.com/api/stats
register.it/scripts/track_
reuters.com^*/rcom-wt-mlt.js
reuters.com^*/tracker_video.js
reuters.com^*/widget-rta-poc.js
reutersmedia.net^*/tracker-article*.js
riverisland.com^*/mindshare.min.js
roadandtrack.com^*/RTdartSite.js
runnersworld.com^*/universalpixel.html
sagepub.com^*/login_hit_hidden.gif
samsung.com^*/scripts/tracking.js
scribd.com^*/tracker.gif
search.yahoo.com/ra/click
seeclickfix.com^*/text_widgets_analytics.html
sella.co.nz^*/sella_stats_
sevenload.com/som_
sh.st/bundles/smeweb/img/tracking-
shareaholic.com^*/bake.gif
shopzilla-images.com/s2static/*/js/tracker.js
sky.com^*/hightrafficsurveycode.js
skype.com^*/inclient/
skype.com^*/track_channel.js
skypeassets.com^*/inclient/
skypeassets.com^*/track_channel.js
smallcapnetwork.com^*/viewtracker/
soundcloud.com/event
spoonful.com^*/tracking.js
spreaker.com^*/statistics/
statesmanjournal.com^*/articlepageview.php
static.ow.ly^*/click.gz.js
staticwhich.co.uk/assets/*/track.js
statravel.com^*/Javascript/wt_gets.js
stomp.com.sg/site/servlet/tracker
store.yahoo.net^*/ywa.js
stuff.co.nz^*/track.min.js
supermediastore.com/web/track
superpages.com/ct/clickThrough
tab.co.nz/track
talktalk.co.uk^*/tracking/
tdwaterhouse.co.uk^*/track.js
telegraph.co.uk^*/tmglmultitrackselector.js
thedeal.com/oas_
thefashionspot.com^*/pb.track.js
thefreedictionary.com^*/track.ashx
thegumtree.com^*/tracking.js
thrillist.com/track
tiaa-cref.org^*/js_tiaacref_analytics.
tinyupload.com^*/ct_adkontekst.js
tivo.com/__ssobj/track
tmagazine.com/js/track_
torrentz.eu/ping
torrentz.in/ping
torrentz.li/ping
torrentz.me/ping
toshibadirect.com^*/remarketing_google.js
tradetrucks.com.au/ga.
treato.com/api/analytics
triond.com/cntimp
tripadvisor.*/PageMoniker
trivago.com/check-session-state
truecar.com/tct
twitter.com/abacus
twitter.com/i/csp_report
twitter.com/scribe
twitter.com^*/log.json
twitter.com^*/prompts/impress
twitter.com^*/scribe^
typepad.com/t/stats
ultra-gamerz-zone.cz.cc/b/stats
unisys.com^*/tracking.js
united.com^*/hp_mediaplexunited.html
upi.com/*/stat/
upsellit.com^*/visitor
viamichelin.co.uk^*/stats.js
viamichelin.de^*/stats.js
vice.com*/mb_tracker.html
vice.com*/tracker.html
vid.io^*/mejs-feature-analytics.js
video.nbc.com^*/metrics_viral.xml
videoplaza.com/proxy/tracker
vidxden.com^*/tracker.js
vietnamnet.vn^*/tracking.js
voxmedia.com/needle
wachovia.com^*/stats.js
washingtonpost.com/wp-srv/javascript/placeSiteMetrix.
watchmouse.com^*/jsrum/
whstatic.com^*/ga.js
wikihow.com/visit_info
wired.com/event
worldgolf.com^*/js/track.js
xbox.com^*/vortex_tracking.js
yahoo.com/__perf_log_
yahoo.com/b
yahoo.com/neo/stat
yahoo.com/neo/ymstat
yahoo.com^*/pageview/
yahoo.com^*/rt.gif
yahoo.com^*/ultLog
yahoo.net^*/hittail.js
yahooapis.com/get/Valueclick/CapAnywhere.getAnnotationCallback
yimg.com/nq/ued/assets/flash/wsclient_
yimg.com^*/yabcs.js
yimg.com^*/ywa.js
yobt.tv/js/timerotation*.js
youandyourwedding.co.uk^*/EAS_tag.
youandyourwedding.co.uk^*/socialtracking/
youporn.com^*/tracker.js
youtube-nocookie.com/device_204
youtube-nocookie.com/gen_204
youtube-nocookie.com/ptracking
youtube.com/api/stats/ads
youtube.com/get_video
youtube.com/ptracking
youtube.com/s
youtube.com/set_awesome
ypcdn.com/webyp/javascripts/client_side_analytics_
yuku.com/stats
yupptv.com/yupptvreports/stats.php^
zap2it.com^*/editorial-partner/
zdnet.com/wi
zulily.com/action/track
zvents.com/za
zvents.com/zat
zylom.com^*/global_tracking.jsp
zylom.com^*/tracking_spotlight.js
adobe.com^*/omniture_s_code.js
announcements.uk.com^*/s_code.js
bitdefender.com/resources/scripts/omniture/*/code.js
bleacherreport.net/pkg/javascripts/*_omniture.js
consumerreports.org^*/s_code.js
disneylandparis.fr^*/s_code.js
eltiempo.com/js/produccion/s_code_*.js
loc.gov/js/*/s_code.js
redbox.com^*/scripts/s_code.js
ticketmaster.eu^*/omniture_tracker.js
westernunion.*/_globalAssets/js/omniture/AppMeasurement.js`;
var bad_da_hostpath_regex_flag = 2002 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 386 rules:
var bad_da_regex = `affiliate.
affiliates.
banner.
banners.
oas.*@
ox-*/jstag^
pop-over.
promo.
synad.
online.*/promoredirect?key=
ox-d.*^auid=
ads.
adv.
doubleclick.net/adj/*.collegehumor/sec=videos_originalcontent;
doubleclick.net/pfadx/*adcat=
doubleclick.net^*;afv_flvurl=http://cdn.c.ooyala.com/
metaffiliation.com^*^maff=
metaffiliation.com^*^taff=
35.184.137.181^popup,third-party
35.184.98.90^popup,third-party
247hd.net/ad|
amazon.com/?_encoding*&linkcode
api.ticketnetwork.com/Events/TopSelling/domain=nytimes.com
associmg.com^*.gif?tag-
augine.com/widget|
babylon.com/trans_box/*&affiliate=
babylon.com^*?affid=
booking.com^*;tmpl=banner_
clipdealer.com/?action=widget&*&partner=
cloudfront.net/?tid=
contentcastsyndication.com^*&banner
cts.tradepub.com/cts4/?ptnr=*&tm=
cursecdn.com/shared-assets/current/anchor.js?id=
d2kbaqwa2nt57l.cloudfront.net/?qabkd=
deals4thecure.com/widgets/*?affiliateurl=
depositfiles.com^*.php?ref=
download-provider.org/?aff.id=
downloadprovider.me/en/search/*?aff.id=*&iframe=
everestpoker.com^*/?adv=
fancybar.net/ac/fancybar.js?zoneid
farm.plista.com/widgetdata.php?*%22pictureads%22%7D
filefactory.com^*/refer.php?hash=
freakshare.com/?ref=
generic4all.com^*?refid=
get.*.website/static/get-js?stid=
glam.com^*?affiliateid=
grammarly.com/embedded?aff=
heyoya.com^*&aff_id=
kallout.com^*.php?id=
l.yimg.com^*&partner=*&url=
ladbrokes.com^*&aff_id=
mmo4rpg.com^*.gif|
moosify.com/widgets/explorer/?partner=
msm.mysavings.com^*.asp?afid=
myspace.com/play/myspace/*&locationId
nativly.com/tds/widget?wid=
red-tube.com^*.php?wmid=*&kamid=*&wsid=
rehost.to/?ref=
rover.ebay.com^*&adtype=
seatplans.com/widget|
shragle.com^*?ref=
stacksocial.com^*?aid=
static.plista.com/jsmodule/flash|
streamtheworld.com/ondemand/ars?type=preroll
sweed.to/?pid=
sweeva.com/widget.php?w=
theselfdefenseco.com/?affid=
tipico.*?affiliateId=
townsquareblogs.com^*=sponsor&
trialpay.com^*&dw-ptid=
tritondigital.com/lt?sid*&hasads=
widgets.itunes.apple.com^*&affiliate_id=
winpalace.com/?affid=
zazzle.com^*?rf
6angebot.ch/?ref=
aliexpress.com/?af=
babylon.com/welcome/index.html?affID=
bet365.com^*affiliate=
casino-x.com^*?partner=
dateoffer.net/?s=*&subid=
erotikdeal.com/?ref=
fleshlight.com/?link=
fulltiltpoker.com/?key=
generic4all.com^*.dhtml?refid=
hyperlinksecure.com/back?token=
lovepoker.de^*/?pid=
maxedtube.com/video_play?*&utm_campaign=
media.mybet.com/redirect.aspx?pid=*&bid=
reviversoft.com^*&utm_source=
stake7.com^*?a_aid=
stargames.com/bridge.asp?idr=
stargames.com/web/*&cid=*&pid=
theseforums.com^*/?ref=
tipico.com^*?affiliateid=
urmediazone.com/play?ref=
vidds.net/?s=promo
vkpass.com/*.php?*=
amarotic.com^*?wmid=*&kamid=*&wsid=
eurolive.com/?module=public_eurolive_onlinehostess&
eurolive.com/index.php?module=public_eurolive_onlinetool&
firestormmedia.tv^*?affid=
fuckhub.net^*?pid=
gallery.deskbabes.com^*.php?dir=*&ids=
manhunt.net/?dm=
my-dirty-hobby.com/?sub=
pinkvisualgames.com/?revid=
privatehomeclips.com/privatehomeclips.php?t_sid=
zubehost.com/*?zoneid=
777livecams.com/?id=
amarotic.com^*?wmid=
camcity.com/rtr.php?aid=
chaturbate.com/*/?join_overlay=
cpm.amateurcommunity.*?cp=
epornerlive.com/index.php?*=punder
exposedwebcams.com/?token=
fleshlight-international.eu^*?link=
flirt4free.com^*&utm_campaign
fuckshow.org^*&adr=
ipornia.com/scj/cgi/out.php?scheme_id=
media.campartner.com/index.php?cpID=*&cpMID=
media.campartner.com^*?cp=
mjtlive.com/exports/golive/?lp=*&afno=
myfreecams.com/?co_id=
online.mydirtyhobby.com^*?naff=
pornhub.com^*&utm_campaign=*-pop|
pornme.com^*.php?ref=
postselfies.com^*?nats=
redlightcenter.com/?trq=
seeme.com^*?aid=*&art=
sexier.com^*_popunder&
tube911.com/scj/cgi/out.php?scheme_id=
tuberl.com^*=
videobox.com/?tid=
videosz.com^*&tracker_id=
visit-x.net/cams/*.html?*&s=*&ws=
xrounds.com/?lmid=
xvideoslive.com/?AFNO
2oceansvibe.com/?custom=takeover
64.245.1.134/search/v2/jsp/pcwframe.jsp?provider=
977music.com/index.php?p=get_loading_banner
answerology.com/index.aspx?*=ads.ascx
awkwardfamilyphotos.com*/?ad=
cdmediaworld.com*/!
cnn.com^*/banner.html?&csiid=
comicgenesis.com/tcontent.php?out=
crazymotion.net/video_*.php?key=
dictionary.cambridge.org/info/frame.html?zone=
diytrade.com/diyep/dir?page=common/ppadv&
duckduckgo.com/i.js?o=a&
duckduckgo.com/m.js?*&o=a
ebayrtm.com/rtm?RtmCmd*&enc=
ebayrtm.com/rtm?RtmIt
expertreviews.co.uk/?act=widgets.
fileshut.com/etc/links.php?q=
firstrow*/pu.js
gamecopyworld.com*/!
gamecopyworld.eu*/!
gameknot.com/amaster.pl?j=
hentaistream.com/wp-includes/images/$object
herold.at/fs/orgimg/*.swf?baseurl=http%3a%2f%2fwww.*&amp;linktarget=_blank$object
herold.at^*.swf?*&linktarget=_blank
hipforums.com/newforums/calendarcolumn.php?cquery=bush
hulu.com/beacon/*=adauditerror
ibtimes.com^*&popunder
kitguru.net/?kitguru_wrapjs=1&ver=
kovideo.net^*.php?user_
macmillandictionary.com/info/frame.html?zone=
mail.yahoo.com/neo/mbimg?av/curveball/ds/
mediaspanonline.com/inc.php?uri=/&bannerPositions=
meteomedia.com^*&placement
mirrorstack.com/?q=r_ads
monster.com/null&pp
mp3mediaworld.com*/!
msn.com/?adunitid
musictarget.com*/!
news.com.au/news/vodafone/$object
nutritionhorizon.com/content/flash_loaders/$object
preev.com/ads|
preev.com/ad|
psgroove.com/images/*.jpg|
radiocaroline.co.uk/swf/ACET&ACSP_RadioCaroline_teg.swf
rawstory.com^*.php?code=bottom
retrevo.com/m/google?q=
scmagazine.com.au/Utils/SkinCSS.ashx?skinID=
search.triadcareers.news-record.com/jobs/search/results?*&isfeatured=y&
sendspace.com/defaults/framer.html?z=
sendspace.com^*?zone=
shops.tgdaily.com^*&widget=
shortcuts.search.yahoo.com^*&callback=yahoo.shortcuts.utils.setdittoadcontents&
slacker.com^*/getspot/?spotid=
softpedia-static.com/images/*.jpg?v
softpedia-static.com/images/*.png?v
spa.dictionary.com^$object
static.hd-trailers.net/js/javascript_*.js|
thefile.me^*.php?*zoneid
tigerdroppings.com^*&adcode=
twitch.tv/ad/*=preroll
twitter.com/i/cards/tfw/*?advertiser_name=
uploadbaz.com^*-728-$object
vogue.in/node/*?section=
wikia.com/__are?r=
yahoo.*/serv?s=
zabasearch.com/search_box.php?*&adword=
zoozle.org/if.php?q=
tweaktown.com/zyx?p=
tweaktown.com^$object
allmyvideos.net/*=
casino-x.com^*&promo
deb.gs^*?ref=
eafyfsuh.net^*/?name=
edomz.com/re.php?mid=
exashare.com^*&h=
filmon.com^*&adn=
freean.us^*?ref=
ifly.com/trip-plan/ifly-trip?*&ad=
linkbucks.com^*/?*=
miniurls.co^*?ref=
oddschecker.com/clickout.htm?type=takeover-
plarium.com/play/*adCampaign=
sponsorselect.com/Common/LandingPage.aspx?eu=
thevideo.me/*:
torrentz.eu/search*=
vkpass.com/goo.php?link=
2hot4fb.com/img/*.gif?r=
2hot4fb.com/img/*.jpg?r=
fritchy.com^*&zoneid=
hdzog.com/hdzog.php?t_sid=
julesjordanvideo.com/flash/$object
krasview.ru/content/$object
myvidster.com^*.php?idzone=
olderhill.com^*.html|
porntube.com/ads|
tnaflix.com/*.php?t=footer
tubecup.org/?t_sid=
voyeurhit.com/related/voyeurhit.php?t_sid=
waybig.com/blog/wp-content/uploads/*?pas=
xxnxx.eu/index.php?xyz_lbx=
fantasti.cc^*?ad=
movies.askjolene.com/c64?clickid=
ivwextern.
mint.*/?js
piwik.
doubleclick.net/imp;
quantserve.com^*^a=
visiblemeasures.com/swf/*/vmcdmplugin.swf?key*pixel
24option.com/?oftc=
6waves.com/edm.php?uid=
ad.atdmt.com/i/*=
ad.atdmt.com/i/go;
addthis.com^*/p.json?*&ref=
addthiscdn.com/*.gif?uid=
amazon.com/gp/*&linkCode
amazonaws.com/?wsid=
anvato.com/anvatoloader.swf?analytics=
assoc-amazon.*^e/ir?t=
auctiva.com/Default.aspx?query
bufferapp.com/wf/open?upn=
c.ypcdn.com^*&ptid
c.ypcdn.com^*?ptid
cloudfront.net/?a=
dditscdn.com/?a=
ebayrtm.com/rtm?RtmCmd&a=img&
elb.amazonaws.com/?page=
elb.amazonaws.com/g.aspx?surl=
etahub.com^*/track?site_id
events.eyeviewdigital.com^*.gif?r=
forms.aweber.com^*/displays.htm?id=
freehostedscripts.net^*.php?site=*&s=*&h=
heroku.com/?callback=getip
imagepix.okoshechka.net^*/?sid=
inq.com^*/onEvent?_
jangomail.com^*?UID
k7-labelgroup.com/g.html?uid=
lijit.com/blog_wijits?*=trakr&
liverail.com/?metric=
mediaplex.com^*?mpt=
metaffiliation.com^*^mclic=
ooyala.com/authorized?analytics
ooyala.com^*/report?log
p.po.st/p?pub=
p.po.st/p?t=view&
p.po.st^*&pub=
p.po.st^*&vguid=
pussy.org^*.cgi?pid=
r.ypcdn.com^*/rtd?ptid
redplum.com^*&pixid=
s5labs.io/common/i?impressionId
secureprovide1.com/*=tracking
shopify.com/storefront/page?*&eventType=
socialreader.com^*?event=email_open^
soundcloud.com^*/plays?referer=
speedtestbeta.com/*.gif?cb
sugarops.com/w?action=impression
trove.com^*&uid=
tsk5.com/17*?*=ex-
ui-portal.com^*;ns_referrer=
vds_dyn.rightster.com/v/*?rand=
wikinvest.com/plugin/*=metricpv
ws.amazon.com/widgets/*=gettrackingid|
yellowpages.com^*.gif?tid
yimg.com^*/l?ig=
ziffprod.com^*/zdcse.min.js?referrer=
zoomtv.me^*?pixel=
airfrance.com/s/?tcs=
alipay.com/web/bi.do?ref=
amazon.*/batch/*uedata=
androidcommunity.com/ws/?js
api.tinypic.com/api.php?action=track
arstechnica.com/*.ars$object
arstechnica.com/|$object
arstechnica.com^*.gif?id=
arstechnica.com^*/|$object
banggood.com/?p=
binaries4all.nl/misc/misc.php?*&url=http
bloomberg.com/apps/data?referrer
brobible.com/?ACT
businessseek.biz/cgi-bin/*.pl?trans.gif&ref=
c.ypcdn.com^*/webyp?rid=
cbox.ws^*/relay.swf?host=
cgi.nch.com.au^*&referrer
computerarts.co.uk/*.php?cmd=site-stats
djtunes.com^*&__utma=
dropbox.com/el/?b=open:
dx.com/?utm_rid=
ebay.com/op/t.do?event
ebayobjects.com/*;dc_pixel_url=
efukt.com^*?hub=
email-tickets.com/dt?e=PageView
freelotto.com/offer.asp?offer=
freeones.com/cd/?cookies=
freeones.com^*/cd/?cookies=
gamezone.com/?act=
gawker.com/?op=hyperion_useragent_data
giffgaff.com/r/?id=
google.*/stats?frame=
gumtree.com.au/?pc=
hulu.com/*&beaconevent
huluim.com/*&beaconevent
humanclick.com/hc/*/?visitor=
imagetwist.com/?op=
imdb.com/rd/?q
infospace.com^*=pageview&
ip-adress.com/gl?r=
juno.com/start/javascript.do?message=
kosmix.com^*.txt?pvid=
linkbucks.com/clean.aspx?task=record
liveperson.net/hc/*/?visitor=
mail.yahoo.com/dc/rs?log=
mozilla.org/includes/min/*=js_stats
musicstack.com/livezilla/server.php?request=track
neatorama.com/story/view/*.gif?hash
netflix.com/beacons?*&ssizeCat=*&vsizeCat=
optimum.net^*=pageview&
orain.org/w/index.php/Special:RecordImpression?
overstock.com/dlp?cci=
p.ctpost.com/article?i=
photobucket.com^*/api.php?*&method=track&
photographyblog.com/?ACT
pluto.airbnb.com^*.php?uuid=
quantserve.com/pixel;
rediff.com^*/?rkey=
redtube.com/blockcount|
rover.ebay.com.au^*&cguid=
servedby.yell.com/t.js?cq
stylelist.com/ping?ts=
tesco.com/cgi-bin3/buyrate?type=
thefilter.com^*/CaptureRest.ashx?cmd=
thefrisky.com/?act=
tinypic.com/api.php?*&action=track
totalporn.com/videos/tracking/?url=
truste.com/notice?*consent-track
u.bb/omni*.swf|
uploadrocket.net/downloadfiles.php?*&ip
usage.zattoo.com/?adblock=
wellsphere.com/?hit=
wikimedia.org/wiki/Special:RecordImpression?
wikinvest.com/plugin/api.php?*=metricld&
ws.elance.com^*&referrer=
www.imdb.*/rd/?q=
xhamster.com/ajax.php?act=track_event
xnxx.com/in.php?referer
yahoo.com/p.gif;
yahoo.com/serv?s
yahoo.com/sig=
yahoo.com/yi?bv=
yimg.com^*/swfproxy-$object`;
var bad_da_regex_flag = 386 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 0 rules:
var good_url_parts = "";
var good_url_parts_flag = 0 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 1941 rules:
var bad_url_parts = `&trackingserver=
-analitycs/fab.
-analitycs/ga.
-analitycs/metrica.
-analytics-tagserver-
-analytics/insight.
-asset-tag.
-bluekai.
-comscore.
-criteo.
-event-tracking.
-ga-track.
-gatracker.
-google-analytics.
-google-analytics/
-logging/log?
-mediaplex_
-optimost-
-page-analytics.
-rttracking.
-sa-tracker-
-scroll-tracker.js
-seo-tracker.
-social-tracking.
-stat/collect/
-stats/fab.
-stats/ga.
-stats/imr.
-stats/metrica.
-tracking-pixel.
-tracking.gtm.
-tracking.js?
-trackingScript.
-xtcore.js
.analytics.min.
.beacon.min.js
.cc/s.gif?
.cn/1.gif?
.cn/2.gif?
.cn/a.gif?
.cn/b.gif?
.cn/gs.gif?
.cn/r.gif?
.cn/s.gif?
.cn/xy.gif?
.cn/z.gif?
.com/a.gif?
.com/analytics?
.com/counter?
.com/log?event
.com/p.gif?
.com/pagelogger/
.com/s/at?site
.com/stats.ashx?
.com/stats.aspx?
.com/t.gif?
.com/track?$~object
.com/tracker.jsp
.com/tracking?
.com/traffic/?t=*&cb=
.com/v.gif?
.com/vtrack|
.core.tracking-min-
.do_tracking&
.gatracker.
.gatracking.js
.googleanalytics.js
.gov/stat?
.idge/js/analytics/
.io/track?
.lms-analytics/
.me/geoip/
.net/p.gif?
.net/vtrack|
.ntpagetag.
.php?p=stats&
.php?tracking=
.PixelNedstatStatistic/
.ru/0.gif?
.sitecatalyst.js
.siteclarity.
.sitetracking.
.skimlinks.js
.social_tracking.
.stats?action=
.to/vtrack|
.track_Visit?
.trackArticleAction&
.tracking.js?dpv=
.trackUserAction&
.tv/log?event
.tv/t.png?
.uk/track?
.uk/traffic/?
.usertracking_script.js
.webmetrics.js
.webstats.
/!crd_prm!.
/1x1.gif?tracking
/1x1.gif?utm
/1x1tracker.
/3rd-party-stats/
/?com=visit*=record&
/?essb_counter_
/__ssobj/core.js
/__utm.gif
/__utm.js
/__varnish_geoip
/_topic_stats?
/_tracking/
/abp-analytics.
/acbeacon2.
/accAnal.js
/AccessCounter/
/accesstracking/
/AccessTrackingLogServlet?
/acclog.cgi?
/acecounter/
/acecounter_
/acounter.php?
/act_pagetrack.
/activetrackphp.php?
/activity-track/?
/adb/track.php?
/add_stats
/adds/counter.js
/adlog.
/adlogger.
/adlogger_
/adloggertracker.
/adm_tracking.js
/admantx-
/admantx.
/admantx/
/adonis_event/
/adplogger/
/adrum-
/adrum.
/ads/counter.
/ads/track/
/ads?cookie_
/ads_tracker.
/ads_tracking.
/adsct?
/adstat.
/adstats.
/adstrack.
/adv/tracking.
/adviewtrack.
/advstats/
/adwords-conversion-tracking.
/adwords-tracker.
/aegis_tracking.
/affil/tracker/
/affiliate-track.
/affiliate-tracker.
/affiliate.1800flowers.
/affiliate/track?
/affiliateTracking.
/affiliatetracking/
/affilinetRetargeting.
/afftrack.
/afftracking.
/aftrack.
/aftrackingplugin.swf
/ajax-hits-counter/
/ajax/analytics/
/ajax/heatmap-
/ajax/stat/
/ajax/track.php?
/ajax_store_analytics?
/ajax_video_counter.php?
/ajaxClicktrack.
/ajaxstat/
/ajaxtracker.
/ajx/ptrack/
/akamai_analytics_
/alllinksclicktracker.js
/amazon-affiliate-
/amptrack.
/analiz.php3?
/analyse.js
/analysis-logger/
/analytic/count.
/analytic?publisher
/analytic_data_
/analyticReporting.
/analytics-assets/
/analytics-beacon-
/analytics-dotcom/
/analytics-event-
/analytics-js.
/analytics-plugin/
/analytics-post-
/analytics-tag.
/analytics-v1.
/analytics.ad.
/analytics.ashx
/analytics.bundled.js
/analytics.compressed.js
/analytics.do
/analytics.gif?
/analytics.google.js
/analytics.html?
/analytics.min.
/analytics.php.
/analytics.php?
/analytics.swf?
/analytics.v1.js
/analytics/*satellitelib.js
/analytics/activity.
/analytics/cms/
/analytics/core.
/analytics/dist/
/analytics/eloqua/
/analytics/events
/analytics/eventTrack
/analytics/ga/
/analytics/ga?
/analytics/gw.
/analytics/hit
/analytics/hmac-
/analytics/idg_
/analytics/js/
/analytics/mbox.js
/analytics/mouse_
/analytics/p.gif?
/analytics/pageview.
/analytics/pv.gif?
/analytics/report/
/analytics/smarttag-
/analytics/socialTracking.js
/analytics/tagx-
/analytics/track-
/analytics/track.
/analytics/track/
/analytics/track?
/analytics/tracker.
/analytics/trackers?
/analytics/tracking/
/analytics/track|
/analytics/urlTracker.
/analytics/visit/
/analytics/yell-
/analytics3.
/analytics?body=
/analytics?http_referer
/analytics?token=
/analytics_embed.
/analytics_frame.
/analytics_id.
/analytics_js/
/analytics_ping.
/analytics_prod.
/analytics_tag.
/analytics_tracker
/analytics_v2.js
/analyticsfeed.ashx?
/analyticsid.
/analyticsjs.
/analyticsjs/
/analyticsmediator.
/analyticsscript_
/analyticstick.
/analyticstrack.
/analyticstracking.
/analyticstracking_
/analyticstrain-
/analyticsUnitaire?
/analyze.js
/analyzer.gif?
/analyzer2.
/anycent_tracker_
/api/*/visitor?
/api/0/stats
/api/analytics/
/api/stat?
/api/tracking/
/apitracking.
/argtk.min.
/arstat?
/article-tracking.js
/article_counter.php?
/asknet_tracking.
/aspenanalytics.
/aspstats/index.asp?
/assets/analytics:
/assets/tracking-
/assets/uts/
/astrack.js
/astracker.
/astracker/
/asyncggtracking.
/atlas_track.
/audience-meter.
/autotag.
/avmws_*.js
/avtstats.
/aw-tracker.
/aws-analytics.js
/awstats.js
/awstats_misc_tracker
/aztrack.
/b/ss/*&events=
/b/ss/*=event36&
/b/ss/*?aqb=1&pccr=
/b2bsdc.js
/backlink.php?
/backlink2.
/banner-tracker.
/banner.stats?
/banners-stat.
/basesdc.js
/bcn.gif?
/bcn?
/beacon-cookie.
/beacon.cgi?
/beacon.gif?
/beacon.html?
/beacon.js
/beacon/b.ashx?
/beacon/track/
/beacon/vtn_loader.gif?
/beacon?
/beacon_async.
/beaconconfigs/
/beaconimg.php?
/betamax_tracker.gif?
/betamax_tracker.js
/bh_counter.js
/bi.tracking/
/bicomscore.
/bicomscore_
/biddr-analytics.
/bin/stats?
/bitrix/spread.php?
/blockstat?
/blog/traffic/?
/blogsectiontracking.
/blogtotal_stats_
/bluekai.
/bluekai/
/bluekaicookieinfo.
/bluetracker/
/bm-analytics-trk.js
/bm-analytics/
/bn/tracker/
/boost_stats.
/brandAnalytics.js
/brightcove/tracking/
/brightcoveGoogleAnalytics.
/brightedge.js
/britetrack/
/bstat.js
/btn_tracking_pixel.
/bugcounter.php?
/bugsnag-
/bundles/tracciamento?
/buzz_stats.
/c_track.php?
/calameo-beacon.
/callbacks/stats?
/campaign_tracker.
/campaign_trax.
/cbanalytics.
/cc?a=
/cclickTracking.
/cct?
/cdn-monitoring-pixel.
/cdn.stats2?
/cdn5.js?
/cds-webanalytics.
/cdx.gif?
/cedexis.js
/cedexis/
/cedexisus.
/certona.
/cfformprotect/
/cgi-bin/cnt/
/cgi/stats.pl?
/chan_slidesurvey.js
/chanalytics.
/chartbeat-
/chartbeat.jhtml
/chartbeat.js
/chartbeat.min.js
/chartbeat/
/chartbeat_
/chartbeatCode.
/chartbeatftr.
/chcounter/
/checkstat.asp
/citycounter.
/cjtracker2.
/ckimg_1x1.gif?
/cklink.gif?
/class.tracking.js
/clear.gif?
/clicevent.php?
/click-count.
/click-logger.
/click-stat.js
/click-tracker
/click.cgi?callback=
/click_metrics-jquery.js
/click_stat/
/click_statistics/
/click_stats.
/click_track.js
/click_tracking
/clickability-
/clickability/
/clickability2/
/clickability?
/clickAnalyse.
/clickcount.cfm?
/clickcount_
/clickctrl.js
/clickheat.js
/clickheat^
/clicklog.
/clicklog4pc.
/clicklog_
/clickLogger?
/clicklognew.
/clickmap.js
/clickpathmedia.
/clickpathmedia_
/clickrecord.php?
/clicks/servlet/
/clickscript.
/clickstats.
/clickstream.aspx?
/clickstream.js
/clicktale-
/clicktale.
/clicktale/
/clicktale_
/clicktrack-*.gif?
/clicktrack?
/clicktracker.
/clicktracking-global.
/clicktracking.
/clicktracking/
/clicktrends/
/clicky.js
/client-event-logger.
/clientdatacollector/
/clientstat?
/cms/stats/
/cn-fe-stats/
/cnstats.
/cnstats/
/cnt-combined.php?
/cnt.aspx?
/cnt.cgi?
/cnt.js
/cnt.php?rf=
/cnt/cnt.php?
/cnt/start.php?
/cntpixel.
/cnvtr.js
/cnwk.1d/*/apex.js
/cognitive_match/
/collect_data.php?
/collection.php?data=
/com_joomla-visites/
/com_joomlawatch/
/comscore.
/comscore/pageview_
/comscore_beacon.
/comscore_engine.
/comscore_stats.
/comscorebeacon.
/condenet-metric.
/connect_counter.js
/content-targeting-staging.js
/contentanalytics/
/contentiq.js
/control/tracking.php?
/cookie.crumb
/cookie/visitor/
/cookie?affiliate
/Cookie?merchant=
/coradiant.js
/core-tracking.js
/coretracking.php?
/count.exe?
/count_stats/
/counter.asp?
/counter.aspx?
/counter.cgi/
/counter.cgi?
/counter.do?
/counter.lt?
/counter.php?chcounter_mode=
/counter.pl?
/counter.visit?
/counter/action_
/counter/article?
/counter/ct.php?
/counter/process.asp?
/counter/r.pl
/counter/stat.
/counter?id=
/counter_1.php
/counter_2.php?
/counter_3.php
/counter_image.gif?
/countercgi.
/countercollector/
/counterFooterFlash.
/countertab.js?
/countstat.php?
/cqcounter.
/crai_tracker.
/criteo.
/criteo_
/criteoRTA.
/crtracker.
/csc-event?
/csm/analytics;
/ctr_tracking.
/custom-tracking.
/cx-video-analytics.js
/cx_tracking.js
/cxense-video/
/cyberestat/
/dc-storm-track.
/dc-storm/track.
/dcs.gif?
/dcstorm-track.
/dcstorm/track.
/demandbase.
/demandbase_
/demdex.js
/deskanalytics.js
/disp_cnt.
/dl_counter.
/dla_tracker.
/dltrack.
/dltrack/
/dmp-tracking-
/dmtracking2.
/dotomi_abandon.
/dotomi_tracking/
/doubleclickCheck/
/dow_analytics.
/downloadAndOutboundLinksTracking.
/drads?referrer=
/dstracking.
/dtmtag.js
/dtrack.js
/dwanalytics-
/dwanalytics.
/e.gif?data=
/ea-analytics/
/eae-logger/
/ecanalytics.js
/ecom/status.jsp?
/econa-site-search-ajax-log-referrer.php
/econa-site-search/log.php?
/ecos-surveycode.
/ecos_survey.
/ecos_surveycode_
/ecossurvey.
/edata.js
/eftracking.
/elex.track.
/elqcfg.js
/elqcfg.min.js
/elqimg.js
/elqnow/
/elqtracking.
/eluminate?
/emstrack.
/endpoint/stats.
/entry.count.image?
/entry_stats?
/estatistica.js
/estatnativeflashtag.swf
/etracker.
/etracker/
/etrackercode.
/eu-survey.js
/ev/co/*?eventid=
/event-log/
/event-report?*&uid=
/event-tracking.js
/event.gif?
/event/*/*?*&euidl=*&url=
/event/pageview?
/event/rumdata?
/event?auditLinkReceived=
/event?pmo=
/event?stat_
/event?t=*&__seed=
/eventLogServlet?
/events?data=
/eventtracker.js
/evtrack-
/ewtrack.
/exaonclick.js
/exelate.htm?
/exelate.html?
/exittracker.
/exittraffic.
/expcount/
/external-promo-metrics.
/external-tracking.
/external/nielsen_
/external_teaser_impression?
/ezytrack.
/fairfax_tracking.js
/fastcounter.
/favcyanalytics?
/fb-app-tracker.
/fb-ga-track-
/fb-tracking.js
/fbanalytics/
/fbcounter/
/fe/track/
/federated-analytics.
/files/ga.js
/finalizestats.
/firestats/
/flash-stats.php?
/flip-stats-queue?
/flv_tracking.
/footer-tracking.js
/footer_tag_iframe.
/footerpixel.gif?
/fora_player_tracking.
/foresee/
/fp/clear.png?
/fpcount.exe
/freecgi/count.cgi?
/frtrack.
/fsrscripts/
/g-track/
/g=analytics&
/g_track.php?
/ga-affiliates.
/ga-beacon.*/UA-
/ga-custom-tracking.
/ga-explorations.
/ga-links.js
/ga-script.
/ga-socialtracker.
/ga-track.
/ga-tracker.
/ga-tracking-
/ga-tracking/
/ga/trackevent.
/ga_anonym.js
/ga_dpc_youtube.
/ga_dualcode_tracking.
/ga_event_frame?
/ga_event_tracking.
/ga_link_tracker_
/ga_outgoinglinks.
/ga_social.
/ga_social_tracking_
/ga_track.php?adurl=
/ga_tracker.
/ga_tracking-
/ga_tracklinks.
/gaaddons-
/gaaddons.js
/gaclicktracking.
/gadsfuncs.
/galinks-
/gallerystats.
/galtracklib.
/ganalytics.
/gapagetracker.
/gascript.
/gasocialtracking.
/gatrack.
/gatracking.
/gatrackingcampaigns/
/gatrackthis.
/gatrackwww.
/gcui_vidtracker/
/generictracking.
/geocc.
/geocounter.
/geoip.html
/geoip?
/geoip_cc
/geoip_script?
/geoipAPI.js?
/get_geoip?
/get_statistics.php?screen_width=
/get_tracking_id?
/getclicky.
/getclicky_
/gifbanner?
/gifstats.
/glbltrackjs.
/global-analytics.js
/global/tracker.
/globalpagetracking.js
/gn_analytics.
/gn_tracking.
/google-analyticator/
/google-analytics-
/google-analytics.
/google-analytics/
/google-nielsen-analytics.
/google.analytics.
/google/analytics.js
/google/analytics_
/google/autotrack.
/google_analitycs.
/google_analytics-bc.swf
/google_analytics.
/google_analytics/
/google_analytics_
/google_page_track
/google_tracker.
/googleana.
/googleAnal.js
/googleanalytics-
/googleanalytics.js
/googleanalytics/
/googleAnalytics1.
/googleAnalytics2.
/GoogleAnalytics?utmac=
/googleAnalytics_
/googleAnalyticsBase_
/googleAnalyticsBottom.
/googleanalyticsmanagement.swf
/googleAnalyticsOutgoingLinks.
/googleAnalyticsTracking.
/googleanalyze1.
/googleanalyze2.
/googletrack.js
/googleTracker.
/googletracker/
/googleTracking.js
/googlytics-
/gosquared-livestats/
/gravity-beacon-
/gravity-beacon.js
/gs-analytics-
/gscounters.
/gtrack.
/gweb/analytics/
/hash_stat_bulk/
/hc_pixel.gif?
/headerpixel.gif?
/headupstats.gif?
/heatmap.*?
/heatmap.js
/heatmap_log.js
/hints.netflame.cc/
/histats/
/hit-counter.
/hit/tracker
/hit_counter
/hit_img.cfm?
/hits/logger?
/hitslink.
/hittrack.cgi?
/horizon.*/track?
/horizon/track?
/hpanalytics_
/hpmetrics.
/hrtrackjs.gif?
/hs_track.
/i?siteid=
/iframe.tracker.js
/iframe_googleAnalytics
/iframetracker.
/IGA.linktagger.
/image.articleview?
/image.ng/
/images/1px.gif?
/images/mxl.gif?
/images/uc.GIF?
/imageTracking.
/img.aspx?q=l3mkwgak
/img.gif?
/img.mqcdn.com/a/a
/img/gnt.gif?
/img/gut.gif?
/img?eid=
/imgcount.cgi?
/imgcount.php?
/imgtracker.
/imp?imgid=
/imp_cnt.gif?
/imp_img.php?
/impression.ashx
/impression.gif?
/impression.js?
/impression.php?
/impression.pl?
/impression.track?
/impression/widget?
/impression_tracker.
/impression_tracking.
/impressioncount.
/impressions/servlet/
/impressions3.asp?
/impressions?
/impressionTrackerV2.
/in.getclicky.com/
/includes/tracker/
/increment_page_counter.
/index.track?
/inetlog.ru/
/insales_counter.
/insert_impressions.
/insitemetrics/
/intellitracker.js
/iperceptions.
/iperceptions/
/iperceptions_
/iporganictrack.
/ips-invite.iperceptions.com/
/istat.aspx?
/itrack.php?
/iva_analytics.
/iva_thefilterjwanalytics.
/ivw_analytics_
/iwstat.js
/javascript/analytics/
/Javascript/ga.js
/javascripts/ga.js
/javascripts/tracking_
/jcaffiliatesystem/
/jquery.analytics.js|
/jquery.google-analytics.
/jquery.trackstar.
/jquery.unica.
/js/analitycs_
/js/analytics.
/js/counter.js?
/js/dart.js
/js/google_stats.
/js/hbx.js
/js/livestats_
/js/logger?
/js/quantcast-
/js/tagging/tagtrack.js
/js/tracking.js
/js/tracking.min.js?
/js/tracking/
/js_hotlink.php?
/js_logger.
/js_tracker.
/jscounter.
/jslogger.php?ref=
/json/stats?
/json/tracking/
/jsonp_geoip?
/jsstat.
/jstatphp.
/jstats.php
/jstats/js/
/jtracking/
/kaiseki/script.php
/kaiseki/track.php?
/kaizentrack/
/keen-tracker.
/keen-tracking-
/kejobscounter.
/keywordlogger.
/khan_analystics.js
/kissmetrics.
/kissmetrics/
/KISSmetricsTrackCode.
/kontera.js
/konterayahoooo.
/krux.js
/leadgen_track
/lib/analytics.
/libs/tracker.js
/link_track.
/link_tracking/
/linkcountdata/
/linkinformer.js
/linktracker.js
/linktracker/
/linktracking.
/livezilla/server.php?request=track&
/load.gif?
/load.js.gz?
/loadcounter.
/loader-counter.
/locotrack.js
/log-ads.
/log/ad-
/log/impression/
/log?data=
/log?event=
/log_event?
/log_impression/
/log_stats.php?
/log_tracker.
/log_view.
/log_zon_img.
/logaholictracker.
/logclick.
/logcollectscript_
/logcounter.
/logevent.action?
/logextrastats.
/logger.ashx?
/logger.dll/
/logger.pageperf?
/logger/?et=
/logger/?referer=
/logger/p.gif?
/logger?d=
/logger?description=
/logging-code.
/logging/pixel?
/logging_requests.
/logging_save.
/loggingService.js
/loggly.tracker.js
/logpstatus.
/logstat.
/logstat?
/lunametrics-
/lycostrack.js
/lzdtracker.
/mail_tracking-cg.php
/mail_tracking.php
/mailstatstrk/
/mapstats.
/marketing-analytics.js
/mbcom.tracking.
/mdwtc/click_thru/
/media_viewed_tracking.
/mediateGA.js
/megacounter/
/mendelstats.
/meta-analytics/
/metatraffic/track.asp?
/metrics-ga.
/metrics.xml
/metrics/ga.html?
/metrics/image.gif?
/metrics/metrics
/metrics/onload
/metrics/stat.
/metrics/survey/
/metrics/vanity/?
/metricsISCS.
/metrika/watch_
/mi/insite/
/mianalytics.
/minder-tracker.
/mindshare-tracking.
/mintstats/?js
/mistats/
/mixpanel_beacon.
/mixpanel_tracker.
/mktg_metrics/
/ml.track.me?
/mlopen_track.
/mm-metrics.
/mm_track/
/mngi/tracking/
/mobify_ga.gif
/mobileanalytics.
/modoweb-tracking/
/module/analytics/
/momentum-tracking/
/mouseover-tracker.
/mpf-mediator.
/mstartracking/
/mstats.
/mstrack/
/mtrack.nl/js/
/mtracking.
/mtvi_reporting.js
/myasg/stats_js.asp
/mycounter/counter_in.php?
/myImage.track?
/myopslogger.
/mystats.asp?
/mystats/track.js
/mystats2.px?
/nbc-stats/
/nedstat.
/neocounter.
/neocounter/
/netcounter?
/netizen_track.
/netstat.
/nettracker.js
/nettracker/
/neustar.beacon.
/new.cnt.aspx?
/newstat/
/newstatsinc.
/nextPerformanceRetargeting.
/nielsen.htm
/nielsen.js
/nielsen.min.
/nielsen.track
/nielsen_geotarget/
/nielsen_v53.
/nielson/track
/nielson_stats.
/ninemsn.tracking.
/nm_track.js
/no-impression.gif?
/npssurvey.
/ntpagetag-
/ntpagetag.
/ntpagetag_
/ntpagetaghttps.
/ntrack.asp?
/oas_analytics.
/object_stats.
/ocounter.
/olx/tracker.
/om_ctrack.
/om_tracking_
/omnidiggthis|
/omnipagetrack.
/omniture/tracking.
/oms_analytics_
/onestat.js
/onsitegeo.
/opentag-
/opentag/
/openxtargeting.js
/opinionlab.js
/optimost-
/optimost.
/optimost_
/optimostBody1.
/optimostBody2.
/optimostfoot.
/optimosthead.
/optimosthead/
/optimostHeader.
/optimostHeader1.
/optimostHeader2.
/ordertrack/
/ovstats.
/ow_analytics.
/owa.tracker-combined-min.js
/ox_stats.
/oxtracker.
/page-analytics.
/page-track.
/page_analytics.
/page_counter.
/pageeventcounter;
/pagelogger/connector.php?
/pageloggerobyx.
/pagestat?
/pagestats/
/pagetrack.php?
/pageviews-counter-
/pageviews_counter.
/pbasitetracker.
/performance_tracker-
/permalink-tracker.html?
/pgtracking.
/pgtrackingV3.
/php-stats.js
/php-stats.php?
/php-stats.phpjs.php?
/php-stats.recjs.php?
/phpmyvisites.js
/ping.gif?
/ping_hotclick.js
/pistats/cgi-bin/
/piwik.php
/piwik1.
/piwik2.js
/piwik_
/piwikapi.js
/piwikC_
/piwikTracker.
/pix.gif?
/pixall.min.js
/pixel-events.
/pixel-page.html
/pixel.*/track/*
/pixel.gif?
/pixel.png?
/pixel.track2?
/pixel.track?
/pixel/?__tracker
/pixel/img/
/pixel/impression/
/pixel/visit?
/pixel1/impression.
/pixel?google_
/pixel_iframe.
/pixel_track.
/pixel_tracking.
/pixelcounter.
/PixelNedstat.
/pixelstats/
/pixeltrack.php?
/pixeltracker.
/pixeltracking/
/pladtrack.
/planetstat.
/player_counter.ashx?
/PlayerDashboardLoggingService.svc/json/StartSession?
/playerlogger.
/playerstats.gif?
/playertracking/
/plgtrafic.
/plingatracker.
/pluck-tracking.
/plugins/stat-dfp/
/plugins/status.gif?
/plugins/wordfence/visitor.php?
/popanalytics.
/popupCookieWriter.
/popuplog/
/pphlogger.
/printtracker.js
/prnx_track.
/probance_tracker.
/prodtracker?
/profile_tracker.
/promo_tracking/
/prum.
/pstats.
/ptrack.
/public/visitor.json?
/public/visitor/create?
/pubstats.
/pvcounter.
/pvcounter/
/pvcounter?
/pvevent_
/pview?event
/pxa.min.js
/pzn/proxysignature
/qtracker-
/quant.js
/quant.swf?
/quantcast.js
/quantcast.xml
/quantcast/
/quantcast_
/quantcastjs/
/quantserve.com/
/quantv2.swf?
/qubittracker/
/ra_track.
/rcdntpagetag.js
/readcounter.aspx?
/readtracker-
/recommendtrack?
/record-impressions.
/record_clicks.
/record_visitor.
/recstatsv2.
/redirectexittrack.php?
/ref_analytics.
/refer-tracking.
/referral_tracker.
/referral_tracking.
/referrer_tracking.
/refstats.asp?
/reg_stat.php?
/register_stats.php?
/register_video_*&server=
/registeradevent?
/remoteTrackingManager.cfc?*trackPage&
/render?trackingId=
/repdata.*/b/ss/*
/report?event_
/reporting/analytics.js
/resmeter.js
/resourcestat.
/rest/analytics/
/restats_
/resxclsa.
/resxclsa_
/retargetingScript/
/revsci.
/revtracking/
/rkrt_tracker-
/roi_tracker.
/roitrack.
/roitracker.
/roitracker2.
/rolluptracker_
/rtkbeacon.gif?
/rtracker.
/rtt-log-data?
/rubics_trk
/rubicsimp/c.gif?
/rum-dytrc.
/rum-track?
/rum/id?
/rumstat.
/runtimejs/intercept/
/sage_tracker.
/save_stats.php?
/savetracking?
/sb.logger.js
/sb.trackers.js
/sbtracking/pageview2?
/sclanalyticstag.
/scmetrics.*/b/ss/*
/script/analytics.
/script/analytics/
/script_log.
/scriptAnalytics.
/scripts.kissmetrics.com/
/scripts/analytics.
/scripts/analytics_
/scripts/clickjs.php
/scripts/contador.
/scripts/ga.js
/scripts/hbx.js
/scripts/log.
/scripts/statistics/
/scripts/stats/
/scripts/xiti/
/sctracker.
/sdxp1/dru4/meta?_hc=
/securetracker.
/send-impressions.html
/sensor/statistic?
/seosite-tracker/
/seostats/
/seotracker/
/server.php?request=track&output=
/services/analytics/
/services/counter/
/services/counters/
/session-hit.
/session-tracker/tracking-
/sessioncam/
/set_tracking.js
/shareCounts.
/shareTrackClient.
/shinystat.
/shinystat_
/shopify_stats.js
/showcounter.
/si-tracking.
/sidtracker.
/sikcomscore_
/sikquantcast_
/silverpop/
/simplereach_counts/
/simtracker.min.js
/siq-analytics.
/site-tracker-
/site-tracker.
/site-tracker_
/site_statistics.
/site_stats.
/site_stats/
/site_tracking.
/siteAnalytics-
/siteAnalytics.
/siteanalytics_
/sitecatalist.js
/sitecounter/counter.
/sitecrm.js
/sitecrm2.js
/siteskan.com/
/sitestat.
/sitestat_
/sitestatforms.
/sitestats.gif?
/sitetracker21.
/sitetrek.js
/skstats-
/skstats_
/skype-analytics.
/slimstat/
/smetrics.*/b/ss/*
/social_tracking.
/socialButtonTracker.
/socialtracking.min.js
/softclick.js
/softpage/stats_registerhit.asp?
/sometrics/
/sophus/logging.js
/sophus3_logging.js
/sp-analytics-
/sp_logging.
/sp_tracker.
/spannerworks-tracking-
/spip.php?page=stats.js
/springmetrics.
/sstat_plugin.js
/stat-analytics/
/stat.aspx?
/stat.gif?
/stat.htm?
/stat.js?
/stat.php?
/stat.png?
/stat.tiff?
/stat/ad?
/stat/count
/stat/event?
/stat/fe?
/stat/inserthit.
/stat/track.php?mode=js
/stat/track_
/stat/tracker.
/stat/uvstat?
/stat2.aspx?
/stat2.js
/stat36/stat/track.php
/stat?sid=
/stat?SiteID=
/stat?track=
/stat_js.asp?
/stat_page.
/stat_page2.
/stat_search.
/stat_visits.
/stat_vue.php?
/stataffs/track.php?
/statcapture.
/statcollector.
/statcount.
/statcounter.asp
/statcounter.js
/statcountex/count.asp?
/stateye/
/static/tracking/
/statics/analytics.js?
/statistics-page-view/
/statistics.asp?
/statistics.aspx?profile
/statistics.js?
/statistics/fab.
/statistics/ga.
/statistics/get?
/statistics/getcook.php?
/statistics/imr.
/statistics/logging/
/statistics/metrica.
/statistics/pageStat/
/statistics/set?
/statistics?counter=
/statistics?eventType=
/statlogger.
/stats-js.cgi?
/stats-tracking.js
/stats.asp?id
/stats.gif?
/stats.hitbox.com/
/stats.php?*http
/stats.php?type=
/stats.php?uri=
/stats/?js
/stats/?ref=
/stats/add/
/stats/adonis_
/stats/collector.js
/stats/counter.
/stats/CounterPage.
/stats/dlcount_
/stats/et_track.asp?
/stats/ga.
/stats/impression
/stats/imr.
/stats/init.
/stats/log.
/stats/mark?
/stats/metrica.
/stats/metrics/
/stats/mixpanel-
/stats/page_view_
/stats/pgview.
/stats/ping?
/stats/record.php?
/stats/services/
/stats/track.asp?
/stats/tracker.gif?
/stats/tracker.js
/stats/welcome.php?
/stats?aid=
/stats?blog_
/stats?callback=
/stats?ev=
/stats?object
/stats?sid=
/stats_blog.js?
/stats_brand.js
/stats_js.asp?
/stats_tracker.
/statsadvance.js
/statscounter/
/statscript.js
/statsd_proxy
/statspider?
/statspixel.
/statstracker?
/statsupdater.
/stattracker-
/stracking.js
/stt/track.
/stt/track/
/stwc-counter/
/supercookie.
/superstats.
/supertracking.
/surphace_track.
/survey_invite_
/surveyoverlay/
/swfaddress.js?tracker=
/syndication/metrics/
/syndstats.
/tacoda.
/tacoda_
/taevents-
/tbuy/tracker/
/tc_logging.js
/tc_targeting.
/tc_throttle.js
/tealium.js
/textlink.php?text
/thbeacon/
/thetracker.js
/third-party-analitycs/
/third-party-stats/
/third-party/tracking.
/thirdpartyCookie.
/tiara/tracker/
/tide_stat.js
/timeslog.
/tmpstats.gif?
/tncms/tracking.js
/tops-counter?
/touchclarity/
/tpix.gif?
/tracciamento.php?
/track-compiled.js
/track-referrals.js
/track.ads/
/track.ashx?*=http
/track.aspx?
/track.cgi?
/track.gif?
/track.js?referrer
/track.js?screen=
/track.php?*&uid=
/track.png?
/track.srv.
/track/*&CheckCookieId=
/track/?site
/track/a.gif?
/track/aggregate?
/track/component/
/track/count*js
/track/dot.gif?
/track/event/
/track/imp?
/track/impression/
/track/impression?
/track/jsinfo
/track/mygreendot/
/track/pix.asp?
/track/pixel.
/track/pixel/
/track/read/
/track/site/
/track/track-
/track/track.php?
/track/view/
/track/visitors/?
/track/visits/?
/track2.php
/track;adv
/track?browserId
/track?event=
/track?referer=
/track_clicks_
/track_event.php?
/track_js/?
/track_metric/
/track_pageview?
/track_proxy?
/track_social.
/track_stat?
/track_views.
/track_visit.
/track_visit?
/trackad.
/trackAdHit.
/trackClickEvent.js
/trackContentViews.
/trackconversion?
/tracker-config.js
/tracker-ev-sdk.js
/tracker-pb-min-rem.js
/tracker-r1.js
/tracker.do?
/tracker.js.php?
/tracker.json.php?
/tracker.log?
/tracker.min.js
/tracker.pack.
/tracker.php?
/tracker.pl?
/tracker.tsp?
/tracker/aptimized-
/tracker/event?
/tracker/eventBatch/
/tracker/imp?
/tracker/index.jsp?
/tracker/log?
/tracker/p.gif?
/tracker/ping/
/tracker/receiver/
/tracker/referrer/
/tracker/story.jpg?
/tracker/t.php?
/tracker/track.php?
/tracker/tracker.js
/tracker2.js
/tracker?*=
/tracker_activityStream.
/tracker_article
/tracker_czn.tsp?
/tracker_gif.
/tracker_pageview.
/tracker_pixel.
/trackerGif?
/trackerpixel.js
/trackerstatistik.
/trackEvent.js?
/trackEvent.min.js?
/trackga.
/trackGAEvents.
/trackhandler.ashx?
/trackimage/
/trackImpression/
/trackimps?
/tracking-active/
/tracking-ad/
/tracking-cookie.
/tracking-hits.
/tracking-info.gif?
/tracking-init.
/tracking-pixel.
/tracking-pixel/
/tracking-portlet/
/tracking-v3.
/tracking-widget.
/tracking.ashx?
/tracking.cgi?
/tracking.fcgi?
/tracking.gif?
/tracking.jsp
/tracking.php?id
/tracking.php?q=
/tracking.phtml?
/tracking.relead.
/tracking.vidt
/tracking/*/agof-
/tracking/addview/
/tracking/adobe.js
/tracking/ads.
/tracking/article.
/tracking/article/
/tracking/at.js
/tracking/beacon/?
/tracking/clicks
/tracking/create?
/tracking/csp?
/tracking/epixels.
/tracking/fingerprint/
/tracking/impression/
/tracking/index.
/tracking/log.php?
/tracking/open?
/tracking/pageview.
/tracking/pixel.
/tracking/pixel/
/tracking/pixel_
/tracking/pixels.
/tracking/referrer?
/tracking/setTracker/
/tracking/simplified_
/tracking/t.srv?
/tracking/tag_commander.php?
/tracking/track.jsp?
/tracking/track.php?
/tracking/tracking.
/tracking/tracking_
/tracking/trk-
/tracking/tynt_
/tracking/user_sync_widget?
/tracking/views/
/tracking/widget/
/tracking202/
/tracking_add_ons.
/tracking_ajax.
/tracking_clic.
/tracking_clickevents.
/tracking_cookie_baker.
/tracking_frame_
/tracking_headerJS_
/tracking_id_
/tracking_iframe.
/tracking_link_cookie.
/tracking_pix.
/tracking_pixel
/tracking_super_hot.js
/trackingCode-
/trackingCode.js
/trackingcookies.
/trackingDTM.js
/trackingfilter.json?
/trackingFooter.
/trackingheader.
/trackingImpression/
/trackingp.gif
/trackingPixel.
/trackingPixelForIframe.
/trackingpixels/get?referrer=
/trackings/addview/
/trackingScript1.
/trackingScript2.
/trackingService.min.js
/trackingService/
/trackIt.js
/trackit.php?
/trackit.pl?
/trackjs.
/trackjs1.
/trackjs6.
/trackjs_
/trackmerchant.js
/tracknat.
/trackopen.cgi?
/trackpagecover?
/trackpageview.
/trackPageView/
/trackpidv3.
/trackpix.
/trackpixel.
/trackpxl?
/trackr.swf
/trackstats?
/tracksubprop.
/trackTimings.gif?
/trackuity.
/TrackView/?track
/trackVisit/
/trackvisit?
/traffic.asmx/
/traffic/status.gif?
/traffic/track^
/traffic4u.
/traffic_link_client.php?
/traffic_record.php?
/traffic_tracker.
/traffictracker.
/traffictrade/
/traffix-track.
/trafic.js
/trakksocial.js
/trans_pixel.asp
/transparent1x1.
/traxis-logger.
/triggertag.js
/triggit-analytics.
/trkpixel.gif
/trovit-analytics.js
/truehits.php?
/tse/tracking.
/turn-proxy.html?
/tw-track.js
/tynt.js
/udctrack.
/uds/stats?
/ui/analytics/
/ultra_track/
/universal-tracking-
/urchinstats.
/userfly.js
/usertrack.aspx?
/usertracking.js
/usertrackingajax.php?
/usr.gif?openratetracking=
/utag.ga.
/utag.loader-
/utag.loader.
/utrack.js?
/utrack?
/utracker.js
/uvstat.js
/uxm_tracking.
/valueclickbrands/
/vanillastats/
/vblntpagetag.
/vertical-stats.
/vglnk.js
/video_count.php?
/videoanalytic/
/videoAnalytics.
/videolog?vid=
/videotracking/
/vidtrack.
/view_stats.js.php
/viewcounterjqueryproxy.
/viewcounterproxy.
/viewstats.aspx?
/viewtracking.aspx?
/viglink_
/vip-analytics.
/viperbar/stats.php?
/visistat.js
/visit-tracker.js
/visit.gif?
/visit/log.js?
/visit/record.gif?
/visit?id=
/visit_pixel?
/visit_tracking.
/visitor-event?
/visitor.cgi?aff
/visitor.gif?ts=
/visitor.js?key=
/visitor.min.js
/visitor/identity?
/visitor/segment?*=
/visitorCookie.
/visitortrack?
/visitortracker.pl?
/visits/pixel?
/visits_contor.
/visitWebPage?_
/visualstat/stat.php
/vmtracking.
/vpstats.
/vptrack_
/vs-track.js
/vs/track.
/vs_track.
/vstat.php
/vstats/counter.php
/vstrack.
/vtrack.aspx
/vtrack.php?
/vtracker.
/vztrack.gif?
/wanalytics/
/wdg/tracking-
/wdg_tracking-
/web-analytics.
/web_analytics/
/web_traffic_capture.js
/webanalytics3.
/webcounter/
/webiq.
/webiq/
/webiq_
/weblog.*?cookie
/weblog.js?
/weblog.php?
/weblog/*&refer=
/weblog_*&wlog_
/webmetricstracking.
/webstat/cei_count.asp?
/webstat_
/webstatistics.php?
/webstatistik/track.asp
/webstats.js
/webstats.php
/webstats/index?
/webstats/stat
/webstats/track.php?
/webstats_counter/
/webtrack.
/webtracker.
/webtraffic.js
/wholinked.com/track
/whoson_*_trackingonly.js
/widget/s.gif?
/wjcounter-
/wjcounter.
/wjcountercore.
/wlexpert_tracker.
/wlexpert_tracker/
/wmxtracker.js
/woopra.js
/worldwide_analytics/
/wp-click-track/
/wp-clickmap/
/wp-content/plugins/stats/count.php?
/wp-content/tracker.
/wp-counter.php
/wp-js/analytics.
/wp-powerstat/
/wp-slimstat/
/wp_stat.php?
/wprum.
/wrapper/quantcast.swf
/written-analytics.
/wstat.pl
/wstats.php?
/wtbase.js
/wtcore.js
/wtid.js
/wtinit.js
/wysistat.js
/wz_logging.
/xiti.js
/xitistatus.js
/xn_track.
/xstat.aspx?
/xtanalyzer_roi.
/xtclick.
/xtclicks.
/xtclicks_
/xtrack.php?
/xtrack.png?
/yahoo-beacon.js
/yahoo_marketing.js
/yahooBeacon.
/yahooTracker/
/ybn_pixel/
/yell-analytics-
/yell-analytics.
/youtube-track-event_
/ystat.do
/ystat.js
/zag.gif?
/zemtracker.
/ztagtrackedevent/
/~utm_gif?
;manifest-analytics.js
=ATAtracker&
=googleanalytics_
=stats&action=
=stats&apiVersion=
=track_view&
=widgetimpression&
?&anticache=*filename.gif
?_siteid=
?act=counter&
?action=event&
?action=track_visitor&
?action=tracking_script
?bstat=
?criteoTrack=
?event=General.track
?event=log&
?eventtype=impression&pid=
?eventtype=request&pid=
?googleTrack=
?hmtrackerjs=
?log=stats&
?ref=*&itemcnt=
?token=*&sessionid=*&visitorid=
?trackingCategory=
?triggertags=
^name=atatracker^
_247seotracking.
_analytics.php?
_astatspro/
_beacon?
_cedexis.
_chartbeat.js
_clickability/
_clicktrack.asp?
_clickTracking.
_directtrack.js
_event_stats.
_global_analytics_
_google_analytics.
_googleAnalytics.
_googleAnalytics_
_imp_logging?
_impressions.gif?
_logimpressions.
_m10banners/tracking.php?
_metricsTagging.
_minder_tracking/
_nedstat.js
_nielsen.js
_ntpagetag.
_pages_tracker.
_performance_tracker-
_quantcast.swf
_quantcast_tag.
_resource/analytics.js
_social_tracking.
_stat_counter.php?
_stats.js?
_stats/Logger?
_stats_log.
_tracker-active/
_tracker.js.
_tracker.js?
_tracker.php?*http
_tracker_min.
_trafficTracking.
_url_tracking.
_web_stat.js
_webanalytics.
_webiq.
cgi-bin/counter
-logabpstatus.
/adblock?action=
_adblock_stat.
_mongo_stats/
/cdn-cgi/pe/bag2?*.google-analytics.com
/cdn-cgi/pe/bag2?*bluekai.com
/cdn-cgi/pe/bag2?*bounceexchange.com
/cdn-cgi/pe/bag2?*cdn.onthe.io%2Fio.js
/cdn-cgi/pe/bag2?*chartbeat.js
/cdn-cgi/pe/bag2?*dnn506yrbagrg.cloudfront.net
/cdn-cgi/pe/bag2?*geoiplookup
/cdn-cgi/pe/bag2?*getblueshift.com
/cdn-cgi/pe/bag2?*google-analytics.com%2Fanalytics.js
/cdn-cgi/pe/bag2?*histats.com
/cdn-cgi/pe/bag2?*hs-analytics.net
/cdn-cgi/pe/bag2?*log.outbrain.com
/cdn-cgi/pe/bag2?*mc.yandex.ru
/cdn-cgi/pe/bag2?*newrelic.com
/cdn-cgi/pe/bag2?*nr-data.net
/cdn-cgi/pe/bag2?*optimizely.com
/cdn-cgi/pe/bag2?*piwik.js
/cdn-cgi/pe/bag2?*quantserve.com
/cdn-cgi/pe/bag2?*radarurl.com
/cdn-cgi/pe/bag2?*scorecardresearch.com
/cdn-cgi/pe/bag2?*static.getclicky.com%2Fjs
/cdn-cgi/pe/bag2?*viglink.com
/cdn-cgi/pe/bag2?*yieldbot.intent.js`;
var bad_url_parts_flag = 1941 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 0 rules:
var good_url_regex = "";
var good_url_regex_flag = 0 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// 0 rules:
var bad_url_regex = "";
var bad_url_regex_flag = 0 > 0 ? true : false;  // save #rules, then delete this string after conversion to hash or RegExp

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\w*+-]{2,15}):\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]+)(\\??[\\S]*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24}\\.?)", "i");
var slashend_RegExp = RegExp("\\/$", "i");

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

var domain_anchor_RegExp = RegExp("^\\|\\|");
// performance: use a simplified, less inclusive of subdomains, regex for domain anchors
// also assume that RexgExp("^https?//") stripped from url string beforehand
//var domain_anchor_replace = "^(?:[\\w\-]+\\.)*?";
var domain_anchor_replace = "^";
var n_wildcard = 1;
function easylist2re(pat,offset) {
    function tr(pat) {                                                          
        return pat.replace(/[/.?+@^|]/g, function (m0, mp, ms) {  // url, regex, EasyList special chars
            // res = m0 === '?' ? '[\s\S]' : '\\' + m0;                   
            // https://adblockplus.org/filters#regexps, separator '^' == [^\w.%-]
            var res = '\\' + m0;
            switch (m0) {
            case '^':
                res = '[^\\w-]';
                break;
            case '|':
                res = mp + m0.length === ms.length ? '$' : '^';
                break;
            default:
                res = '\\' + m0;  // escape special characters
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
        return '(?=([\\s\\S]*?' + tr(m0.substr(1)) + eos + '))\\' + n_wildcard++;
    });
    return pat;
}

// inclusive example -- step through at regex101.com to decode
// var res = easylist2re('||' + 'a*'.repeat(2) + 'b.com/?q=1^ad_box_|')
// console.log(res);
// ^(?:https?:\/\/){0,1}(?:[\w\-]+\.)*[^\w\-]?a(?=([\s\S]*?a))\1(?=([\s\S]*?b\.com\/\?q=1[^\w-]ad_box_$))\2

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
var good_da_host_RegExp = new RegExp(domain_anchor_replace + "(?:" + good_da_host_regex.split("\n").map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_da_hostpath_RegExp = new RegExp(domain_anchor_replace + "(?:" + good_da_hostpath_regex.split("\n").map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_da_RegExp = new RegExp(domain_anchor_replace + "(?:" + good_da_regex.split("\n").map(easylist2re).join("|") + ")", "i");

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_da_host_RegExp = new RegExp(domain_anchor_replace + "(?:" + bad_da_host_regex.split("\n").map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_da_hostpath_RegExp = new RegExp(domain_anchor_replace + "(?:" + bad_da_hostpath_regex.split("\n").map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_da_RegExp = new RegExp(domain_anchor_replace + "(?:" + bad_da_regex.split("\n").map(easylist2re).join("|") + ")", "i");

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_url_parts_RegExp = new RegExp("(?:" + good_url_parts.split("\n").map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_url_parts_RegExp = new RegExp("(?:" + bad_url_parts.split("\n").map(easylist2re).join("|") + ")", "i");

n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var good_url_regex_RegExp = new RegExp("(?:" + good_url_regex.split("\n").map(easylist2re).join("|") + ")", "i");
n_wildcard = 1;  // reset n_wildcard for concatenated patterns
var bad_url_regex_RegExp = new RegExp("(?:" + bad_url_regex.split("\n").map(easylist2re).join("|") + ")", "i");

// Post-processing: Dereference large strings (perhaps unnecessarily) to allow garbage collection
good_da_host_regex = null;
good_da_hostpath_regex = null;
good_da_regex = null;
bad_da_host_regex = null;
bad_da_hostpath_regex = null;
bad_da_regex = null;
good_url_parts = null;
bad_url_parts = null;
good_url_regex = null;
bad_url_regex = null;

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

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ) {
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

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
            (use_pass_rules_parts_flag &&
                (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                // test logic: only do the slower test if the host has a (non)suspect fqdn
                (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                (good_url_parts_flag && good_url_parts_RegExp.test(url_pathonly)) ||
                (good_url_regex_flag && good_url_regex_RegExp.test(url))) ) {
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
