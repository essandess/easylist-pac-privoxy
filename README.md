# easylist-pac-privoxy
EasyList Tracker and Adblock Rules to Proxy Auto Configuration (PAC) File and Privoxy Actions and Filters

Converts [EasyList](https://easylist.to/index.html) tracker and ad blocking rules to efficient filter blocks in a [proxy.pac](https://raw.githubusercontent.com/essandess/easylist-pac-privoxy/master/proxy.pac) file for automatic proxy network configurations and [Privoxy](http://www.privoxy.org) proxy servers.

## Proxy Auto Configuration (PAC)

Using EasyList rules in a in a [proxy.pac](https://raw.githubusercontent.com/essandess/easylist-pac-privoxy/master/proxy.pac) file provides these benefits:

* Tracker and Ad blocking performed in all clients that use PAC files, browsers and non-browsers alike.
* Tracker and Ad blocking on both desktop and mobile devices, especially via [VPN](../../../essandess/osx-openvpn-server).
* Browser plugins or filtering proxies are not necessarily used (although PAC files work well in sequence with these).
* PAC files do not alter the webpage DOM, used by adblock detection methods.

The script `easylist_pac.py` downloads EasyList and EasyPrivacy [rules](https://adblockplus.org/filter-cheatsheet) and converts these to a combination of very efficient Javascript hash lookups and efficient NFA regular expressions. The size of the PAC file and rulesets are limited in the posted example to a total of over fifteen thousand (18788) to ensure efficient execution on modern mobile devices. For full rulesets, use in conjunction with a browser plugin and/or Privoxy. 

Example hash (exact match) blocking entries look like:

```
"tracker.myseofriend.net"
"adwiretracker.fwix.com"
```

Example regular expression blocking rules look like:

```
online.*/promoredirect?key=
secureprovide1.com/*=tracking
```

### Running

```
python3 easylist_pac.py
```

The new file [proxy.pac](https://raw.githubusercontent.com/essandess/easylist-pac-privoxy/master/proxy.pac) will be created in the (default `~/Downloads` directory. See `easylist_pac.py -h` for options.

## Privoxy

Under development. See [here](../../../../skroll/privoxy-adblock/issues/11) for related issues.
