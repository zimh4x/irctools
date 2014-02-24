* ho_qoper_rsa.pl -- for use with "hotools" aka "HOSC" or "hybrid oper script collection."  HOSC was primarily/originaly authored by garion and is found here:  http://garion.org/hosc/.  ho_qoper_rsa.pl is intended to work with the ratbox-ircd's RSA CHALLENGE/RESPONSE style of authentication for opering up.  It requires that the user's irc client be able to execute a ratbox-respond binary (located here: http://svn.ratbox.org/svnroot/respond/trunk/ratbox-respond/)

* ho_reformat.data -- this is a supplemental file to the ho_reformat.pl script included with HOSC.  It re-writes server messages for a number of the major IRC networks.  Originally, I received this file from Exstatica, but I believe may have had many contributors.  I have modified this version for several items specific to my use cases, but its content has proved valuable on numerous networks.

* ho_reject_invalid.pl -- this file assumes the client is an operator on a ratbox ircd network, and is utilizing umode +r to see rejected clients.  Clients who "hammer" with invalid usernames which break the RFC can be banned with a configured reason based on failing to connect in an RFC-compliant manner N times in T seconds.

* ho_reject_throttle.pl -- this file assumes the client is an operator on a ratbox ircd network, and is utilizing umode +r to see rejected clients.  By default, ratbox 3.x will notify aforementioned opered clients that an IP address was 'throttled' by the server as it attempted to connect.  This is typically a result of the same IP attempting to connect 4 times in 60 seconds and failing to do so, generally because the client is misconfigured or altogether not "speaking" irc protocol over the wire.  This script can temporarily ban such clients based on N throttle notifications in T seconds with a configurable message.

* klines.py and testmask.py -- are intended to quickly convert large lists of hosts into copy/pastable commands for use on hybrid or ratbox ircds.  They are essentially the same function but different commands.  I found it easier/faster to react, to just have two scripts instead of editing the same one each time.


more to come in this repo as I dig through years of little hacked together tools over various shell and colo archives of min.!  -zz
