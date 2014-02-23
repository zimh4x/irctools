# ho_reject.pl
#
# $Id: ho_reject.pl,v 1.5 2004/09/11 12:21:49 jvunder REL_0_3 $
#
# Part of the Hybrid Oper Script Collection.
#
# Looks for rejecting clients and acts upon them.
#
# TODO: code HOSC::Kliner and use it.

use strict;
use vars qw($VERSION %IRSSI $SCRIPT_NAME);

use Irssi;
use Irssi::Irc;
use HOSC::again;
use HOSC::again 'HOSC::Base';
use HOSC::again 'HOSC::Tools';
import HOSC::Tools qw{is_server_notice};

# ---------------------------------------------------------------------

($VERSION) = '$Revision: 1.0 $' =~ / (\d+\.\d+) /;
%IRSSI = (
    authors     => 'zimzum',
    contact     => 'zimzum@rizon.net',
    name        => 'ho_reject',
    description => 'Looks for rejecting or throttled rejected clients and acts upon them.',
    license     => 'Public Domain',
    url         => 'n/a',
    changed     => 'Wed Jan  2 19:38:27 PST 2013',
);
$SCRIPT_NAME = 'ThrottleReject';

# Hashtable with connection times per host
# Key is the host
# Value is an array of connection times (unix timestamp)
my %conntimes;

# The last time the connection hash has been cleaned (unix timestamp)
my $conntimes_last_cleaned = 0;


# ---------------------------------------------------------------------
# A Server Event has occurred. Check if it is a server NOTICE;
# if so, process it.

sub event_serverevent {
    my ($server, $msg, $nick, $hostmask) = @_;

    return unless is_server_notice(@_);

    process_event($server, $msg);
}


# ---------------------------------------------------------------------
# This function takes a server notice and matches it with a few regular
# expressions to see if any special action needs to be taken.

sub process_event {
    my ($server, $msg) = @_;

    #throttled client
    if ($msg =~ /Adding throttle for (.*)/) {
        process_throttle($server, $1);
        return;
    }

    # Invalid Username
    # nick, host, username
    #if ($msg =~ /Invalid username:\s(.*)\s\((.*)\).*/) {
    #    process_invalid_user($server, $1, $2, $3);
    #    return;
    #}
}

sub process_throttle {
        my ($server, $ip) = @_;
        return unless Irssi::settings_get_bool('ho_reject_throttleban_enable');
        return if $ip eq '255.255.255.255' && Irssi::settings_get_bool('ho_reject_ignore_spoofs');
        my $tag = $server->{tag};

        my $watch_this_network=0;
        foreach my $network (split /\s+/,lc(Irssi::settings_get_str('ho_reject_throttle_network_tags')))
        {
                if ($network eq lc($server->{tag}))
                {
                        $watch_this_network=1;
                }
        }
        return unless $watch_this_network;

        my $now = time();
        push @{ $conntimes{$tag}->{$ip} }, $now;

        if ( @{ $conntimes{$tag}->{$ip} } >= Irssi::settings_get_int('ho_reject_throttleviolation_count') )
        {
                my $firsttime = ${ $conntimes{$tag}->{$ip} }[0];
                my $lasttime = ${ $conntimes{$tag}->{$ip} }[@{ $conntimes{$tag}->{$ip} } - 1];
		my $timediff = $lasttime - $firsttime;


                if ($timediff <= Irssi::settings_get_int('ho_reject_throttleviolation_time'))
                {
                        my $time = Irssi::settings_get_int('ho_reject_throttle_dline_time');
                        my $reason = Irssi::settings_get_str('ho_reject_throttle_dline_reason');
			my $throttlecount = @{ $conntimes{$tag}->{$ip} };
			my $throttletime = $timediff;

                        # src ip is officially annoying exceeding throttle count per time settings
			$server->command("quote dline $time $ip :$reason");
                        ho_print("Throttling violation: D-lined $ip for $throttlecount throttles in $throttletime seconds.");
		}

        }

	#cleanup hashtable every 60 seconds
	if ($now > $conntimes_last_cleaned + 60) {
        	$conntimes_last_cleaned = $now;
        	cleanup_conntimes_hash(2400);
    	}
}


# ---------------------------------------------------------------------
# Cleans up the connection times hash.
# The only argument is the number of seconds to keep the hostnames for.
# This means that if the last connection from a hostname was longer ago
# than that number of seconds, the hostname is dropped from the hash.

sub cleanup_conntimes_hash {
    my ($keeptime) = @_;
    my $now = time();

    # If the last time this host has connected is over $keeptime secs ago,
    # delete it.
    for my $tag (keys %conntimes) 
    {
        for my $ip (keys %{ $conntimes{$tag} }) 
	{
            my $lasttime = ${ $conntimes{$tag}->{$ip} }[@{ $conntimes{$tag}->{$ip} } - 1];

            # Discard this host if no connections have been made from it during
            # the last $keeptime seconds.
            if ($now > $lasttime + $keeptime) {
                delete $conntimes{$tag}->{$ip};
            }
        }
    }
}

# ---------------------------------------------------------------------
# The /reject command.

sub cmd_reject {
    my ($data, $server, $item) = @_;
    if ($data =~ m/^[(help)]/i ) {
        Irssi::command_runsub ('throttle', $data, $server, $item);
    } else {
        ho_print("Use /throttle HELP for help.")
    }
}

# ---------------------------------------------------------------------
# The /reject help command.

sub cmd_reject_help {
    print_help();
}

# ---------------------------------------------------------------------

ho_print_init_begin();

Irssi::signal_add_first('server event', 'event_serverevent');

Irssi::command_bind('throttle',      'cmd_reject');
Irssi::command_bind('throttle help', 'cmd_reject_help');

Irssi::settings_add_bool('ho', 'ho_reject_throttleban_enable',		0);
Irssi::settings_add_bool('ho', 'ho_reject_ignore_spoofs',     1);
Irssi::settings_add_int('ho', 'ho_reject_throttleviolation_count',   10);
Irssi::settings_add_int('ho', 'ho_reject_throttleviolation_time',   120);
Irssi::settings_add_int('ho', 'ho_reject_throttle_dline_time',      1440);
Irssi::settings_add_str('ho', 'ho_reject_throttle_network_tags',      '');
Irssi::settings_add_str('ho', 'ho_reject_throttle_dline_reason',
    '[Automated D-line] Reconnecting too fast without speaking IRC protocol.');

if (length Irssi::settings_get_str('ho_reject_throttle_network_tags') > 0) {
        if (Irssi::settings_get_bool('ho_reject_throttleban_enable')) {
                ho_print("Script enabled for the following tags: " .
                        Irssi::settings_get_str('ho_reject_throttle_network_tags'));
        } else {
                ho_print("Script disabled. The following tags have been set: " .
                        Irssi::settings_get_str('ho_reject_throttle_network_tags') .
                        ". Use /SET ho_reject_throttleban_enable ON to enable the script.");
        }
} else {
        ho_print_warning("No network tags set. Please use ".
                "/SET ho_reject_throttle_network_tags tag1 tag2 tag3 .. ".
                "to choose the tags the script will work on.");
}

ho_print_init_end();
ho_print("Use /throttle HELP for help.");

# ---------------------------------------------------------------------

sub print_help {
    ho_print_help('head', $SCRIPT_NAME);

    ho_print_help('section', 'Description');
    ho_print_help("This script tracks reconnecting clients and can take action on ".
        "them, being either printing a warning or banning them from the server ".
        "automatically. Clients that reconnect rapidly are called 'rejecting ".
        "clients', which explains the name of this script.\n");

    ho_print_help('section', 'Settings');
        ho_print_help('setting', 'ho_reject_throttleban_enable',
                'Master setting to enable/disable this script.');
        ho_print_help('setting', 'ho_reject_throttle_network_tags',
                'Tags of the networks rejecting clients must be tracked.');
        ho_print_help('setting', 'ho_reject_ignore_spoofs',
                'Whether spoofs should be ignored.');
        ho_print_help('setting', 'ho_reject_dline_reason',
                'The reason of the ban placed on the rejecting client.');

#    ho_print_help('setting', 'ho_reject_throttlewarning_count', 'and');
#    ho_print_help('setting', 'ho_reject_throttlewarning_time',
#        'If clients from a host connect more than ho_reject_throttlewarning_count '.
#        'times in ho_reject_throttlewarning_time seconds, a warning is printed.');

    ho_print_help('setting', 'ho_reject_throttleviolation_count', 'and');
    ho_print_help('setting', 'ho_reject_throttleviolation_time',
        'If clients from a host connect more than ho_reject_throttleviolation_count '.
        'times in ho_reject_throttleviolation_warning_time seconds, the host is banned.');
}
