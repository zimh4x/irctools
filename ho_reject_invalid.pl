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
    name        => 'ho_reject_invalid',
    description => 'Looks for rejecting or invalidd rejected clients and acts upon them.',
    license     => 'Public Domain',
    url         => 'n/a',
    changed     => 'Wed Jan  2 23:46:56 PST 2013',
);
$SCRIPT_NAME = 'InvalidReject';

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


    # Invalid Username
    # nick, username, hostname
    if ($msg =~ /Invalid username:\s(.*)\s\((.*)\@(.*)\).*/) {
    	#ho_print_warning("server:  $server->{tag}\nnick: $1\nhost: $2\nusername: $3\n");
        process_invalid_user($server, $1, $2, $3);
        return;
    }
}

sub process_invalid_user {
        my ($server, $nick, $un, $hn) = @_;
	my $username = $un;
	my $host = $hn;

	#ho_print("Invalid event being processed");
	#ho_print("hn = $hn.");
	#ho_print("username = $username.");
	#ho_print("host = $host.");
	#ho_print("userhost[0] = $userhost[0].");
	#ho_print("userhost[1] = $userhost[1].");

        return unless Irssi::settings_get_bool('ho_reject_invalidban_enable');
        my $tag = $server->{tag};

        my $watch_this_network=0;
        foreach my $network (split /\s+/,lc(Irssi::settings_get_str('ho_reject_invalid_network_tags')))
        {
                if ($network eq lc($server->{tag}))
                {
                        $watch_this_network=1;
                }
        }
        return unless $watch_this_network;

        my $now = time();
        push @{ $conntimes{$tag}->{$host} }, $now;

        if ( @{ $conntimes{$tag}->{$host} } >= Irssi::settings_get_int('ho_reject_invalidviolation_count') )
        {
                my $firsttime = ${ $conntimes{$tag}->{$host} }[0];
                my $lasttime = ${ $conntimes{$tag}->{$host} }[@{ $conntimes{$tag}->{$host} } - 1];
		my $timediff = $lasttime - $firsttime;


                if ($timediff <= Irssi::settings_get_int('ho_reject_invalidviolation_time'))
                {
                        my $time = Irssi::settings_get_int('ho_reject_invalid_kline_time');
                        my $reason = Irssi::settings_get_str('ho_reject_invalid_kline_reason');
			my $invalidcount = @{ $conntimes{$tag}->{$host} };
			my $invalidtime = $timediff;

                        # src ip is officially annoying exceeding invalid count per time settings
			$server->command("quote kline $time *\@$host :$reason");
                        ho_print("Invalid user: K-lined *\@$host for $invalidcount invalids in $invalidtime seconds.");
		}

        }

	#cleanup hashtable every 60 seconds
	if ($now > $conntimes_last_cleaned + 60) {
        	$conntimes_last_cleaned = $now;
        	cleanup_conntimes_hash(14400);
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
        for my $host (keys %{ $conntimes{$tag} }) 
	{
            my $lasttime = ${ $conntimes{$tag}->{$host} }[@{ $conntimes{$tag}->{$host} } - 1];

            # Discard this host if no connections have been made from it during
            # the last $keeptime seconds.
            if ($now > $lasttime + $keeptime) {
                delete $conntimes{$tag}->{$host};
            }
        }
    }
}

# ---------------------------------------------------------------------
# The /reject command.

sub cmd_reject {
    my ($data, $server, $item) = @_;
    if ($data =~ m/^[(help)]/i ) {
        Irssi::command_runsub ('invalid', $data, $server, $item);
    } else {
        ho_print("Use /invalid HELP for help.")
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

Irssi::command_bind('invalid',      'cmd_reject');
Irssi::command_bind('invalid help', 'cmd_reject_help');

# kline for 1440 minutes if client connects with invalid username 3 times in 30 minutes (1800 seconds)
Irssi::settings_add_bool('ho', 'ho_reject_invalidban_enable',		0);
Irssi::settings_add_int('ho', 'ho_reject_invalidviolation_count',   3);
Irssi::settings_add_int('ho', 'ho_reject_invalidviolation_time',   1800);
Irssi::settings_add_int('ho', 'ho_reject_invalid_kline_time',      1440);
Irssi::settings_add_str('ho', 'ho_reject_invalid_network_tags',      '');
Irssi::settings_add_str('ho', 'ho_reject_invalid_kline_reason', 'Hammering with invalid username. Please see: https://tools.ietf.org/html/rfc2812#section-3.1.3');

if (length Irssi::settings_get_str('ho_reject_invalid_network_tags') > 0) {
        if (Irssi::settings_get_bool('ho_reject_invalidban_enable')) {
                ho_print("Script enabled for the following tags: " .
                        Irssi::settings_get_str('ho_reject_invalid_network_tags'));
        } else {
                ho_print("Script disabled. The following tags have been set: " .
                        Irssi::settings_get_str('ho_reject_invalid_network_tags') .
                        ". Use /SET ho_reject_invalidban_enable ON to enable the script.");
        }
} else {
        ho_print_warning("No network tags set. Please use ".
                "/SET ho_reject_invalid_network_tags tag1 tag2 tag3 .. ".
                "to choose the tags the script will work on.");
}

ho_print_init_end();
ho_print("Use /invalid HELP for help.");

# ---------------------------------------------------------------------

sub print_help {
    ho_print_help('head', $SCRIPT_NAME);

    ho_print_help('section', 'Description');
    ho_print_help("This script tracks reconnecting clients and can take action on ".
        "them, being either printing a warning or banning them from the server ".
        "automatically. Clients that reconnect rapidly are called 'rejecting ".
        "clients', which explains the name of this script.\n");

    ho_print_help('section', 'Settings');
        ho_print_help('setting', 'ho_reject_invalidban_enable',
                'Master setting to enable/disable this script.');
        ho_print_help('setting', 'ho_reject_invalid_network_tags',
                'Tags of the networks rejecting clients must be tracked.');
        ho_print_help('setting', 'ho_reject_invalid_kline_reason',
                'The reason of the ban placed on the rejecting client.');

#    ho_print_help('setting', 'ho_reject_invalidwarning_count', 'and');
#    ho_print_help('setting', 'ho_reject_invalidwarning_time',
#        'If clients from a host connect more than ho_reject_invalidwarning_count '.
#        'times in ho_reject_invalidwarning_time seconds, a warning is printed.');

    ho_print_help('setting', 'ho_reject_invalidviolation_count', 'and');
    ho_print_help('setting', 'ho_reject_invalidviolation_time',
        'If clients from a host connect more than ho_reject_invalidviolation_count '.
        'times in ho_reject_invalidviolation_warning_time seconds, the host is banned.');
}
