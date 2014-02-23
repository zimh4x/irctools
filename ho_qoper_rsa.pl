# ho_qoper_rsa.pl
#
# This is a supplemental public key oper auth script for use with HOSC and ratbox ircd.
# If ho_qoper.pl and challenge-irssi.pl had a baby, this would be it. Thanks to
# garion@efnet.nl for ho_qoper.pl and HOSC in general, and thanks to James Seward
# for challenge-irssi.pl
#
# -zz

use strict;
use Irssi;
use IPC::Open2;
use HOSC::again;
use HOSC::again 'HOSC::Base';
use HOSC::again 'HOSC::Tools';
import HOSC::Tools qw(get_named_token);

use vars qw[$VERSION %IRSSI $SCRIPT_NAME];

$SCRIPT_NAME = "qoper_rsa";
$VERSION = "1.0";
%IRSSI = (
        authors         => 'zimzum',
        contact         => 'zimzum@darkspace.org',
        name            => 'ho_qoper_rsa',
        description     => 'Automatic CHALLENGE opering on connect.',
        license         => 'Public Domain',
        url             => '',
        changed         => 'Wed Feb 18 00:57:09 EST 2009',
);

#global vars for setting without servertag
my $main_keypass = '';
my $main_keypath = '';

#hashmaps for storing separate information per servertag
my $key_filepaths;
my $key_passwords;

#temporary storage
my $challenge_cookie;

sub rsa_event_connected {
        my ($server) = @_;
        my @networks = get_networks();
        my $tag = lc $server->{tag};
        return unless grep /^$tag$/, @networks;

        if (defined get_keypath($tag)) {
                ho_print("qoper_rsa - connected.");
                if (!defined get_password($tag) ) {
                        ho_print_warning("qoper_rsa - performing key auth with NO PASSPHRASE.");
                }
                my $opernick = get_opernick($server->{tag});
                if (!defined $opernick || length $opernick == 0) {
                        $opernick = $server->{nick};
                }
                $server->send_raw("CHALLENGE $opernick");
                ho_print("qoper_rsa - CHALLENGE request sent.");

        }
}

sub rsa_event_opered {
        my ($server, $msg) = @_;
        my @networks = get_networks();

        return unless grep lc $server->{tag}, @networks;

        my $usermodes = get_usermodes($server->{tag});
        if (defined $usermodes && length $usermodes > 0) {
                ho_print("qoper_rsa - just opered up. setting user modes $usermodes");
                $server->send_raw("MODE " . $server->{nick} . " $usermodes");
        } else {
                ho_print("qoper_rsa - no usermodes set for tag " . $server->{tag} . ".");
        }
}

# handle 740 numeric from server: receive 1 or more parts of ratbox challenge cookie
sub event_challenge_rpl {
        my ($server, $challenge) = @_;
        ho_print("qoper_rsa -  receiving CHALLENGE data from $server->{tag}/$server->{address}");
        $challenge =~ s/^[^ ]+ ://;
        ho_print( "CHALLENGE_DATA: $challenge" );
        $challenge_cookie .= $challenge;
}

# handle 741 numeric from server: got entire challenge cookie from server so calculate and send response
sub event_challenge_rpl_end {
        my ($server, $blah) = @_;
        my $challenge_keyphrase = "";
        ho_print("qoper_rsa -  CHALLENGE data received from $server->{tag}/$server->{address}");
        my $respond_path = Irssi::settings_get_str("ho_qoper_rsa_ratboxrespond_path");
        my $keyfile_path = get_keypath($server->{tag});
        if ($respond_path eq '' || !defined $respond_path) {
                ho_print("qoper_rsa -  whoops! You need to /set ho_qoper_rsa_ratboxrespond_path <path to binary>");
                return 0;
        }
        if ($keyfile_path eq '' || !defined $keyfile_path) {
                ho_print("qoper_rsa -  whoops! You need to /qoper_rsa_setkeypath <tag> </path/to/private.key>");
                return 0;
        }
        #check respond binary exists and is executable
        if (! -x $respond_path) {
                ho_print("qoper_rsa -  $respond_path is not executable by you :(");
                return 0;
        }
        if (! -r $keyfile_path) {
                ho_print("qoper_rsa -  $keyfile_path is not readable by you :(");
                return 0;
        }
        my $pid;
        unless ($pid = open2(*Reader, *Writer, $respond_path, $keyfile_path)) {
                ho_print("qoper_rsa -  couldn't exec respond, failed!");
                return 0;
        }
        $challenge_keyphrase = lc get_password($server->{tag});
        print Writer "$challenge_keyphrase\n";
        print Writer "$challenge_cookie\n";
        #erase data, just in case
        $challenge_keyphrase =~ s/./!/g;
        $challenge_cookie =~ s/./!/g;
        $challenge_keyphrase = $challenge_cookie = '';
        #get response to send
        my $output = scalar <Reader>;
        chomp($output);
        #wait for ratbox-respond to exit
        waitpid $pid, 0;

        if ($output =~ /^Error:/) {
                $output =~ s/^Error: //;
                ho_print_warning("qoper_rsa -  Error from respond: $output");
                return 0;
        }
        $server->send_raw("CHALLENGE +$output");
        ho_print("qoper_rsa - RSA CHALLENGE-RESPONSE sent to $server->{tag}/$server->{address}");
        return 1;
}

#retrieve data
sub get_keypath {
        my ($tag) = @_;
        if ( defined $key_filepaths->{$tag} ) {
                return $key_filepaths->{$tag};
        }
        return $main_keypath;
}

sub get_password {
        my ($tag) = @_;
        if (defined $key_passwords->{$tag}) {
                return $key_passwords->{$tag};
        }
        return $main_keypass;
}

sub get_networks {
        my @networks = split / +/,
        lc Irssi::settings_get_str('ho_qoper_rsa_network_tags');
        return @networks;
}
sub get_opernick {
        my ($tag) = @_;
        return get_named_token(Irssi::settings_get_str('ho_qoper_rsa_nick'), $tag);
}

sub get_usermodes {
        my ($tag) = @_;
        return get_named_token(Irssi::settings_get_str('ho_qoper_rsa_usermode'), $tag);
}

#store data
sub set_keypath {
        my ($args, $server, $item) = @_;
        my $tag = '';
        my $newkeypath = '';
        if ($args =~ /^(\S+)\s+(.+)$/) {
                $tag = $1;
                $newkeypath = $2;
        } else {
                $tag = $args;
        }

        if ( (length $tag > 0) && (length $newkeypath == 0 || $newkeypath eq '') ) {
                $main_keypath= $tag;
                ho_print("qoper_rsa - main keypath set.");
        } elsif (length $tag > 0 && length $newkeypath > 0) {
                $key_filepaths->{$tag} = $newkeypath;
                ho_print("qoper_rsa - keypath for '$tag' set to '$newkeypath'.");
        } else {
                ho_print("Usage:\t/qoper_rsa_setkeypath </path/to/private/key>");
                ho_print("Usage:\t/qoper_rsa_setkeypath <tag> </path/to/private/key>");
        }
}

sub set_password {
        my ($args, $server, $item) = @_;
        my $tag = '';
        my $newpassword = '';
        if ($args =~ /^(\S+)\s+(.+)$/) {
                $tag = $1;
                $newpassword = $2;
        } else {
                $tag = $args;
        }

        if (length $tag > 0 && length $newpassword == 0) {
                $main_keypass = $tag;
                ho_print("qoper_rsa - main key passphrase set.");
        } elsif (length $tag > 0 && length $newpassword > 0) {
                $key_passwords->{$tag} = $newpassword;
                ho_print("qoper_rsa - set key passphrase for '$tag'.");
        } else {
                ho_print("Usage:\t/qoper_rsa_setpassphrase <password>");
                ho_print("Usage:\t/qoper_rsa_setpassphrase <tag> <password>");
        }
}

#clear data
sub clear_key {
        my ($tag) = @_;
        if (defined $tag  && defined $key_filepaths->{$tag}) {
                delete $key_filepaths->{$tag};
                ho_print("qoper_rsa - keypath for $tag cleared.");
                return;
        }
        return;
}

sub clear_keys {
        foreach my $tag ( keys %$key_filepaths ) {
                clear_key($tag);
        }
        $main_keypath = '';
        ho_print("qoper_rsa - ALL keypaths cleared.");
        return;
}

sub clear_password {
        my ($tag) = @_;
        if (defined $tag && defined $key_passwords->{$tag}) {
                $key_passwords->{$tag} =~ s/./!/g;
                $key_passwords->{$tag} = '';
                delete $key_passwords->{$tag};
                ho_print("qoper_rsa - password for $tag cleared.");
        }
        return;
}

sub clear_passwords {
        foreach my $tag (keys %$key_passwords) {
                clear_password($tag);
        }
        $main_keypass =~ s/./!/g;
        $main_keypass = '';
        ho_print("qoper_rsa - ALL passwords have been cleared.");
        return;
}

#sub rsa_sig_setup_save {
#       my ($mainconfig, $auto) = @_;
#       if ( !defined $auto ) {
#               clear_keys();
#               clear_passwords();
#       }
#}

sub sig_setup_reread {
        ho_print_warning("qoper_rsa was loaded:\nyou may want to unload ho_oper.pl");
        qoper_rsa_usage();
}

sub qoper_rsa_usage {
        ho_print("commands are:\n" .
                "\t/qoper_rsa_status\n" .
                "\t/qoper_rsa_challenge <opernick>\n" .
                "\t/qoper_rsa_setkeypath </path/to/private.key>\n" .
                "\t/qoper_rsa_setkeypath <tag> </path/to/private.key>\n" .
                "\t/qoper_rsa_setpassphrase <password>\n" .
                "\t/qoper_rsa_setpassphrase <tag> <password>\n" .
                "\t/qoper_rsa_clear_key <tag>\n" .
                "\t/qoper_rsa_clear_all_keys\n" .
                "\t/qoper_rsa_clear_passphrase <tag>\n" .
                "\t/qoper_rsa_clear_all_passphrases\n" .
                "\t/qoper_rsa_usage\n" );
}

sub cmd_challenge {
        my ($cmdline, $server, $channel) = @_;
        if ($cmdline eq '') {
                my $opernick = get_opernick($server->{tag});
                if (!defined $opernick || length $opernick == 0) {
                        $opernick = $server->{nick};
                }
                if ( length $opernick > 0 ) {
                        $server->send_raw("CHALLENGE $opernick");
                        ho_print("qoper_rsa - CHALLENGE request sent.");
                } else {
                        ho_print_warning("qoper_rsa - failed to determine oper nick: CHALLENGE request not sent.");
                        ho_print_warning("qoper_rsa - please \'set ho_qoper_rsa_nick opernick\' or /challenge <opernick>");
                }
                return 0;
        }
        $server->send_raw("CHALLENGE $cmdline");
        ho_print("qoper_rsa - CHALLENGE request sent.");
        return 0;
}

sub cmd_qoper_rsa_status {
        my ($cmdline, $server, $channel) = @_;
        my $keysfound = '';
        foreach my $tag ( keys %$key_filepaths ) {
                if ( $keysfound eq '' ) {
                        $keysfound = "yes";
                }
                ho_print("qoper_rsa - $tag\'s keypath = " . $key_filepaths->{$tag} );
                if( defined $key_passwords->{$tag} ) {
                        ho_print("qoper_rsa - $tag currently has a password set.");
                } else {
                        ho_print("qoper_rsa - $tag currently does NOT have a password set.");
                }
        }
        if ( length $main_keypath > 0 ) {
                $keysfound = "yes";
                ho_print("qoper_rsa - main_keypath = " . $main_keypath );
        }
        if ( length $main_keypass > 0 ) {
                $keysfound = "yes";
                ho_print("qoper_rsa - main_keypass = set.");
        }
        if ( $keysfound eq '' ) {
                ho_print("qoper_rsa - no stored data found.");
        }
        return;
}

#client settings data
Irssi::settings_add_str('ho', 'ho_qoper_rsa_ratboxrespond_path', '');
Irssi::settings_add_str('ho', 'ho_qoper_rsa_nick', '');
Irssi::settings_add_str('ho', 'ho_qoper_rsa_usermode', '');
Irssi::settings_add_str('ho', 'ho_qoper_rsa_network_tags', '');

#client event hooks
Irssi::signal_add_first('event 001', 'rsa_event_connected');
Irssi::signal_add_first('event 381', 'rsa_event_opered');
Irssi::signal_add_first('event 740', 'event_challenge_rpl');
Irssi::signal_add_first('event 741', 'event_challenge_rpl_end');

#client signal hooks
#Irssi::signal_add('setup saved', 'rsa_sig_setup_save');
Irssi::signal_add('setup reread', 'rsa_sig_setup_reread');

#command bindings
Irssi::command_bind('qoper_rsa_setkeypath', 'set_keypath');
Irssi::command_bind('qoper_rsa_setpassphrase', 'set_password' );

Irssi::command_bind('qoper_rsa_clear_key', 'clear_key');
Irssi::command_bind('qoper_rsa_clear_all_keys', 'clear_keys');

Irssi::command_bind('qoper_rsa_clear_passphrase', 'clear_password');
Irssi::command_bind('qoper_rsa_clear_all_passphrases', 'clear_passwords');

Irssi::command_bind('qoper_rsa_usage', 'qoper_rsa_usage');

Irssi::command_bind('qoper_rsa_challenge', 'cmd_challenge');
Irssi::command_bind('qoper_rsa_status','cmd_qoper_rsa_status');
