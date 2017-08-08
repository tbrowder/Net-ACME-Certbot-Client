#!/usr/bin/env perl6

use lib <lib>;

use Text::More :strip-comment;
use Proc::More :run-command;
use Net::ACME::Certbot::Client :ALL;
   
my %known-options; # defined in BEGIN block at eof
my $domain-list   = "/etc/acme-certbot-client/domains";
my $client-config = "/etc/acme-certbot-client/config";
my $certbot-dir   = "/etc/letsencrypt";
#die "FATAL: Unknown dir '$sdir'" if !$sdir.IO.d;

# 5 modes
my $report = 0; # report cert status
my $auto   = 0; # issue new if needed
my $copy   = 0; # copy cert prods into place
my $show   = 0; # show a list of long and short names of all domains
my $check  = 0; # check and report on apache (httpd) run status

sub z {
    $report = 0; # report cert status
    $auto   = 0; # issue new if needed
    $copy   = 0; # copy cert prods into place
    $show   = 0; # show a list of long and short names of all domains
    $check  = 0; # check and report on apache (httpd) run status
}

# 8 options
my $force   = 0; # force issue even if valid
my $exe     = 0; # needed to allow file system changes
my $debug   = 0;
my $test    = 0; # use the acme test (stage) server
my $verbose = 0;
my $D       = 0; # input subset of known domains
my $help    = 0; # really a mode, but handled a bit differently at the moment
my $log     = 0;

my %doms;  # the set of all domains
my %sdoms; # the set of all domains keyed by a unique short name
my %udoms; # the set of domains to be considered
           # or valid subset of domains entered as D=d1[,d2,...,dN]
# this may not be needed at global scope:
my %adoms; # the set of domains to be actually issued or renewed

my $usage = "Usage: $*PROGRAM mode | help [options]";

if !@*ARGS {
    say $usage;
    exit;
}

%doms = read-domains;
for @*ARGS {
    # 5 modes ('z' is a sub that zeroes all mode args)
    when /^ ch / { z; $check   = 1; }
    when /^ co / { z; $copy    = 1; }
    when /^ a  / { z; $auto    = 1; }
    when /^ r  / { z; $report  = 1; }
    when /^ s  / { z; $show    = 1; }

    # 8 options
    when /^ e  / { $exe     = 1; }
    when /^ h  / { $help    = 1; }
    when /^ d  / { $debug   = 1; }
    when /^ f  / { $force   = 1; }
    when /^ t  / { $test    = 1; }
    when /^ v  / { $verbose = 1; }
    when /^ l  / { $log     = 1; }
    when /^ 'D=' / {
       $D = 1;
       my $a = $_;
       if $a ~~ /^ \s* 'D=' (<[-\w,._]> ** 1..*) / {
           my $doms = lc ~$0;
           $doms ~~ s:g/','/ /;
           my @d = unique $doms.words;
           say "debug: doms arg = '$doms'" if $debug;
           say "resulting array = <{@d.gist}>" if $debug;
           for @d -> $d {
               # check for shorthand first
               if %sdoms{$d} {
                   %udoms{%sdoms{$d}} = 1;
               }
               # then the full name
               elsif %doms{$d} {
                   %udoms{$d} = 1;
               }
               else {
                   say "WARNING: Unknown domain '$d'...skipping.";
                   next;
               }
           }
       }
   }
    default {
        say "FATAL: Unknown arg '$_'.";
        exit;
    }
}

help if $help;
if $D && !%udoms {
    say "FATAL: No known domains entered with the 'D=' option.";
    exit;
}
else {
    %udoms = %doms;
}

# a convenience var:
my $view = $debug || $verbose;

=begin comment
# for now set log default for report and auto
$log = 1 if $report || $auto;
if $log {
    my $f = "$LOGDIR/manip-certs.log";
    $log = open $f, :a;
}
=end comment

# now execute per chosen mode
{
    when so $check  { check-apache }
    #when so $copy   { copy-files }
    when so $report { report }
    when so $auto   { auto }
    when so $show   { list-domains: %doms }
}

say "\nNormal end." if $view;

#### SUBROUTINES ####
sub report {
    log-msg "-- Entering sub '&?ROUTINE.name'...";

    my %r = collect-stats;
    my @r = %r.keys.sort; # keys are numbers -1..90

    log-start-msg;
    my $m = "\nReport Summary:";
    log-msg $m;

    for @r -> $n {
        my @d = @(%r{$n}); # note the dereference!!
        if $debug {
            say "debug:";
            say %r{$n}.perl
        }
        my $nd = +@d;
        my $s  = $nd > 1 ?? 's' !! '';
        my $s2 = $n  > 1 ?? 's' !! '';
        if $n < 0 {
            my $m1 = "\n  $nd domain$s missing cert$s:";
            log-msg $m1;
            for @d {
                my $m2 = "    $_";
                log-msg $m2;
            }
        }
        else {
            my $m1 = "\n  $nd domain$s with cert$s expiring in $n day$s2:";
            log-msg $m1;
            for @d {
                my $m2 = "    $_";
                log-msg $m2;
            }
        }
    }

    # report any domains due reissue
    if %adoms.elems {
        my @d = %adoms.keys.sort; # keys are domain names
        my $nd = +@d;
        my $s  = $nd > 1 ?? 's' !! '';
        my $s2 = $nd > 1 ?? ''  !! 's';
        my $m1 = "\n  $nd domain cert$s need$s2 issue or reissue:";
        log-msg $m1;
        for @d {
            my $m2 = "    $_";
            log-msg $m2;
        }
    }
    else {
        my $m = "\nNo domains need issue or reissue.";
        log-msg $m;
    }

    if apache-is-running() {
        my $m = "\nApache IS running.";
        log-msg $m;
    }
    else {
        $m = "\nApache is NOT running.";
        log-msg $m;
    }
    log-end-msg;
    log-msg "-- Exiting sub '&?ROUTINE.name'...";

}

sub list-domains(%doms) {
    log-msg "-- Entering sub '&?ROUTINE.name'...";
    my @doms = %sdoms.keys.sort;
    # two passes to get nice formatting
    my $max = 0;
    for @doms -> $d {
        my $len = $d.chars;
        $max = $len if $len > $max;
    }

    for @doms -> $d {
        my $short = %sdoms{$d};
        printf "%-*.*s  %-s\n", $max, $max, $d, $short;
    }
    log-msg "-- Exiting sub '&?ROUTINE.name'...";
}

sub auto {
    =begin comment
    log-msg "-- Entering sub '&?ROUTINE.name'...";
    # the monitoring and installing process
    # note reissue is essentially same as issue per acme rfc

    # don't normally need the returned hash from collect-stats,
    # doms needing issue are in %adoms
    log-start-msg;
    collect-stats: %udoms; # values are days to expiration, or -1 for no cert existing

    # need later to consider case of user wanting to issue all certs

    if !%adoms.elems {
        # no certs to be issued...finished
        my $m = "NOTE: No domain certs to be issued at this time.";
        log-msg $m;
        log-end-msg;
        log-msg "-- Exiting sub '&?ROUTINE.name'...";
        return;
    }

    my @d = %adoms.keys.sort;
    # stop apache if it's running...
    stop-apache;

    # wait long enough to make sure it's stopped
    for 1..$STOP-ATTEMPTS {
        last if !apache-is-running;
        sleep $SLEEP-INTERVAL;
    }


    # restart apache...
    start-apache;
    sleep 5;

    # make sure it's working...
    if !apache-is-running() {
        my $m = 'ERROR: Apache is NOT running after attempted restart.';
        log-msg($m);
    }
    else {
        my $m = 'Apache IS running after restart.';
        log-msg($m);
    }

    # done!
    log-end-msg;
    log-msg "-- Exiting sub '&?ROUTINE.name'...";
    =end comment
}

sub help {
    print qq:to/HERE/;
    $usage

    modes:
      r  - report cert status
      a  - issue new if needed
      co - copy cert prods into place
      s  - show a list of long and short names of all domains
      ch - check and report on apache (httpd) run status

    options:
      f     force issue even if valid
      e     needed to allow file system changes
      d     debug
      t     use the acme test (stage) server
      v     verbose
      D=x,y input subset of known domains (e.g., domains 'x' and 'y')
      h     help (really a mode, handled a bit differently at the moment)
      l     log?

    The report mode is for development as is the debug option.

    The auto mode is intended for either a one-time use
    or as a cron job.

    The exe option is required for actual acme.sh use
    or file system modification.

    HERE
    exit;
}

sub read-domains() {
    my $f = $domain-list;
    return if !$f.IO.f;
    my %doms;
    for $f.IO.lines -> $line {
        $line = lc strip-comment($line);
        next if $line !~~ /\S/;
        my @words = $line.words;
        my $dom = @words[0];
        # default is to have first name DOMAIN.TLD
        my @d = split('.', $dom, :skip-empty);
        die "FATAL: first domain '$dom' is not in DOMAIN.TLD format" if @d.elems != 2;
        # ensure we have "www.DOMAIN.TLD"
        @words.append: "www.$dom";
        my @doms = unique @words;
        $dom = shift @doms;
        # check for uniqueness as a key
        if %doms{$dom}.exists {
            die "FATAL:  Domain '$dom' is not a unique key.";
        }
        %doms{$dom} = [flat @doms];
    }
    return %doms;
}

sub read-client-config() {
    my $f = $client-config;
    return if !$f.IO.f;
    my $in-certbot = 0;
    for $f.IO.lines -> $line is copy {
        $line = lc strip-comment($line);
        next if $line !~~ /\S/;
        my @words = $line.words;
        my $key = shift @words;
        $key .= lc;
        my $val = @words.elems ?? join('', @words) !! '';
        $val .= lc;
        # is the key a certbot tag?
        if $key eq '[certbot]' {
            ++$in-certbot;
            next;
        }

        # is the key a valid option?
        if %known-options{$key}.exists {
            # does it have leading hyphens?
            if $key ~~ /^ '-' / && !$in-certbot {
                die "FATAL:  Key '$key' is not a known acme-certbot-client option.";
            }
	    my $typ = %known-options{$key};
	    die "fix this";
        }
        else {
            die "FATAL:  Unknown client configuration option '$key'.";
        }

        # what now???
    }
}

BEGIN {
    %known-options = [
        # acme-certbot-client
        # distinguished by no leading hyphen(s)
        allow-any-cn => '',

        # certbot options
        # distinguished by leading hyphen(s)
	'--test-cert' => '',
	'--dry-run' => '',
	'--debug' => '',
	'--webroot' => '',
	'-vvv' => '',
	'--non-interactive' => '',
	'--preferred-challenges' => 'list',
	'--must-staple' => '',
	'--rsa-key-size' => 'uint',
	'--agree-tos' => '',
    ];
}
