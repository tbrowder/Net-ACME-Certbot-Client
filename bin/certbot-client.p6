#!/usr/bin/env perl6

use lib <../lib lib>;

use Text::More :strip-comment;
use Proc::More :run-command;
use Net::ACME::Certbot::Client :ALL;
   
my %known-options; # defined in BEGIN block at eof
my $domain-list   = "/etc/acme-certbot-client/domains";
my $client-config = "/etc/acme-certbot-client/config";
my $certbot-dir   = "/etc/letsencrypt";
#die "FATAL: Unknown dir '$sdir'" if !$sdir.IO.d;

# 4 modes
my $report = 0; # report cert status
my $cron   = 0; # write a cron script
my $show   = 0; # show a list of long and short names of all domains
                # also shows a list of subdomains
my $issue  = 0; # catch-all issue command using the webroot method unless the
                # standalone option is used
                # for now this just writes a script for each domain

sub z {
    $report = 0; # report cert status
    $cron   = 0; # write a cron script
    $show   = 0; # show a list of long and short names of all domains
    $issue  = 0; # catch-all issue command
}

# 8 options
# 4 issue options
my $force   = 0; # force issue even if valid
my $test    = 0; # use the acme test (stage) server
my $D       = 0; # input subset of known domains
my $alone   = 0; # use the standalone
# 4 other options
my $debug   = 0;
my $verbose = 0;
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

%doms = read-domains($domain-list, :debug(0));
read-client-config($client-config);
for @*ARGS {
    # 4 modes ('z' is a sub that zeroes all mode args)
    when /^ c  / { z; $cron    = 1; }
    when /^ r  / { z; $report  = 1; }
    when /^ s  / { z; $show    = 1; }
    when /^ i  / { z; $issue   = 1; }

    # 8 options
    when /^ h  / { $help    = 1; }
    when /^ a  / { $alone   = 1; }
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
    when so $report { report(%doms) }
    when so $cron   { cron(%doms) }
    when so $show   { list-domains(%doms) }
    when so $issue  { write-cert-issue-scripts(%doms) }
}

say "\nNormal end." if $view;

#### SUBROUTINES ####
sub report(%doms) {
    log-msg "-- Entering sub '{&?ROUTINE.name}'...";

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
        say "\nNo domains need issue or reissue.";
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
    log-msg "-- Exiting sub '{&?ROUTINE.name}'...";

}

sub list-domains(%doms) {
    log-msg "-- Entering sub '{&?ROUTINE.name}'...";
    say "DEBUG: -- Entering sub '{&?ROUTINE.name}'..." if $debug;
    say %doms.gist if $debug;
    say "WARNING: \%doms has no elements" if !%doms.elems;
    # need abbrevs
    my %word-abbrev;
    my %abbrev-word;
    abbrev(%doms, :%word-abbrev, :%abbrev-word);
    my @doms = %doms.keys.sort;
    # two passes to get nice formatting
    my $max = 0;
    for @doms -> $d {
        my $len = $d.chars;
        $max = $len if $len > $max;
    }

    say "CN domains and subdomains:";
    for @doms -> $d {
        say "DEBUG: domain '$d'" if $debug;
        my $abbrev = %word-abbrev{$d};
        printf "%-*.*s  %-s\n", $max, $max, $d, $abbrev;
        my @sd = @(%doms{$d});
        for @sd -> $sd {
            say "  => $sd";
        }
    }
    log-msg "-- Exiting sub '{&?ROUTINE.name}'...";
}

sub cron(%doms) {
    =begin comment
    log-msg "-- Entering sub '{&?ROUTINE.name}'...";
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
        log-msg "-- Exiting sub '{&?ROUTINE.name}'...";
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
    log-msg "-- Exiting sub '{&?ROUTINE.name}'...";
    =end comment
}

sub help {
    print qq:to/HERE/;
    $usage

    modes:
      r  - report cert status
      c  - create a cron script 
      s  - show a list of long and short names of all domains
      i  - write certbot script for each CN domain

    options:
      a     use the standalone mode
      f     force issue even if valid
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

sub read-domains($domain-list-fname, :$debug) {
    say "DEBUG: in sub '&?ROUTINE.name'" if $debug;
    my $f = $domain-list-fname;
    my %doms;
    if !$f.IO.f {
        say "WARNING: Domain file '$f' not found.";
        return %doms;
    }
    for $f.IO.lines -> $line is copy {
        $line = lc strip-comment($line);
        next if $line !~~ /\S/;
        say "DEBUG: line = '$line'" if $debug;
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
        if %doms{$dom}:exists {
            die "FATAL:  Domain '$dom' is not a unique key.";
        }
        %doms{$dom} = [flat @doms];
    }
    say %doms.gist if $debug;
    say "WARNING: \%doms has no elements" if !%doms.elems;
    return %doms;
}

sub read-client-config($client-config-file) {
    my $f = $client-config-file;
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

sub write-cert-issue-scripts(%doms) {
    my @ofils;
    for %doms.kv -> $d, $s {
        my @sd = @($s);
        my $script = "certbot-issue-request-$d.sh";
        my $fh = open($script, :w);

        # option flags
        my ($o1, $o2, $o3, $o4, $o5, $o6, $o7, $o8);
        $o2 = '--must-staple';
        $o4 = '--non-interactive';
        $o5 = '--webroot';
        $o6 = '--agree-tos';
        $o7 = '-w /var/www/acme';
        $o8 = '--redirect --hsts';
        if 1 {
            # for testing
            $o1 = '--force-renewal';
            $o3 = '--test-cert';
        }
        else {
            # for real!
            $o1 = $force ?? '--force-renewal' !! '';
            $o3 = $test ?? '--test-cert' !! '';
        } 
        my $email = 'tom.browder@gmail.com';
        $fh.printf: "#!/bin/bash\n";
        $fh.printf: "certbot certonly --email $email $o1 $o2 $o3 $o4 $o5 $o6 $o7 $o8 -d $d"; # no newline!
        for @sd -> $sd {
            $fh.print: " -d $sd";
        }
        $fh.print-nl;
        $fh.close;
        $script.IO.chmod: 0o755;
        @ofils.append: $script;

        if $debug {
            say "Working CN domain '$d' and its subdomains:";
            for @sd -> $sd {
               say "  $sd";
            }
        }
    }

    say "Normal end.";
    if +@ofils {
        my $s = @ofils.elems > 1 ?? 's' !! 'm';
        say "See certbot script$s:";
        say "  $_" for @ofils;
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
