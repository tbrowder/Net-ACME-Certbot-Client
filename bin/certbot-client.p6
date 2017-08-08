#!/usr/bin/env perl6

use lib <lib>;

use Net::ACME::Certbot::Client :ALL;

# use LFS for determining a good place and name for the domain list

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

my %udoms; # the set of domains to be considered
           # or valid subset of domains entered as D=d1[,d2,...,dN]

# this may not be needed at global scope:
my %adoms; # the set of domains to be actually issued or renewed

my $usage = "Usage: $*PROGRAM mode | help [options]";

if !@*ARGS {
    say $usage;
    exit;
}

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
    =begin comment
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
    =end comment
    default {
        say "FATAL: Unknown arg '$_'.";
        exit;
    }
}

help if $help;
=begin comment
if $D && !%udoms {
    say "FATAL: No known domains entered with the 'D=' option.";
    exit;
}
else {
    %udoms = %doms;
}
=end comment

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
    when so $copy   { copy-files }
    when so $report { report }
    when so $auto   { auto }
    when so $show   { list-domains }
}

say "\nNormal end." if $view;

#### SUBROUTINES ####
sub report {
    my $sub = 'report';
    log-msg "-- Entering sub '$sub'...";

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
    log-msg "-- Exiting sub '$sub'...";

}

sub stop-apache {
    my $sub = 'stop-apache';
    log-msg "-- Entering sub '$sub'...";
    return if !apache-is-running;
    my $cmd = 'apachectl graceful-stop';

    my $p = run $cmd.words;
    log-msg "-- Exiting sub '$sub'...";
    return $p.exitcode;
}

sub start-apache {
    my $sub = 'start-apache';
    log-msg "-- Entering sub '$sub'...";
    return if apache-is-running;
    my $cmd = 'apachectl start';

    my $p = run $cmd.words;
    log-msg "-- Exiting sub '$sub'...";
    return $p.exitcode;
}

sub collect-stats(:$reissue = 30) {
    my $sub = 'collect-stats';
    log-msg "-- Entering sub '$sub'...";
    # note reissue is essentially same as issue per acme rfc
    my %r;
    for %udoms.keys.sort -> $d {
        say "=== Working domain '$d'" if $view;
        # get the file name of the cert file (if any)
        my $f  = "$sdir/$d/$d.cer";

        if $f.IO.e {
            say "Found cert file '$f'" if $view;
            my $n = check-cert($f);
            #%r{$n} = [] if !%r{$n};
            %r{$n}.push: $d;
            next if $n > $reissue;
            # put doms in %adoms if need reissue
            %adoms{$d} = $n;
        }
        else {
            my $n = -1;
            #%r{$n} = Array.new if !%r{$n};
            %r{$n}.push: $d;
            # put doms in %adoms if need issue
            %adoms{$d} = -1;
            say "No x509 cert file found...skipping to next domain" if $view;
        }
    }
    log-msg "-- Exiting sub '$sub'...";
    return %r;
}

sub list-domains {
    my $sub = 'list-domains';
    log-msg "-- Entering sub '$sub'...";
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
    log-msg "-- Exiting sub '$sub'...";
}

sub auto {
    my $sub = 'auto';
    log-msg "-- Entering sub '$sub'...";
    # the monitoring and installing process
    # note reissue is essentially same as issue per acme rfc

    # don't normally need the returned hash from collect-stats,
    # doms needing issue are in %adoms
    log-start-msg;
    collect-stats; # values are days to expiration, or -1 for no cert existing

    # need later to consider case of user wanting to issue all certs

    if !%adoms.elems {
        # no certs to be issued...finished
        my $m = "NOTE: No domain certs to be issued at this time.";
        log-msg $m;
        log-end-msg;
        log-msg "-- Exiting sub '$sub'...";
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
    log-msg "-- Exiting sub '$sub'...";
}

sub get-user-host {
    my ($user, $host) = ('?', '?');
    if %*ENV<TMB_MAKE_HOST> {
        $host = %*ENV<TMB_MAKE_HOST>;
    }
    if %*ENV<USER> {
        $user = %*ENV<USER>;
    }
    return ($user, $host);
}

sub run-command(Str:D $cmd is copy --> Int) {
    my $sub = 'run-command';
    log-msg "-- Entering sub '$sub'...";

    # returns exit code
    my $p = run $cmd.words;
    log-msg "-- Exiting sub '$sub'...";
    return $p.exitcode;
}

sub apache-is-running(--> Bool) {
    my $sub = 'apache-is-running';
    log-msg "-- Entering sub '$sub'...";
    # uses the ps command to detect a running apache (httpd) process

    # the best and safest method:
    my $cmd  = "ps -C $APACHE -o cmd=";

    my $p = run $cmd.words, :out;
    my $e = $p.exitcode;
    my $o = $p.out.slurp(:close);

    if $debug {
        print qq:to/HERE/;
            debug: out = '$o'";
                   cmd = '$cmd'";
                   exit code = '$e'";
        HERE
    }

    if $o ~~ /$APACHE/ {
        log-msg "-- Exiting sub '$sub'...";
        return True;
    }
    else {
        log-msg "-- Exiting sub '$sub'...";
        return False;
    }
}

sub check-apache {
    if apache-is-running() {
        say "Apache IS running.";
    }
    else {
        say "Apache is NOT running.";
    }
}

sub copy-files {
    my $sub = 'copy-files';
    log-msg "-- Entering sub '$sub'...";
    # final dir on dedi2 is:
    #   /home/tbrowde/letsencrypt-certs
    my $certdir = "/home/tbrowde/letsencrypt-certs";
    mkdir $certdir;

    # dir and all files are owned by root
    #   chown -R root.root $dir

    my %d = %udoms; # the domains to be considered

    # special actions may be needed????
    # if force, then collect all files for all domains? NO
    # collect files to be copied from all %adoms? YES
    if 0  {
        if !%adoms {
            # have to check for new files
        }
    }

    # for now will use %adoms if not empty
    %d = %adoms if %adoms.elems;

    # source dir is $sdir
    # todir is
    #   /home/tbrowde/letsencrypt-certs
    # now for the copy

    # the certs and unlocked keys
    for %d.keys -> $d {
        # source dir
        my $fromdir = "$sdir/$d";

        my $cert-f = 'fullchain.cer';
        my $key-f  = "$d.key";

        my $cert = "$fromdir/$cert-f";
        my $key  = "$fromdir/$key-f";

        # don't continue unless we have both source files
        next if !($cert.IO.e && $key.IO.e);

        # ensure we have the target dir
        my $todir   = "$certdir/$d";
        mkdir $todir;

        my $cert-to = "$todir/$cert-f";
        my $key-to  = "$todir/$key-f";

        # compare the files before copying
        if same-file($cert, $cert-to) {
            my $m = "WARNING:  Domain '$d' cert file '$cert-f' has not changed.";
            log-msg $m;
        }
        else {
            copy $cert, $cert-to;
            my $m = "Copied domain '$d' cert file to '$cert-to'.";
            log-msg $m;
        }
        if same-file($key, $key-to) {
            my $m = "WARNING:  Domain '$d' key file '$key-f' has not changed.";
            log-msg $m;
        }
        else {
            copy $key, $key-to;
            my $m = "Copied domain '$d' key file to '$key-to'.";
            log-msg $m;
        }
    }
    log-msg "-- Exiting sub '$sub'...";

}

sub same-file($f1, $f2 --> Bool) {
    use File::Compare;
    return files_are_equal($f1, $f2);
}

sub log-msg($m) {
    say $m if $view;
    $log.say: $m if $log
}

sub log-start-msg {
    my $dt = DateTime.now;
    my $m = "==== Start: $dt";
    # for now don't show on stdout
    # log-msg $m;
    $log.say: $m if $log
}

sub log-end-msg {
    my $dt = DateTime.now;
    my $m = "==== End: $dt";
    # for now don't show on stdout
    # log-msg $m;
    $log.say: $m if $log
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
    my $f = $domains;
    return if !$f.IO.f;
    my %doms;
    for $f.IO.lines -> $line {
        $line = lc strip-comment($line);
        next if $line !~~ /\S/ 
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
        next if $line !~~ /\S/ 
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
	'--preferred-challenges => 'list',
	'--must-staple' => '',
	'--rsa-key-size => 'uint',
	'--agree-tos' => '',
    ];
}
