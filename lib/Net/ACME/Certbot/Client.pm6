unit module Net::ACME::Certbot::Client;

my $APACHE = "/usr/local/apache2/bin/httpd";
my $debug  = 0;

sub check-cert-valid-days($certfile,
                          :$view,
                           --> Int) is export(:check-cert-valid-days) {
    #log-msg "-- Entering sub '&?ROUTINE.name'...";

    # cert should be a pem-encoded file
    # we use openssl to get clear text to view and search
    # our goal is to return the valid days remaining till
    # the expiration date of the cert which
    # is in format:
    #   Not After : May 12 17:21:00 2017 GMT

    my $cmd  = "openssl x509 -in $certfile -text -noout";
    my $p = run $cmd.words, :out;
    my $out = $p.out.slurp(:close);

    if $debug {
	spurt $out, 'DEBUG.cleartext.pem';
    }

    my $valid-days = 0;
    my $CN = '';
    my @SAN;
    for $out.lines -> $line {
        #say $line if $debug;
        if $line ~~ /^ \s* 'Not After :' \s+
            (\w**3) \s+ (\d\d) \s+ \d\d ':' \d\d ':' \d\d \s* (\d**4) \s+ / {
            my $mon   = ~$0;
            my $day   = +$1;
            my $year  = +$2;

            # get exp date in ISO format
            $valid-days = get-cert-valid-days(:$day, :$mon, :$year);
            say "Expiration date is $day $mon $year ($valid-days days hence)" if $view;
        }
	# CN
	elsif $line ~~ /^ \s* 'Subject:' \s+ 'CN=' (<[\da..zA..Z_\-\.]>+) / {
	    $CN = ~$0;
	    say "DEBUG: \$CN = '$CN'" if $debug;
	}
	# SAN
	elsif $line ~~ /^ \s* 'DNS:' / {
	    my $s = $line;
	    # eliminate all 'DNS:' and commas
	    $s ~= s:g/ 'DNS:' //;
	    $s ~= s:g/ ',' //;
	    # what's left is one or more Subject Alternative names
	    # the first should be the same as the CN
	    @SAN = $s.words;
	    say "DEBUG: \@SAN = '{@SAN}'" if $debug;
	}
    }

    #log-msg "-- Exiting sub '&?ROUTINE.name'...";
    return $valid-days;
}


sub get-cert-valid-days(Int:D :$day! where { $day ~~ 1..31 },
                        Str:D :$mon!,
                        Int:D :$year! where { $year > 2015 },
			--> Int
		       ) is export(:get-cert-valid-days) {
    #log-msg "-- Entering sub '&?ROUTINE.name'...";

    my $mon-num = do given $mon {
        when /:i ^ jan / { '01' }
        when /:i ^ feb / { '02' }
        when /:i ^ mar / { '03' }
        when /:i ^ apr / { '04' }
        when /:i ^ may / { '05' }
        when /:i ^ jun / { '06' }
        when /:i ^ jul / { '07' }
        when /:i ^ aug / { '08' }
        when /:i ^ sep / { '09' }
        when /:i ^ oct / { '10' }
        when /:i ^ nov / { '11' }
        when /:i ^ dec / { '12' }
        default {
            die "FATAL: Unknown month input '$mon'"
        }
    }

    # get the days since the epoch
    my $expjdays = Date.new("$year-$mon-num-$day").daycount;
    my $nowjdays = Date.today.daycount;

    # the difference is the number of valid days remaining
    #log-msg "-- Exiting sub '&?ROUTINE.name'...";

    return $expjdays - $nowjdays;
}

sub apache-is-running(--> Bool) is export(:apache-is-running) {
    log-msg "-- Entering sub '&?ROUTINE.name'...";
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
        log-msg "-- Exiting sub '&?ROUTINE.name'...";
        return True;
    }
    else {
        log-msg "-- Exiting sub '&?ROUTINE.name'...";
        return False;
    }
}

sub check-apache() is export(:check-apache) {
    if apache-is-running() {
        say "Apache IS running.";
    }
    else {
        say "Apache is NOT running.";
    }
}

sub same-file($f1, $f2 --> Bool) is export(:same-file) {
    use File::Compare;
    return files_are_equal($f1, $f2);
}

sub log-msg($m, :$log, :$view) is export(:log-msg) {
    say $m if $view;
    $log.say: $m if $log
}

sub log-start-msg(:$log) is export(:log-start-msg) {
    my $dt = DateTime.now;
    my $m = "==== Start: $dt";
    # for now don't show on stdout
    # log-msg $m;
    $log.say: $m if $log
}

sub log-end-msg(:$log) is export(:log-end-msg) {
    my $dt = DateTime.now;
    my $m = "==== End: $dt";
    # for now don't show on stdout
    # log-msg $m;
    $log.say: $m if $log
}

sub start-apache() is export(:start-apache) {
    log-msg "-- Entering sub '&?ROUTINE.name'...";
    return if apache-is-running;
    my $cmd = 'apachectl start';

    my $p = run $cmd.words;
    log-msg "-- Exiting sub '&?ROUTINE.name'...";
    return $p.exitcode;
}

sub stop-apache() is export(:stop-apache) {
    log-msg "-- Entering sub '&?ROUTINE.name'...";
    return if !apache-is-running;
    my $cmd = 'apachectl graceful-stop';

    my $p = run $cmd.words;
    log-msg "-- Exiting sub '&?ROUTINE.name'...";
    return $p.exitcode;
}

sub collect-stats(:%adoms, :$certbot-dir, :%udoms, :$reissue = 30, :$view) is export(:collect-stats) {
    log-msg "-- Entering sub '&?ROUTINE.name'...";
    # note reissue is essentially same as issue per acme rfc
    my %r;
    for %udoms.keys.sort -> $d {
        say "=== Working domain '$d'" if $view;
        # get the file name of the cert file (if any)
        my $f  = "$certbot-dir/$d/$d.cer";

        if $f.IO.e {
            say "Found cert file '$f'" if $view;
            my $n = check-cert-valid-days($f);
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
    log-msg "-- Exiting sub '&?ROUTINE.name'...";
    return %r;
}

sub abbrev(%words, %abbrev-word, %word-abbrev) is export(:abbrev) {
    # for a hash of words, computes minimum unique abbreviation
    # inspiration and code use from Text::Abbrev
    my $seen = SetHash.new;
    my %result;
    for %words.keys -> $word {
        for 1..$word.chars -> $len {
            my $abbrev = $word.substr(0, $len);
            if $seen{$abbrev} {
                %result{$abbrev}:delete;
            }
            else {
                $seen{$abbrev}   = True;
                %result{$abbrev} = $word;
            }
        }
    }
    # now we need to get the shortest abbrev for each word
    for %result.kv -> $abbrev, $word {
        my $alen = $abbrev.chars;
        if %word-abbrev{$word}:exists {
            my $len = %word-abbrev{$word}.chars;
            if $alen < $len {
                %word-abbrev{$word}   = $abbrev;
            }
        }
        else {
            %word-abbrev{$word}   = $abbrev;
        }
    }
    # now get the antipair hash for completeness
    %abbrev-word = %word-abbrev.antipairs;
} 

