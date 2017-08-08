unit module Net::ACME::Certbot::Client;

my $debug = 0;

sub check-cert-valid-days($certfile,
                          :$view,
                           --> Int) is export(:check-cert-valid-days) {
    my $sub = 'check-cert';
    #log-msg "-- Entering sub '$sub'...";

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

    #log-msg "-- Exiting sub '$sub'...";
    return $valid-days;
}


sub get-cert-valid-days(Int:D :$day! where { $day ~~ 1..31 },
                        Str:D :$mon!,
                        Int:D :$year! where { $year > 2015 },
			--> Int
		       ) is export(:get-cert-valid-days) {
    my $sub = 'get-cert-valid-days';
    #log-msg "-- Entering sub '$sub'...";

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
    #log-msg "-- Exiting sub '$sub'...";

    return $expjdays - $nowjdays;
}
