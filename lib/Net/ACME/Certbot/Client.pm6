unit module Net::ACME::Certbot::Client;

sub check-cert-valid-days($certfile --> Int) is export(:check-cert-valid-days') {
    my $sub = 'check-cert';
    log-msg "-- Entering sub '$sub'...";

    # cert should be a pem-encoded file
    # we use openssl to get clear text to view and search
    # our goal is to return the valid days remaining till
    # the expiration date of the cert which
    # is in format:
    #   Not After : May 12 17:21:00 2017 GMT

    my $cmd  = "$bin x509 -in $certfile -text -noout";
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
	elsif $line ~~ /^ \s* 'Subject:' \s+ 'CN=' (<[\da..zA..Z_-.]>+) / {
	    $CN = ~$0;
	    say "DEBUG: \$CN = '$CN'" if $debug;
	}
	# SAN
	elsif $line ~~ /^ \s* 'DNS:' / {
	    my $s = $line;
	    # eliminate all 'DNS:' and commas
	    $s ~= /:g 'DNS:' //;
	    $s ~= /:g ',' //;
	    # what's left is one or more Subject Alternative names
	    # the first should be the same as the CN
	    @SAN = $s.words;
	    say "DEBUG: \@SAN = '{@SAN}'" if $debug;
	}
    }

    log-msg "-- Exiting sub '$sub'...";
    return $valid-days;
}
