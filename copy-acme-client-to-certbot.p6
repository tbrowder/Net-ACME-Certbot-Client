#!/usr/bin/env perl6

my $TEST = 1;
my $BASEDIR;
if $TEST {
    $BASEDIR = '/usr/local/people/tbrowde/mydata/tbrowde-home-bzr/perl6/my-public-modules/github/Net-ACME-Certbot-Client-Perl6';
}
else {
    $BASEDIR = '';
}

my $ADIR  = "$BASEDIR/etc/ssl/acme";
my $ADIR2 = "$BASEDIR/etc/ssl/acme/private";

my $N = 1;

if !@*ARGS {
    say "Usage: $*PROGRAM test | exe [debug]";
    say "";
    say "Tests or executes updating certbot client dirs with acme-client files.";
    say "  in directories:";
    say "    '$ADIR'";
    say "    '$ADIR2'.";
    say "";
    exit;
}

if !$ADIR.IO.d {
    die "FATAL:  Dir '$ADIR' not found!";
}
elsif !$ADIR2.IO.d {
    die "FATAL:  Dir '$ADIR2' not found!";
}

my $EXE = 0;
my $debug = 0;
for @*ARGS {
    when /:i ^ e/ { $EXE = 1 }
    when /:i ^ t/ { $EXE = 0 }
    when /:i ^ d/ { $debug = 0 }
    default       { $EXE = 0 }
}

if $EXE {
    say "Executing..."
}
else {
    say "Testing..."
}

# # debugging
# if [[ -n $EXE ]] ; then
#     say "EXE is defined"
# else
#     say "EXE is NOT defined"
# fi
# say "DEBUG exit"
# exit

# these domains are already in place:
#   mygnus.com
#   tbrowder.net
# these also need to be skipped:
#   ns1.tbrowder.net
#   ...

my @SKIP=<
mygnus.com
tbrowder.net
ns1.tbrowder.net
>;

# domains with good certs from acme-client:
# UPDATE!!!
#canterburycircle.us
#computertechnwf.org
#mbrowder.com
my @ADOMS=<
novco1968tbs.com
nwflug.org
psrr.info
usafa-1965.org
>;

for @ADOMS -> $dom {
    say "Working acme-client domain $dom...";
    for @SKIP -> $s {
        if $s eq $dom {
	    say "NOTE:  Skipping domain '$s'"
	}
    }

    my $SRCDIR="$ADIR/$dom";
    if !$SRCDIR.IO.d {
	die "FATAL:  Dir '$SRCDIR' not found!";
    }

    my $SRCDIR2="$ADIR/private/$dom";
    if !$SRCDIR2.IO.d {
	die "FATAL:  Dir '$SRCDIR2' not found!"
    }

    # new files: chown root.root
    # new files: chmod 0400

    #=============================================================
    # this file is for the httpd server:
    # cp $ADIR/DOMAIN/cert.pem      -> /etc/letsencrypt/archive/DOMAIN/certN.pem
    # cp $ADIR/DOMAIN/chain.pem     -> /etc/letsencrypt/archive/DOMAIN/chainN.pem
    # cp $ADIR/DOMAIN/fullchain.pem -> /etc/letsencrypt/archive/DOMAIN/fullchainN.pem
    my $TODIR="$BASEDIR/etc/letsencrypt/archive/$dom";
    if !$TODIR.IO.d {
	say "Creating dir '$TODIR'...";
	if $EXE {
	    #mkdir -p $TODIR;
	    mkdir $TODIR;
	}
    }

    # don't forget the links to
    # /etc/letsencrypt/live/tbrowder.net/chain.pem -> ../../archive/tbrowder.net/chain1.pem
    #   /etc/letsencrypt/live/DOMAIN !!!!!!!!!!!!
    # achieved by: (cd /etc/letsencrypt/live/DOMAIN; ln -s ../../archive/DOMAIN/chain1.pem ./chain.pem)

    # /etc/letsencrypt/archive/DOMAIN/certN.pem # /etc/letsencrypt/archive/DOMAIN/certN.pem
    # /etc/letsencrypt/archive/DOMAIN/chainN.pem # /etc/letsencrypt/archive/DOMAIN/chainN.pem
    # /etc/letsencrypt/archive/DOMAIN/fullchainN.pem # /etc/letsencrypt/archive/DOMAIN/fullchainN.pem

    for <cert chain fullchain> -> $f {
        my $F1A="$SRCDIR/$f.pem";
        my $F1B="$TODIR/{$f}{$N}.pem";
        say "Copying file '$F1A' to";
        say "             '$F1B'";
        if !$F1A.IO.f {
            die "FATAL:  File '$F1A' not found!"
        }
        if $EXE {
	    copy $F1A, $F1B;
	    run "chown root.root $F1B".words;
            $F1B.IO.chmod: 0o0400;
        }
    }


    #=============================================================
    # this file is for the httpd server:
    # cp $ADIR/DOMAIN/cert.pem      -> /etc/letsencrypt/archive/DOMAIN/privkeyN.pem
    my $F2A = "$SRCDIR2/privkey.pem";
    my $F2B = "$TODIR/privkey{$N}.pem";
    say "Copying file '$F2A' to";
    say "             '$F2B'";
    if !$F2A.IO.d {
	die "FATAL:  File '$F2A' not found!";
    }
    if $EXE {
	copy $F2A, $F2B;
        run "chown root.root $F2B".words;
        $F2B.IO.chmod: 0o0400;
    }
}



exit

#==========================================================
# for later use

# other domains (and hosts) with good acme-client certs
my @CDOMS=<
dedi2.tbrowder.net
f-111.org
freestatesofamerica.org
highlandsprings61.org
mail.tbrowder.net
moody67a.org
mygnus.com
ns1.tbrowder.net
ns2.tbrowder.net
nwflorida.info
nwfpug.nwflorida.info
smtp.tbrowder.net
tbrowder.net
>;

=begin comment

#=================
# 8 acme domains to skip (add all subdomains to main domain):
nwfpug.nwflorida.info
mygnus.com
dedi2.tbrowder.net
tbrowder.net
mail.tbrowder.net
ns1.tbrowder.net
ns2.tbrowder.net
smtp.tbrowder.net

# ? domains to copy
mbrowder.com
usafa-1965.org
canterburycircle.us
nwflorida.info
nwflug.org
f-111.org
highlandsprings61.org
psrr.info
freestatesofamerica.org
novco1968tbs.com
moody67a.org
computertechnwf.org

/etc/letsencrypt/
/etc/letsencrypt/csr/
/etc/letsencrypt/accounts/
/etc/letsencrypt/keys/
/etc/letsencrypt/keys/0001_key-certbot.pem
/etc/letsencrypt/live/
/etc/letsencrypt/live/tbrowder.net
/etc/letsencrypt/live/tbrowder.net/chain.pem -> ../../archive/tbrowder.net/chain1.pem
/etc/letsencrypt/live/tbrowder.net/privkey.pem -> ../../archive/tbrowder.net/privkey1.pem
/etc/letsencrypt/live/tbrowder.net/README
/etc/letsencrypt/live/tbrowder.net/fullchain.pem -> ../../archive/tbrowder.net/fullchain1.pem
/etc/letsencrypt/live/tbrowder.net/cert.pem -> ../../archive/tbrowder.net/cert1.pem
/etc/letsencrypt/live/mygnus.com
/etc/letsencrypt/renewal/
/etc/letsencrypt/renewal/tbrowder.net.conf
/etc/letsencrypt/renewal/mygnus.com.conf
/etc/letsencrypt/archive/
/etc/letsencrypt/archive/tbrowder.net
/etc/letsencrypt/archive/tbrowder.net/fullchain1.pem
/etc/letsencrypt/archive/tbrowder.net/cert1.pem
/etc/letsencrypt/archive/tbrowder.net/privkey1.pem
/etc/letsencrypt/archive/tbrowder.net/chain1.pem
/etc/letsencrypt/archive/mygnus.com

=end comment
