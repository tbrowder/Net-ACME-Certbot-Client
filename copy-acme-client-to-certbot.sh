#!/bin/bash

ADIR=/etc/ssl/acme
ADIR2=/etc/ssl/acme/private

if [[ -z $1 ]] ; then
    echo "Usage: $0 test | exe"
    echo
    echo "Tests or executes updating certbot client dirs with acme-client files."
    echo "  in directories '$ADIR' and '$ADIR2'."
    echo
    exit
fi

if [[ ! -d $ADIR ]] ; then
    echo "FATAL:  Dir '$ADIR' not found!"
    exit
elif [[ ! -d $ADIR2 ]] ; then
    echo "FATAL:  Dir '$ADIR2' not found!"
    exit
fi

EXE=
if [[ $1 = 'exe' ]] ; then
    EXE=1
    echo "Executing..."
else
    echo "Testing..."
fi

# # debugging
# if [[ -n $EXE ]] ; then
#     echo "EXE is defined"
# else
#     echo "EXE is NOT defined"
# fi
# echo "DEBUG exit"
# exit

# these domains are already in place:
#   mygnus.com
#   tbrowder.net
# these also need to be skipped:
#   ns1.tbrowder.net
#   ...

SKIP="\
mygnus.com \
tbrowder.net \
ns1.tbrowder.net \
"

# domains with good certs from acme-client:
ADOMS=$"\
canterburycircle.us \
computertechnwf.org \
mbrowder.com \
novco1968tbs.com \
nwflug.org \
psrr.info \
usafa-1965.org \
"

for dom in $ADOMS
do
    echo "Working $dom...";
    for s in $SKIP ; do
        if [[ $s = $dom ]] ; then
	    echo "NOTE:  Skipping domain '$s'"
	fi
    done

    SRCDIR=$ADIR/$dom
    if [[ ! -d $SRCDIR ]] ; then
	echo "FATAL:  Dir '$SCRDIR' not found!"
	exit
    fi

    SRCDIR2=$ADIR/private/$dom
    if [[ ! -d $SRCDIR2 ]] ; then
	echo "FATAL:  Dir '$SCRDIR2' not found!"
	exit
    fi

    # new files: chown root.root
    # new files: chmod 0400

    #=============================================================
    # this file is for the httpd server:
    # cp $ADIR/DOMAIN/fullchain.cer -> /etc/ssl/acme/DOMAIN/fullchain.pem
    # cp $ADIR/DOMAIN/fullchain.cer -> /etc/ssl/acme/DOMAIN/fullchain.pem
    TODIRPUB=/etc/ssl/acme/$dom
    if [[ ! -d $TODIRPUB ]] ; then
	echo "Creating dir '$TODIRPUB'..."
	if [[ -n $EXE ]] ; then
	    mkdir -p $TODIRPUB
	fi
    fi
    F1A=$SRCDIR/fullchain.cer
    F1B=$TODIRPUB/fullchain.pem
    echo "Copying file '$F1A' to"
    echo "             '$F1B'"
    if [[ ! -f $F1A ]] ; then
	echo "FATAL:  File '$F1A' not found!"
	exit
    fi
    if [[ -n $EXE ]] ; then
	cp $F1A $F1B
	chown root.root $F1B
	chmod 0400      $F1B
    fi

    #=============================================================
    # this file is for the httpd server:
    # cp $ADIR/DOMAIN/DOMAIN.key    -> /etc/ssl/acme/private/DOMAIN/privkey.pem
    TODIRPRIV=/etc/ssl/acme/private/$dom
    if [[ ! -d $TODIRPRIV ]] ; then
	echo "Creating dir '$TODIRPRIV'..."
	if [[ -n $EXE ]] ; then
	    mkdir -p $TODIRPRIV
	fi
    fi
    F2A=$SRCDIR/$dom.key
    F2B=$TODIRPRIV/privkey.pem
    echo "Copying file '$F2A' to"
    echo "             '$F2B'"
    if [[ ! -f $F2A ]] ; then
	echo "FATAL:  File '$F2A' not found!"
	exit
    fi
    if [[ -n $EXE ]] ; then
	cp $F2A $F2B
	chown root.root $F2B
	chmod 0400      $F2B
    fi


    #=============================================================
    # this file is for the bookkeeping to check the valid dates:
    # cp $ADIR/DOMAIN/DOMAIN.cer    -> /etc/ssl/acme/DOMAIN/cert.pem
    F3A=$SRCDIR/$dom.cer
    F3B=$TODIRPUB/cert.pem
    echo "Copying file '$F3A' to"
    echo "             '$F3B'"
    if [[ ! -f $F3A ]] ; then
	echo "FATAL:  File '$F3A' not found!"
	exit
    fi
    if [[ -n $EXE ]] ; then
	cp $F3A $F3B
	chown root.root $F3B
	chmod 0400      $F3B
    fi

done




#==========================================================
# for later use

# other domains (and hosts) with good acme-client certs
CDOMS="\
dedi2.tbrowder.net \
f-111.org \
freestatesofamerica.org \
highlandsprings61.org \
mail.tbrowder.net \
moody67a.org \
mygnus.com \
ns1.tbrowder.net \
ns2.tbrowder.net \
nwflorida.info \
nwfpug.nwflorida.info \
smtp.tbrowder.net \
tbrowder.net \
"

exit

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
