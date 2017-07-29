# Net::AcmeClient
a Perl 6 Let's Eencrypt ACME client

This module provides a wrapper around and extends the excellent C program **acme-client** by ??.
See http://?? for more details, source, and installations.
It is developed on a Debian 8 Linux host but should work on any Linux or similar OS.

## Background

Why another Let's Encrypt client?  The author had tried several but those all seemed to hide the 
gory details of the process from the user, or were too tightly coupled with servers
installed by package managers and couldn't easily be made to work with custom installed servers.
To make matters worse, most documentation was lacking in implementation details sufficient
for trouble-shooting.

Finally, the excellent C client **acme-client** by ?? was tried and was found to meet all this author's
requirements: transparent certificate file and directory structure, clear and detailed
documentation, and single-certificate execution without dependencies on other installed certificates.
In addition, ??'s serious atttention to security is a major benefit of his client.

## Extension's to **acme-client**

1 Net::AcmeClient is designed for the user who manages multiple domains, so the collection
  is treated as a group for status reporting and reissue. Status reporting is independent
  of **acme-client** so it can be done by an ordinary user.

2. To ensure the capability of handling multiple domains, the **-m** option to **acme-client**
   is always used (the author has submitted a PR to make that the standard behavior).

3. The user **may**  provide a configuration file to set desired options for his or her needs. A configuration file with
   the author's standard options is provided as a usable example shown below.

4. The user **must** provide a separate text file with each line providing the domain name plus any alternate names
   for each certificate (names must be separated on the line). Note that the first domain name on each
   line defines the common name (CN) in the certificate
   as well as the key for the database view by **Net::AcmeClient**. All names are treated as lower-case
   regardless of user-entry. An example file is shown below. 

## Dependencies

+ Proc::More (a published Perl 6 module to be installed by zef)

+ acme-client (install from source developed on OpenBSD but ported to Linux and similar OSs)

+ libbsd (install from source)

+ LibreSSL (install from source)

+ OpenSSL (normally available on most OSs)

## Input file examples

### Configuration file (optional)



### Domain file (required)








The current solution consists of: 

- **??.pm6** - Perl 6 module with code supporting the binary program

- **??** - a file to be inserted into the user's /etc/cron.d directory to run the binary program on
a desired schedule (user edits the file for the desired schedule). Note the Letsencrypt recommendation
is to run ACME clents twice daily.

- **??** - a file to deploy the binary and cron files to the host computer (must be executed as the root user)

- **??** - a file to remove the binary and cron files from the host computer (must be executed as the root user)

- **manip-certs.p6** - a Perl 6 program that wraps the **install** command of the excellent **Acme.sh**
client (which is written in shell).

- **MyDomains.p6** - a Perl module that has data structures containing the names and aliases of my
domains. That module will have to be copied and edited by the user for his or her own set of domains to be managed.
The users module 

## Installation

Although the module and programs are able to be installed using the **zef** installation tool,
it is recommended to download the latest release archive and install it in a local
directory for easier customization for the user's needs.

## References

1. Letsencrypt

(RFCs)


LICENCE and COPYRIGHT

