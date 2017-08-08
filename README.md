# Net::ACME::Certbot::Client
a Perl 6 Let's Encrypt ACME client that uses the **certbot** client as its ACME interface 

This module provides a wrapper around and extends the excellent **certbot** client by
adding tools for managing multiple certificates.
It is developed on a Debian 8 (Jessie) Linux host but should work on any Linux or similar OS.

## Background

Why another Let's Encrypt client?  The author had tried several but those all seemed to hide the 
gory details of the process from the user, or were too tightly coupled with servers
installed by package managers and couldn't easily be made to work with custom installed servers.
To make matters worse, most documentation was lacking in implementation details sufficient
for trouble-shooting.

Finally, the author returned to the recommended client, **certbot**, and created wrappers to
satisfy his needs.

## Extensions to **certbot**

1 Net::ACME::Certbot::Client is designed for the user who manages multiple domains, so the collection
  is treated as a group for status reporting and reissue. Status reporting is independent
  of **certbot** so it can be done by an ordinary user.

3. The user **may**  provide a configuration file to set desired options for his or her needs. A configuration file with
   the author's standard options is provided as a usable example shown below.

4. The user **must** provide a separate text file with each line providing the domain name plus any alternate names
   for each certificate (names must be separated on the line). Note that the first domain name on each
   line defines the common name (CN) in the certificate
   as well as the key for the database view by **Net::ACME::Certbot::Client**. All names are treated as lower-case
   regardless of user-entry. An example file is shown below. 

## Dependencies

+ Proc::More (a published Perl 6 module to be installed by zef)

+ Text::More (a published Perl 6 module to be installed by zef)

+ certbot  (install per instructions on its website)

+ OpenSSL (normally available on most OSs)

## Input files

Input files are placed in the **/etc/acme-certbot-client** directory
and sub-directories.  All files are to be owned by root and read-only
for all other users.

### Configuration file (optional)

Configuration files are of two types: (1) a file for the client and (2) a file for a domain.
The client configuration file is expected to be named **/etc/acme-certbot-client/config** 
and domain-specific configuration files are expected to be named **/etc/acme-certbot-client/DOMAIN/config**.
Blank lines and all text from a '#' character to the end of a line are ignored.
All non-comment text lines are treated as lower-case.


The client configuration file can contain **acme-certbot-client** options as well as
**certbot** options.


```
# ACME-CERTBOT-CLIENT OPTIONS
# The default is to always require the CN to be in format 'DOMAIN.TLD'.
# This user wants to allow any format (not recommended):
allow-any-cn

# CERTBOT OPTIONS
[certbot] # <= the section tag is required in order to use **certbot** options
```


### Domain file (required)

The domain file is expected to be named **/etc/acme-certbot-client/domains** and consists of lines showing domain names for each 
certificate, one line per certificate. 
Blank lines and all text from a '#' character to the end of a line are ignored.
All non-comment text lines are treated as lower-case.

```
example.com www.example.com mail.example.com
foo.net www.foo.net ns1.foo.net ns2.foo.net
```






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

