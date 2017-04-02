# Net::ACME2
a Perl 6 Letsencrypt ACME client

I currently have a working Perl 6 solution for a Letsencrypt ACME (Automated Certificate 
Management Environment) client. 

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

