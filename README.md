# acme-check
automatically issues / validates / renews SSL certs listed in **nginx** / **vestaCP** / **OpenVZ Web Panel** configurations using Let's Encrypt ACME tool

# usage
perl acme-check.pl

# requirements
* perl
* socat
* curl (or wget)

# installation
* for Ubuntu / Debian:

 ```apt-get install socat curl -y```
 
* for Redhat / Fedora / CentOS:

```yum install perl socat -y```
