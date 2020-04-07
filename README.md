# acme-check
automatically issues / validates / renews SSL certs listed in **nginx** / **vestaCP** / **OpenVZ Web Panel** configurations using Let's Encrypt ACME tool

# usage
perl acme-check.pl <domain.com>

# usage (one-liner)
* for Ubuntu / Debian:

```apt-get install perl socat curl dnsutils -y && curl https://raw.githubusercontent.com/denisix/acme-check/master/acme-check.pl -o acme-check.pl && perl acme-check.pl```

* for Redhat / Fedora / CentOS:

```yum install perl socat bind-utils -y && curl https://raw.githubusercontent.com/denisix/acme-check/master/acme-check.pl -o acme-check.pl && perl acme-check.pl```

* in case of outdated curl / issues with curl, to use wget please export

```export ACME_USE_WGET=1```

# requirements
* perl
* socat
* curl (or wget)

# installation
* for Ubuntu / Debian:

 ```apt-get install perl socat curl -y```
 
* for Redhat / Fedora / CentOS:

```yum install perl socat -y```
