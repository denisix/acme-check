# acme-check
automatically issues / validates / renews SSL certs listed in **nginx** / **vestaCP** / **OpenVZ Web Panel** configurations using Let's Encrypt ACME tool

# usage
perl acme-check.pl

# usage (one-liner)
* for Ubuntu / Debian:

```apt-get install perl socat curl -y && curl https://raw.githubusercontent.com/denisix/acme-check/master/acme-check.pl -o acme-check.pl && perl acme-check.pl```

* for Redhat / Fedora / CentOS:

```yum install perl socat -y && curl https://raw.githubusercontent.com/denisix/acme-check/master/acme-check.pl -o acme-check.pl && perl acme-check.pl```


# requirements
* perl
* socat
* curl (or wget)

# installation
* for Ubuntu / Debian:

 ```apt-get install perl socat curl -y```
 
* for Redhat / Fedora / CentOS:

```yum install perl socat -y```
