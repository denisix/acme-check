#!/usr/bin/perl
use warnings;
use strict;

my %files;
my %ssl;

my $debug = $ARGV[0] || '';
my $force_host = '';
if ($debug ne 'debug' && $debug =~ /\./) {
	$force_host = $debug;
}

if (not -e "/root/.acme.sh") {
	system("curl https://get.acme.sh | sh");
}

sub parse_nginx {
    my ($l, $file) = @_;

    if ($debug ne '') {
    	for(my $i=0;$i<=$l;$i++) { print " "; }
	print "$file\n";
    }

    return if defined $files{$file};
    $files{$file} = 1;
    $l++;

    if ($file =~ /\*/) {
        while(< $file >) {
            parse_nginx($l, $_);
        }
    } else {
	return if not -e $file;
	my @raw = ('');
        open my $fh, '<'. $file;
	if ($fh) {
		eval {
			#print "$file\n";
			@raw = <$fh>;
			close $fh;
		}
	}
	
        my($key, $crt) = ('', '');
        foreach $_ (@raw) {
            if (/server\s*{/) {
                ($key, $crt) = ('', '');
            }

            if (/ssl_certificate\s+(\S+)\;/) {
                $crt = $1;
				$crt =~ s/[\"\']+//g;
            }

            if (/ssl_certificate_key\s+(\S+)\;/) {
                $key = $1;
				$key =~ s/[\"\']+//g;
            }

            if ($key ne '' && $crt ne '') {
                print "- SSL [$crt] [$key]\n" if $debug ne '';
                $ssl{$crt} = $key;
                ($key, $crt) = ('', '');
            }

            if (/include\s+([\w\W\d\D\S]+)\;/) {
                parse_nginx($l, $1);
            }
        }
    }
    return;
}

sub check_cert_expire {
	my $crt = shift;

	return('y', $force_host, "let's encrypt") if $force_host ne '' && $crt =~ /$force_host/;

	if (! -e $crt) { 
		my $cn = substr $crt, ((rindex $crt, '/')+1);
		$cn =~ s/\.(crt|pem|cert)//g;
		return ('y', $cn, "let's encrypt");
	}

	open my $io, "openssl x509 -in $crt -noout -subject -issuer -checkend 777600 && echo OK || echo FAIL|";
    my ($exp, $cn, $issuer) = ('y', '', '');
    while(<$io>) {
        print "$_\n" if $debug ne '';
        $exp = 'n' if /OK/;
        if (/subject/i && /CN\s*\=\s*([\w\d\.\-]+)/) {
            $cn = $1;
        }

        if (/issuer/i && /O\s*\=\s*([^\/]+)/) {
            $issuer = $1;
        }
    }
	close $io;
	return($exp, $cn, $issuer);
}

parse_nginx 1, '/etc/nginx/nginx.conf' if -e "/etc/nginx/nginx.conf"; # NGINX
parse_nginx 1, '/usr/local/vesta/nginx/conf/nginx.conf' if -e '/usr/local/vesta/nginx/conf/nginx.conf'; # VESTA

# OpenVZ
if (-e '/opt/ovz-web-panel/config/certs/server.crt' && -e '/opt/ovz-web-panel/config/certs/server.key') {
    $ssl{'/opt/ovz-web-panel/config/certs/server.crt'} = '/opt/ovz-web-panel/config/certs/server.key';
}

# Custom
if (-e '/etc/ssl/custom.conf') {
    open FF, '</etc/ssl/custom.conf'; 
    while(<FF>) {
	if (/(\S+)\s+(\S+)/) {
	    print "custom: crt[$1] -> key[$2]\n" if $debug ne '';
	    $ssl{$1} = $2;
	}
    }
    close FF;
} else {
	if ($debug ne '') {
		print "custom format:\ncat /etc/ssl/custom.conf\ncrt key\n\n";
	}
}

# Force via cmdline
if ($force_host ne '') {
	print "- Forcing SSL generation for domain [$force_host]:\n";
	$ssl{"/etc/ssl/$force_host.crt"} = "/etc/ssl/$force_host.key";
}

foreach my $crt (keys %ssl) {
    my $key = $ssl{$crt};
    if ($debug ne '') {
	    print "\tcrt = [$crt]\n\tkey = [$key]\n\n";
    }

    my ($exp, $cn, $issuer) = check_cert_expire($crt);
    print "EXP [$exp] CN[$cn] ISSUER[$issuer]\n" if $debug ne '';

    if ($exp eq 'y' && $issuer =~ /let's encrypt/i) {
        print "EXP $cn\n";

        my @prog;
        push @prog, 'nginx' if -e '/etc/init.d/nginx';
		push @prog, 'exim' if -e '/etc/init.d/exim';
		push @prog, 'dovecot' if -e '/etc/init.d/dovecot';
		push @prog, 'pveproxy' if -e '/etc/init.d/pveproxy';
        push @prog, 'vesta' if $crt =~ /\/vesta\//;
        push @prog, 'owp' if $crt =~ /\/ovz-web-panel\//;

        foreach my $p (@prog) { system("/etc/init.d/$p stop || service $p stop"); }

    	system("cd .acme.sh; ( ./acme.sh --issue -k 4096 --standalone -d $cn --force || ./acme.sh --issue -k 4096 --standalone -d $cn --force --httpport 63219 ) &&
        		cat /root/.acme.sh/$cn/$cn.key > $key &&
	        	cat /root/.acme.sh/$cn/fullchain.cer > $crt && echo OK $cn");

        foreach my $p (@prog) { system("/etc/init.d/$p start || service $p start"); }
    }
}
