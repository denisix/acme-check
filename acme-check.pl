#!/usr/bin/perl
use warnings;
use strict;
use Cwd 'abs_path';
my $myscript = abs_path($0);

my %files;
my %ssl;

my $debug = $ARGV[0] || '';
my $force_host = '';
if ($debug ne 'debug' && $debug =~ /\./) {
	$force_host = $debug;
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
			next if /^#/;

			if (/server\s*{/) {
				($key, $crt) = ('', '');
			}

			if (/ssl_certificate\s+(\S+)\;/) {
				$crt = $1;
			}

			if (/ssl_certificate_key\s+(\S+)\;/) {
				$key = $1;
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

	open my $io, "openssl x509 -in $crt -noout -subject -issuer -checkend 259200 && echo OK || echo FAIL|";
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

	return ('n', '', '') if $cn eq '' || $cn eq 'localhost' || $cn !~ /[\w\d\-]+\.[\w\d]+/;

	return($exp, $cn, $issuer);
}

parse_nginx 1, '/etc/nginx/nginx.conf' if -e "/etc/nginx/nginx.conf"; # NGINX
parse_nginx 1, '/srv/nginx/conf.d/*' if -e "/srv/nginx/conf.d"; # NGINX DOCKER
parse_nginx 1, '/srv/nginx/data/conf.d/*' if -e "/srv/nginx/data/conf.d"; # NGINX DOCKER
parse_nginx 1, '/usr/local/vesta/nginx/conf/nginx.conf' if -e '/usr/local/vesta/nginx/conf/nginx.conf'; # NGINX VESTA

# OpenVZ
if (-e '/opt/ovz-web-panel/config/certs/server.crt' && -e '/opt/ovz-web-panel/config/certs/server.key') {
	$ssl{'/opt/ovz-web-panel/config/certs/server.crt'} = '/opt/ovz-web-panel/config/certs/server.key';
}

# Check SSL directory
while(</etc/ssl/*.crt>) {
	my $crt = $_;
	my $key = $_; $key =~ s/\.crt$/.key/;
	if (-f $key) {
		$ssl{$crt} = $key;
	}
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

my @exp;
foreach my $crt (keys %ssl) {
	my $key = $ssl{$crt};
	if ($debug ne '') {
		print "\tcrt = [$crt]\n\tkey = [$key]\n\n";
	}

	my ($exp, $cn, $issuer) = check_cert_expire($crt);
	print "EXP [$exp] CN[$cn] ISSUER[$issuer]\n" if $debug ne '';

	if ($exp eq 'y' && $issuer =~ /let's encrypt/i) {
		#print "EXP $cn\n";
		push @exp, [$cn,$crt,$key];
	}
}

if ($#exp eq -1) {
	print "- nothing to renew, exiting\n";
	exit 0;
}

print "- updating ACME\n";
system("rm -rf /root/.acme.sh") if -e "/root/.acme.sh";
system("curl https://get.acme.sh | sh");

print "- cleanup ACME from root crontab\n";
system("(crontab -u root -l | grep -v '/root/.acme.sh')|crontab -u root -");
system("crontab -u root -l | grep -q $myscript || (crontab -u root -l; echo '0 4 */2 * * perl $myscript >/dev/null 2>&1') | crontab -u root -");

my @prog;
push @prog, 'nginx' if -e '/etc/init.d/nginx';
push @prog, 'exim' if -e '/etc/init.d/exim';
push @prog, 'dovecot' if -e '/etc/init.d/dovecot';
push @prog, 'pveproxy' if -e '/etc/init.d/pveproxy';
push @prog, 'vesta' if -e '/usr/local/vesta';
push @prog, 'owp' if -e '/opt/ovz-web-panel';
foreach my $p (@prog) { system("/etc/init.d/$p stop || service $p stop") }

my @dockers;
if (-e '/usr/bin/docker') {
	open IO, 'docker ps --format {{.ID}} --filter publish=443/tcp --filter publish=80/tcp|';
	while(<IO>) {
		if (/([0-9a-f]{12})/) {
			my $id = $_;
			push @dockers, $id;
			print "- stoping docker $id\n";
			system("docker stop $id");
		}
	}
	close IO;
}


foreach my $x (@exp) {
	my ($cn, $crt, $key) = @{$x};
	print "-> RENEW: $cn\n";

	system("cd .acme.sh && \
		( ./acme.sh --issue -k 4096 --standalone -d $cn --force || ./acme.sh --issue -k 4096 --standalone -d $cn --force --httpport 63219 ) && \
		cat /root/.acme.sh/$cn/$cn.key > $key && \
		cat /root/.acme.sh/$cn/fullchain.cer > $crt && \
		echo OK $cn");
}

foreach my $p (@prog) { system("/etc/init.d/$p start || service $p start") }
foreach my $id (@dockers) { print "- starting docker $id\n"; system("docker start $id") }

# restart docker containters that have '/etc/ssl' volumes:
open IO, 'docker ps --filter volume=/etc/ssl --format {{.ID}}|';
while(<IO>) {
	if (/([0-9a-f]{12})/) {
		my $id = $_;
		my @f = grep /$id/, @dockers;
		if ($#f eq -1) {
			print "- restarting docker $id (has /etc/ssl volume)\n";
			system("docker restart $id");
		}
	}
}
close IO;
