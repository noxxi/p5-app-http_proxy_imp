
use strict;
use warnings;
package DetectCrossOriginRedirect;
use base 'Net::IMP::HTTP::Request';
use fields qw(req);

use Net::IMP qw(:DEFAULT :log);
use Net::IMP::Debug;
use Carp;

sub RTYPES { ( IMP_PASS,IMP_LOG ) }

sub request_hdr {
    my ($self,$hdr) = @_;
    $self->{req} = $hdr;
    $self->run_callback( [ IMP_PASS,0,IMP_MAXOFFSET ]);
}

sub response_hdr {
    my ($self,$hdr) = @_;
    my $msg;
    {
	my ($code) = $hdr =~m{\AHTTP/1\.[01]\s+(30[1278]) } or last;
	my ($target) = $hdr =~m{^Location:\s*(.*(?:\n .*)*)\n}mi or last;
	$target =~m{^\w+://} or last; # relative path
	$target =~s{\s+$}{};
	$target =~s{^\s+}{};
	my ($met,$origin) = $self->{req} =~m{\A([A-Z]+)\s+(\S+)};
	if ($origin =~m{^/} and
	    my ($host) = $self->{req} =~m{^Host:\s*(.*(?:\n .*)*)\n}mi) {
	    $host =~s{\s+$}{};
	    $host =~s{^\s+}{};
	    $origin = "http://$host$origin";
	}

	#warn "XXX $met redirect from $origin to $target\n";
	my ($ohost) = lc($origin) =~m{^\w+://([^/]+)};
	my ($thost) = lc($target) =~m{^\w+://([^/]+)};
	last if $ohost eq $thost; # same origin

	if ($thost =~m{:.*:|^\d+\.\d+\.\d+\.\d+(?::\w+)$}
	    or $ohost =~m{:.*:|^\d+\.\d+\.\d+\.\d+(?::\w+)$} ) {
	    # origin or target is IPv4 or IPv6 address
	    $msg = "redirect(IP) $met from $ohost to $thost";
	    last;
	}

	# ignore if port differs
	$thost =~s{:\w+$}{};
	$ohost =~s{:\w+$}{};
	last if $thost eq $ohost;

	my @thost = reverse(split(/\.+/,$thost));
	my @ohost = reverse(split(/\.+/,$ohost));
	my @same;
	while (@thost && @ohost && $thost[0] eq $ohost[0]) {
	    shift(@ohost);
	    push @same, shift(@thost);
	}

	# if same is at least two labels we assume same origin
	# FIXME: use IO::Socket::SSL::PublicSuffix to check this
	if ( @same and @same >= (($same[0] =~m{\.(uk|tw)$}) ? 3:2) ) {
	    #warn "XXXX asume same origin between $ohost and $thost\n";
	    last;
	}

	$msg = "redirect $met from $ohost to $thost";
    }

    $self->run_callback([ IMP_LOG,1,0,0,IMP_LOG_WARNING,$msg ]) if $msg;
    $self->run_callback( [ IMP_PASS,1,IMP_MAXOFFSET ]);
}

# will not be called
sub response_body {}
sub request_body {}
sub any_data {}

1;

__END__

=head1 NAME

DetectCrossOriginRedirect - detects and logs cross-origin HTTP redirects 

=head1 SYNOPSIS

    perl bin/http_proxy_imp --filter DetectCrossOriginRedirect ip:port
