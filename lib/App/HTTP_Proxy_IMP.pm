
use strict;
use warnings;

package  App::HTTP_Proxy_IMP;
use fields qw(addr impns filter pcapdir);

use App::HTTP_Proxy_IMP::IMP;
use App::HTTP_Proxy_IMP::Conn;
use App::HTTP_Proxy_IMP::Request;
use App::HTTP_Proxy_IMP::Relay;
use AnyEvent;
use Getopt::Long qw(:config posix_default bundling);
use App::HTTP_Proxy_IMP::Debug qw(debug $DEBUG $DEBUG_RX);
use Net::Inspect::Debug qw(%TRACE);
use Carp 'croak';

our $VERSION = '0.92';

# try IPv6 using IO::Socket::IP or IO::Socket::INET6
# fallback to IPv4 only
my $sockclass;
BEGIN {
    for(qw( IO::Socket::IP IO::Socket::INET6 IO::Socket::INET )) {
	if ( eval "require $_" ) {
	    $sockclass = $_;
	    last;
	}
    }
    $sockclass or die "cannot find usable socket class";
}


sub new {
    my ($class,@args) = @_;
    my $self = fields::new($class);
    $self->{impns} = [qw(App::HTTP_Proxy_IMP::IMP Net::IMP::HTTP Net::IMP)];
    %$self = %{ shift(@args) } if @args && ref($args[0]);
    $self->getoptions(@args) if @args;
    return $self;
}

sub start {
    my $self = shift;
    $self = $self->new(@_) or return if ! ref($self); # package->start

    my $pcapdir = $self->{pcapdir};
    if ( $pcapdir ) {
	croak("pcap directory not writeable") unless -d $pcapdir && -w _;
	eval { require Net::PcapWriter } or croak(
	    "cannot load Net::PcapWriter, which is needed with --pcapdir option");
    }
    my $imp_factory;
    my $filter = $self->{filter};
    if ($filter && @$filter ) {
	my $ns = $self->{impns};
	my @mod;
	for my $f (@$filter) {
	    if ( ref($f) ) {
		# already factory object
		push @mod,$f;
		next;
	    }

	    my $found;
	    for my $prefix ('', map { "${_}::" } @$ns) {
		my $mod = $prefix.$f;
		if ( eval "require $mod" ) {
		    $found = $mod;
		    last;
		}
	    }
	    croak("IMP module $f could not be loaded: $@") if ! $found;
	    push @mod,$found;
	}
	$imp_factory = App::HTTP_Proxy_IMP::IMP->new_factory(@mod);
    }

    # create connection fabric, attach request handling
    my $req  = App::HTTP_Proxy_IMP::Request->new;
    my $conn = App::HTTP_Proxy_IMP::Conn->new($req, 
	pcapdir     => $pcapdir, 
	imp_factory => $imp_factory
    );

    # add hooks for unchunking and decompression
    # FIXME - add these hooks dynamically if we want to inspect content
    # and not only header
    $req->add_hooks('unchunk','uncompress_te','uncompress_ce');


    # create listeners
    my @listen;
    $self->{addr} = [ $self->{addr} ] if $self->{addr} && ! ref($self->{addr});
    for my $addr (@{$self->{addr}}) {
	my ($addr,$upstream) = split('=',$addr,2);
	my $srv = $sockclass->new(
	    LocalAddr => $addr,
	    Listen    => 10,
	    ReuseAddr => 1,
	) or croak("cannot listen to $addr: $!");
	push @listen, AnyEvent->io(
	    fh => $srv,
	    poll => 'r',
	    cb => sub {
		my $cl = $srv->accept or return;
		App::HTTP_Proxy_IMP::Relay->new($cl,$upstream,$conn);
	    }
	);
    }

    # on SIGUSR1 dump state of all relays
    my $usr1 = AnyEvent->signal( signal => 'USR1', cb => sub {
	# temporaly enable debugging, even if off
	my $od = $DEBUG;
	$DEBUG = 1;
	debug("-------- active relays ------------------");
	my @relays = App::HTTP_Proxy_IMP::Relay->relays;
	debug(" * NO RELAYS") if ! @relays;
	$_->dump_state for(@relays);
	debug("-----------------------------------------");
	$DEBUG = $od;
    });

    my $usr2 = AnyEvent->signal( signal => 'USR2', cb => sub {
	if ( $DEBUG ) {
	    debug("disable debugging");
	    $DEBUG = 0;
	} else {
	    $DEBUG = 1;
	    debug("enable debugging");
	}
    });

    return 1 if defined wantarray;

    # enter Mainloop myself
    AnyEvent->condvar->recv;
}

sub getoptions {
    my $self = shift;
    local @ARGV = @_;
    GetOptions(
	'h|help'      => sub { usage() },
	'P|pcapdir=s' => sub { $self->{pcapdir} = $_[1] },
	'F|filter=s'  => sub { 
	    if ($_[1] eq '-') { 
		# discard all previously defined
		@{$self->{filter}} = ();
	    } else {
		push @{$self->{filter}}, $_[1]
	    }
	},
	'imp-ns=s'    => sub {
	    if ($_[1] eq '-') { 
		# discard all previously defined
		@{$self->{impns}} = ();
	    } else {
		push @{$self->{impns}}, $_[1]
	    }
	},
	'd|debug:s' => sub {
	    $DEBUG = 1;
	    if ($_[1]) {
		my $rx = eval { qr{$_[1]} };
		croak("invalid regex '$_[1]' for debugging: $@") if ! $rx;
		$DEBUG_RX = $rx;
	    }
	},
	'T|trace=s' => sub { 
	    $TRACE{$_} = 1 for split(m/,/,$_[1]) 
	},
    );

    my @addr = @ARGV;
    $self->{addr} or @addr or usage("no listener given");
    $self->{addr} = \@addr;
    1;
}


sub usage {
    my ($msg,$cmd) = @_;
    $cmd ||= $0;
    print STDERR "ERROR: $msg\n" if $msg;
    print STDERR <<USAGE;

HTTP proxy, which can inspect and modify requests and responses before
forwarding using Net::IMP plugins.

$cmd Options* [ip:port|ip:port=upstream_ip:port]+
ip:port - listen address(es) for the proxy
ip:port=upstream_ip:port - listen adress and upstream proxy 

Options:
  -h|--help        show usage
  -F|--filter F    add named IMP plugin as filter, can be used multiple times
                   with --filter mod=args arguments can be given to the filter
  --imp-ns N       perl module namespace, were it will look for IMP plugins.
                   Can be given multiple times.
		   Plugins outside these namespace need to be given with 
		   full name.
		   Defaults to App::HTTP_Proxy_IMP, Net::IMP
  
  # options intended for development and debugging:
  -P|--pcapdir D   save connections as pcap files into D, needs Net::PcapWriter
  -d|--debug [RX]  debug mode, if RX is given restricts debugging to packages
                   matching RX
  -T|--trace T     enable Net::Inspect traces

Examples:
start proxy at 127.0.0.1:8888 and log all requests to /tmp as pcap files
 $cmd --filter Net::IMP::SessionLog=dir=/tmp/&format=pcap  127.0.0.1:8888
start proxy at 127.0.0.1:8888 and log all form fields
 $cmd --filter LogFormData 127.0.0.1:8888
start proxy at 127.0.0.1:8888 with CSRF protection plugin
 $cmd --filter CSRFprotect 127.0.0.1:8888
start proxy at 127.0.0.1:8888 with CSRF protection plugin, using upstream 
proxy proxy:8888
 $cmd --filter CSRFprotect 127.0.0.1:8888=proxy:8888

USAGE
    exit(2);
}


1;
__END__

=head1 NAME

App::HTTP_Proxy_IMP - HTTP proxy with the ability to inspect and modify content

=head1 SYNOPSIS

    # only use cmdline args
    App::HTTP_Proxy_IMP->new(@ARGV)->start;             
    # only use given args
    App::HTTP_Proxy_IMP->new(\%options)->start;         
    # combine cmdline args with given defaults
    App::HTTP_Proxy_IMP->new(\%options,@ARGV)->start;   

    # short for App::HTTP_Proxy_IMP->new(...)->start;
    App::HTTP_Proxy_IMP->start(...);

    # show cmdline usage
    App::HTTP_Proxy_IMP->usage();
    
=head1 DESCRIPTION

App::HTTP_Proxy_IMP implements an HTTP proxy, which can inspect and modify the
HTTP header or content before forwarding. Inspection and modification is done
with plugins implementing the L<Net::IMP> interface.

The proxy is single-threaded and non-forking, but due to the event-driven model
it can still process multiple connections in parallel. It is mainly intended to
be used as a platform for easy prototyping of interesting ideas using IMP
plugins, but should be also fast enough to be used to enhance, secure, restrict
or protocol the browsing experience for small groups.

=head2 Public Methods

=over 4

=item * new([\%OPTIONS],[@ARGV])

Creates a new object.
The first argument might be an hash reference with options.
All other arguments will be used as ARGV for cmdline parsing and might result in
overwriting the defaults from OPTIONS.

The following options and its matching cmdline arguments are defined:

=over 8

=item filter ARRAY | -F|--filter mod

List of IMP filters, which should be used for inspection and modification.
These can be a fully qualified name, or a short name, which need to be combined
with one of the given namespace prefixes to get the full name.
It can also be already an IMP factory object.

The cmdline option can be given multiple times.
If '-' is given as name on the cmdline all previously defined filters are
discarded.

=item impns ARRAY | --imp-ns prefix

Namespace prefixes to make adding filters from cmdline shorter.
Defaults to L<App::HTTP_Proxy_IMP::IMP>, L<Net::IMP>.

The cmdline option can be given multiple times.
If '-' is given at cmdline all previously defined prefixes (including defaults) are
discarded.

=item addr ARRAY|ip:port

List of ip:port combinations or single ip:port.
These are the local addresses where the proxy will listen.

On the cmdline these are given as the remaining arguments, e.g. after all
other options.

=back

The following options are only for the cmdline

=over 8

=item -d|--debug [RX]

Enable debugging.
If RX is given it will be used as a regular expression to restrict debugging to
given packages.

Outside the cmdline these settings can be done by setting C<$DEBUG> and
C<$DEBUG_RX> exported by L<App::HTTP_Proxy_IMP::Debug>.

=item -T|--trace T

Enable tracing for L<Net::Inspect> modules.
Outside the cmdline these settings can be done by setting C<%TRACE> from the
L<Net::Inspect::Debug> package.

=back

=item start

Start the proxy, e.g. start listeners and process incoming connections.
No arguments are expected if called on an object, but one can use the form
C<< App::HTTP_Proxy_IMP->start(@args) >> as a shorter alternative to
C<< App::HTTP_Proxy_IMP->new(@args)->start >>.

If no return value is expected from this method it will enter into an endless
loop using C<< AnyEvent->condvar->recv >>.
If a value is expected it will return 1, and the caller hast to enter the
AnyEvent mainloop itself.

=head2 Reaction to Signals

The installs some signal handlers:

=over 4

=item SIGUSR1

Dump current state to STDERR, e.g. active connections and their state.

=item SIGUSR2

Toggles debugging (e.g. enable|disable).

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright 2012,2013 Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

