
use strict;
use warnings;
package App::HTTP_Proxy_IMP::IMP::FakeResponse;
use base 'Net::IMP::HTTP::Request';
use fields qw(root ignore response);

use Net::IMP;
use Net::IMP::Debug;
use Carp;

sub RTYPES { ( IMP_PASS,IMP_REPLACE,IMP_DENY,IMP_ACCTFIELD ) }

sub new_factory {
    my ($class,%args) = @_;
    my $dir = $args{root} or croak("no root directory given");
    -d $dir && -r _ && -x _ or croak("cannot use base dir $dir: $!");
    return $class->SUPER::new_factory(%args);
}

sub new_analyzer {
    my ($factory,%args) = @_;
    my $self = $factory->SUPER::new_analyzer(%args);
    return $self;
}


sub request_hdr {
    my ($self,$hdr) = @_;
    my $len = length($hdr) or return;

    my ($page) = $hdr =~m{\A\w+ +(\S+)};
    my $host = $page =~s{^\w+://([^/]+)}{} && $1;
    if ( ! $host ) {
	($host) = $hdr =~m{\nHost: *(\S+)}i or do {
	    $self->run_callback([ IMP_DENY,0,"cannot determine URI host"]);
	    return;
	};
    }
    my $port = $host=~s{^(?:\[(\w._\-:)+\]|(\w._\-))(?::(\d+))?$}{ $1 || $2 }e ? $3:80;

    my $dir = $self->{factory_args}{root};
    my $fh;
    for ( "$dir/$host:$port/$page", "$dir/$host/$page" ) {
	-f $_ && -r _ or next;
	open($fh,'<',$_) or next;
    }

    if ( ! $fh ) {
	# pass thru
	debug("no hijack http://$host:$port$page");
	$self->{ignore} = 1;
	$self->run_callback( 
	    # pass thru everything 
	    [ IMP_PASS,0,IMP_MAXOFFSET ], 
	    [ IMP_PASS,1,IMP_MAXOFFSET ], 
	);
	return;
    }

    $self->{response} = do { local $/; <$fh>; };
	
    $hdr =~s{(\A\w+\s+)(\S+)}{$1internal://imp};
    debug("hijack http://$host:$port$page");
    $self->run_callback(
	[ IMP_ACCTFIELD,'orig_uri',"http://$host:$port$page" ],
	[ IMP_REPLACE,0,$len,$hdr ],
	[ IMP_PASS,0,IMP_MAXOFFSET ]
    );
}

my $response_body = "alert('pOwned!')";
sub response_hdr {
    my ($self,$hdr) = @_;
    $self->{ignore} and return;
    my $len = length($hdr);
    my $rphdr = $self->{response} =~s{^(.*?(\r?)\n\2\n)}{}s && $1;
    $rphdr =~s{\r?\n}{\r\n}g;
    $rphdr =~s{(\nContent-length:[ \t]*)\d+}{ $1.length($self->{response}) }e;
    $self->run_callback([ IMP_REPLACE,1,$len,$rphdr ]);
}

sub response_body {
    my ($self,$data) = @_;
    $self->{ignore} and return;
    if ( $self->{response} eq '' ) {
	$self->run_callback([ IMP_REPLACE,1,$self->offset(1),'' ])
	    if $data ne '';
    } else {
	debug("replace data up to offset=%d", $self->offset(1) );
	$self->run_callback([ IMP_REPLACE,1,$self->offset(1),$self->{response} ]);
	$self->{response} = '';
    }
}

# will not be called
sub request_body {}
sub any_data {}

1;

__END__

=head1 NAME 

App::HTTP_Proxy_IMP::IMP::FakeResponse - return alternativ response header and
body for specific URIs

=head1 SYNOPSIS

  # listen on 127.0.0.1:8000 
  # to hijack google analytics put alternative response into 
  # myroot/www.google-analytics.com/ga.js or
  # myroot/www.google-analytics.com:80/ga.js or

  $ perl bin/imp_http_proxy --filter FakeResponse=root=myroot 127.0.0.1:8000


=head1 DESCRIPTION

This module is used to hijack specific URIs and return a different response.
It works by replacing the origin target in the request header with
internal://imp, which causes L<App::IMP_HTTP_Proxy_IMP> to inject a dummy HTTP
response header and body into the data stream, instead of contacting the
original server.
This dummy response is than replaced with the alternative response.

The module has a single argument C<root> for C<new_analyzer>. 
C<root> specifies the base directory, where the alternative responses are
located. 
When getting a request for http://host:port/page it will search inside C<root>
for a file named either C<host:port/page> or C<host/page> and return this as
response.
The response file should include HTTP header and body, any Content-length header
will be corrected to have the correct value for the response body.


=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>
