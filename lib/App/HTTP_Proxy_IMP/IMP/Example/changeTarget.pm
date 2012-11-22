# sample IMP plugin to change target host by replacing request header
# for this example it get changed to spiegel.de - whatever we want to access
# THIS IS JUST A SILLY EXAMPLE!!!!

use strict;
use warnings;
package App::HTTP_Proxy_IMP::IMP::Example::changeTarget;
use base 'Net::IMP::Base';
use fields qw(rqhdr_done);

use Net::IMP;
use Net::IMP::Debug;

my $target = 'www.spiegel.de';
sub USED_RTYPES { ( IMP_PASS ) }

sub new_analyzer {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new_analyzer(%args);
    $self->run_callback(
	# we don't need to look at response
	[ IMP_PASS,1,IMP_MAXOFFSET ],
    );
    return $self;
}

sub data {
    my ($self,$dir,$data) = @_;

    # we should not get these except for eof
    return if $self->{rqhdr_done} or $dir == 1;

    # we except to get the full request header inside the first packet,
    # because the proxy handles it this way
    my $len = length($data) or return;
    $data =~s{\A(\S+\s+http://)([^\s/]+)}{$1$target}; # first line absoluteURI
    $data =~s{^Host:\s*(.*)}{Host: www.spiegel.de}mi; # host header
    $self->{rqhdr_done} = 1;
    $self->run_callback( 
	[ IMP_REPLACE,0,$len,$data ], # replace header
	[ IMP_PASS,0,IMP_MAXOFFSET ], # pass thru everything else
    );
}

1;

__END__

=head1 NAME 

App::HTTP_Proxy_IMP::IMP::Example::changeTarget - example plugin to change
request target

=head1 DESCRIPTION

This module is just a simple example, how one can write an IMP module, which
changes the request target. In this example all requests will have the target
host changed to www.spiegel.de, but preserving the path of the URI.

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>
