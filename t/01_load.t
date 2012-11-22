#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 3;

eval 'use App::HTTP_Proxy_IMP';
cmp_ok( $@,'eq','', 'loading App::HTTP_Proxy_IMP' );

# check, that the plugins we ship can be loaded
# CSRFprotect needs additional modules, so don't test it here
for my $mod (qw( LogFormData Example::changeTarget)) {
    eval {
	my $app = App::HTTP_Proxy_IMP->start({
	    impns => ['App::HTTP_Proxy_IMP::IMP'],
	    filter => [$mod],
	    addr => '127.0.0.1:0', # pick any port
	});
    };
    cmp_ok( $@,'eq','', "setting up proxy with $mod" );
}
