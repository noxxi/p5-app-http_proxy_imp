
use strict;
use warnings;
package ABBFilter;
use base 'Net::IMP::HTTP::Request';
use fields qw(https);

use Net::IMP;
use Net::IMP::Debug;

sub RTYPES { ( IMP_PASS,IMP_DENY ) }

sub new_factory {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new_factory(%args);
    @{$self->{factory_args}}{qw(white black)} = 
	_compile_abblist($self->{factory_args}{files});
    return $self;
}

sub new_analyzer {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new_analyzer(%args);
    $self->{factory_args}{black} or $self->run_callback(
	# if we have no rx pass everything through
	[ IMP_PASS,0,IMP_MAXOFFSET ]
    );
    return $self;
}

sub validate_cfg {
    my ($class,%cfg) = @_;
    delete $cfg{files};
    return $class->SUPER::validate_cfg(%cfg);
}

sub request_hdr {
    my ($self,$hdr) = @_;
    my ($met,$url) = $hdr =~m{\A([A-Z]+)\s+(\S+)};
    if ($met eq 'CONNECT') {
	$url =~s{:443$}{};
	$url = "https://$url/";
    } elsif ($url =~m{^/} and
	my ($host) = $hdr =~m{^Host:\s*(.*(?:\n .*)*)\n}mi) {
	$host =~s{\s+$}{};
	$host =~s{^\s+}{};
	$url = "http://$host$url";
    }
    $url =~s{^http:}{https:} if $self->{https};

    if ( ! $self->{factory_args}{white} || $url !~ $self->{factory_args}{white}
	and $url =~ $self->{factory_args}{black} ) {
	# match: deny
	$self->run_callback([ IMP_DENY,0,"URL blocked by ABBList - $url" ]); 
    } else {
	# no match: pass thru everything else
	$self->run_callback([ IMP_PASS,0,IMP_MAXOFFSET ]); 
    }

    if ($met eq 'CONNECT' && ! $self->{https}) {
	$self->{https} = 1;
    } else {
	$self->run_callback(
	    # we don't need to look at response
	    [ IMP_PASS,1,IMP_MAXOFFSET ]
	);
    }
}

sub response_hdr {
    my ($self,$hdr) = @_;
    $self->{https} or return;
    $self->{https}++ == 1 or return;
    $self->{https} = 0 if $hdr !~m{\AHTTP/1\.[01] 2\d\d}; # tunnel failed
    $self->run_callback( [ IMP_PASS,1,IMP_MAXOFFSET ]); # done with response
}

# see https://adblockplus.org/en/filter-cheatsheet
sub _compile_abblist {
    my $files = shift;
    my (@black,@white);
    for my $file ( split(/,/, $files )) {
	open( my $fh,'<',$file) or die "open $file: $!";
	while (<$fh>) {
	    m{^!} and next; # comment
	    s{\s+$}{};
	    my $line = $_;
	    my $list;
	    if (m{^\@\@}) {
		$list = \@white;
		s{\$.*}{}; # ignore restrictions on whitelist
	    } else {
		m{\$} and next; # we don't understand options, ignore entry
		$list = \@black;
	    }
	    if (m{^\|(.*)\|}) {                  # |exact_url|
		push @$list, qr{^\Q$_\E$};
	    } else {
		my $anchored = s{^\|\|}{};
		s{([.?+()\x5d\x5b\\|])}{\\$1}g;   # escape special chars
		s{\^}{(?:[/:?].*|\$)};           # ^ - seperator or end
		s{\*}{.*}g;                      # * - wildcard
		if ($anchored) {
		    # anchored within domain name
		    $_ = "^https?://(?:[^/:]+\.)?$_";
		}
		my $rx = eval { qr/$_/ };
		die "$line | qr/$_/ | $@\n" if !$rx;
		push @$list, $rx;
	    }
	}
    }
    my $white = join("|",@white);
    $white = qr{$white} if $white;
    my $black = join("|",@black);
    $black = qr{$black} if $black;
    warn "XXX read $files #white=".(+@white)." #black=".(+@black)."\n";
    return ( $white,$black );
}

# will not be called
sub request_body {}
sub response_body {}
sub any_data {}

1;

__END__

=head1 NAME

ABBFilter - uses AdBlockPlus List to filter requests by URL

=head1 SYNOPSIS

    perl bin/http_proxy_imp --filter ABBFilter=files=easy-list.txt,file2.txt ip:port
