
############################################################################
# Request
############################################################################

use strict;
use warnings;

package App::HTTP_Proxy_IMP::Request;
use base 'Net::Inspect::L7::HTTP::Request::InspectChain';
use fields (
    'connected',  # is upstream already connected?
    'chunked',    # chunking status if we do chunked output (undef: not started)
    'resp_te',    # transfer encoding used to output response body: [C]hunked, 
                  # [E]of, [K]eep existing
    'acct',       # some accounting data
    'imp_filter', # App::HTTP_Proxy_IMP::IMP object
);
use Net::IMP::HTTP; # constants
use App::HTTP_Proxy_IMP::Debug qw(debug $DEBUG);

sub new_request {
    my ($self,$meta,$conn) = @_;
    my $obj = $self->SUPER::new_request($meta,$conn);
    $obj->{acct} = { Id => $obj->id };
    if ( my $factory = $conn->{imp_factory} ) {
	$obj->{imp_filter} = $factory->new_analyzer( $obj,$meta);
    }
    return $obj;
}

sub in_request_header {
    my $self = shift;

    # if we we have an open request inside this connection defer
    # the call and disable reading from client
    if ( my $spool = $self->{conn}{spool} ) {
	push @$spool,['in_request_header',@_];
	$self->{conn}{relay}->mask(0,r=>0);
	return 1;
    }

    my ($hdr,$time) = @_;
    my ($method) = $hdr =~m{^(\w+)};
    if ( $method !~ m{^(?:GET|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT)$} ) {
	$self->fatal("cannot handle method $method");
	return 1;
    }

    $self->{acct}{start} = $time;

    # FIXME add decompression only if we really need to inspect content
    $self->add_hooks('unchunk','uncompress_ce','uncompress_te');

    $self->add_hooks({
	name => 'fwd-data',
	request_header => sub {
	    my ($self,$data,$time) = @_;
	    if ( my $filter = $self->{imp_filter} ) {
		$filter->in(0,$$data,IMP_DATA_HTTPRQ_HEADER);
	    } else {
		goto &_inrqhdr_connect_upstream,
	    }
	},
	request_body => sub {
	    my ($self,$data,$eof,$time) = @_;
	    _send_and_remove($self,1,$data,IMP_DATA_HTTPRQ_CONTENT) 
		if $$data ne '';
	    _send($self,1,'',IMP_DATA_HTTPRQ_CONTENT) if $eof;
	    return '';
	},
	response_header => sub {
	    my ($self,$hdr,$time) = @_;
	    $self->{acct}{code} = $1 if $$hdr =~m{\AHTTP/1\.\d\s+(\d+)};

	    # if we might change data remove content-length
	    # and transfer content chunked if HTTP/1.1
	    my $filter = $self->{imp_filter};
	    my $hdr_changed =0;

	    if ( $filter && $filter->can_modify ) {
		$hdr_changed = 1 if $$hdr =~s{^Content-length:.*(\n[ \t].*)*\n}{}img;
		if ( $$hdr =~m{\A.* HTTP/1\.1\r?\n} ) {
		    $hdr_changed = 1;
		    $$hdr =~s{^Transfer-Encoding:.*(\n[ \t].*)*\n}{}img;
		    $$hdr =~s{\n}{\nTransfer-Encoding: chunked\r\n};
		    $self->{resp_te} = 'C';
		} else {
		    $self->{resp_te} = 'E';
		}
	    } else {
		$self->{resp_te} = 
		    $$hdr =~m{^Transfer-Encoding:\s*chunked}mi ? 'C' :
		    $$hdr =~m{^Content-length:}mi ? 'K' :
		    'E';
	    } 

	    _send($self,0,$$hdr,IMP_DATA_HTTPRQ_HEADER);
	    return $hdr_changed;
	},
	response_body => sub {
	    my ($self,$data,$eof,$time) = @_;
	    $self->xdebug("response_body len=".length($$data));
	    if ( $self->{resp_te} eq 'C' ) {
		# add chunk header
		if ( $$data ne '' ) {
		    $$data = sprintf("%s%x\r\n%s",
			$self->{chunked}++ ? "\r\n":"",  # CRLF after chunk
			length($data),                   # length as hex
			$$data
		    );
		}
		$$data .= "0\r\n\r\n" if $eof;
	    }
	    _send_and_remove($self,0,$data,IMP_DATA_HTTPRQ_CONTENT)
		if $$data ne '';
	    _send($self,0,'',IMP_DATA_HTTPRQ_CONTENT) if $eof;
	    return '';
	},
    });

    $self->{conn}{spool} ||= [];
    return $self->SUPER::in_request_header($hdr,$time);
}

sub in_request_body {
    my $self = shift;
    my $conn = $self->{conn};

    # defer call if we have another open request or if the current request
    # has no connected upstream yet
    my $spool = $conn->{spool} ||= ! $self->{connected} && [];
    if ($spool) {
	$self->xdebug("spooling request body");
	$conn->{relay}->mask(0,r=>0) if $_[1] ne ''; # data given
	push @$spool,['in_request_body',@_];
	return 1;
    }

    return $self->SUPER::in_request_body(@_);
}


sub in_data {
    my ($self,$from,$data,$eof,$time) = @_;
    # forward data to other side
    my $to = $from?0:1;
    $self->xdebug("%s bytes from %s to %s",length($data),$from,$to);
    _send($self,$to,$data,IMP_DATA_HTTPRQ_DATA) if $data ne '';
    if ($eof) {
	$self->{conn}{relay}->shutdown($from,0);
	# the first shutdown might cause the relay to close
	$self->{conn}{relay}->shutdown($to,1) if $self->{conn}{relay};
    }
    return length($data);
}

sub fatal {
    my ($self,$reason) = @_;
    warn "[fatal] ".$self->id." $reason\n";
    if ( my $conn = $self->{conn} ) {
	my $relay =  $conn->{relay};
	$relay->account(%{ $self->{meta}}, %{ $self->{acct}});
	$relay->close;
    }
}

sub in_response_body {
    my ($self,$data,$eof,$time) = @_;
    $self->xdebug("in_response_body len=".length($data));
    my $rv = $self->SUPER::in_response_body($data,$eof,$time);
    if ( $eof ) {
	$self->xdebug("end of response, te=$self->{resp_te}");
	$self->{conn}{relay}->account(%{ $self->{meta}}, %{ $self->{acct}});
	# any more spooled requests (pipelining)?
	if ( $self->{resp_te} eq 'E' ) {
	    # eof to signal end of request
	    $self->{conn}{relay}->close;
	    return $rv;
	}
	_call_spooled($self);
    }
    return $rv
}


sub _inrqhdr_connect_upstream {
    my ($self,$hdr,$time) = @_;
    my $req = $self->request_header;
    my $method = $req->method;
    my $uri = $req->uri;

    $self->{acct}{method} = $method;
    $self->{acct}{uri} = $uri;

    my $upstream = $self->{meta}{upstream};

    my $hdr_changed = 0;
    my ($proto,$host,$port,$page,$keep_alive);
    if ( $method eq 'CONNECT' ) {
	($host,$port) = $uri =~m{^(.*?)(?:\:(\d+))?$};
	$port ||= 443;
	$host =~s{^\[(.*)\]$}{$1};
	$proto = 'https';
	$page = '';
	# dont' forward anything, but don't change header :)
	$hdr = \( '' );
    } else {
	($proto,$host,$port,$page) = ($1,$2,$3||80,$4)
	    if $uri =~m{^(?:(\w+)://([^/\s]+?)(?::(\d+))?)?(/.*|$)};
	($proto,$host,$port) = ('http',$2,$3||80)
	    if ! $proto and
	    $req->header('Host') =~m{^(\S+?)(?:(\d+))?$};
	$proto or return $self->fatal('bad request: '.$$hdr),undef;
	return $self->fatal("bad proto: $proto"),undef
	    if $proto ne 'http';

	if ( $upstream ) {
	    # rewrite /page to method://host/page 
	    my $p = $port == 80 ? '':":$port";
	    $hdr_changed = 1 if $$hdr =~s{\A(\w+[ \t]+)(/)}{$1$proto://$host$p$2};
	    ($host,$port) = @$upstream;
	} else {
	    # rewrite method://host/page to /page
	    $hdr_changed = 1 if $$hdr =~s{\A(\w+[ \t]+)(\w+://[^/]+)}{$1};
	}

	# remove Proxy-Connection header
	$hdr_changed = 1 if $$hdr =~s{^Proxy-Connection:.*(\n[ \t].*)*\n}{}img;

	# try to reuse connection of possible
	$keep_alive = ($1 eq 'keep-alive') ? 1:0
	    while ( $$hdr =~m{\nConnection:[ \t]*(close|keep-alive)}ig );
	# implicit keep-alive in HTTP/1.1
	$keep_alive //= $$hdr =~m{\A.*HTTP/1\.1\r?\n}; 
    }

    $self->xdebug("new request $method $proto://$host:$port$page");
    $time ||= AnyEvent->now;
    my $connect_cb = sub {
	$self->{connected} = 1;
	$self->{acct}{ctime} = AnyEvent->now - $time;
	if ($$hdr ne '') {
	    _forward($self,0,1,$$hdr);
	} else {
	    # successful Upgrade, CONNECT.. - send OK to client
	    # fake that it came from server so that the state gets
	    # maintained in Net::Inspect::L7::HTTP
	    $self->{conn}->in(1,"HTTP/1.0 200 OK\r\n\r\n",0,$time);
	}
	$self->{conn}{relay}->mask(1,r=>1);
	_call_spooled($self, { in_request_body => 1 });
    };
    $self->{conn}{relay}->connect(1,$host,$port,$connect_cb,!$keep_alive);
    return $hdr_changed;
}

sub _call_spooled {
    my ($self,$filter) = @_;
    my $spool = $self->{conn}{spool} or return;
    $self->{conn}{spool} = undef;

    while ( @$spool and ! $self->{conn}{spool} ) {
	my ($method,@arg) = @{ $spool->[0] };
	if ( ! $filter or $filter->{$method} ) {
	    shift(@$spool);
	    $self->$method(@arg);
	} else {
	    last;
	}
    }

    # put unfinished requests back into spool
    unshift @{ $self->{conn}{spool} }, @$spool if @$spool;

    # enable read on client side again if nothing in spool
    $self->{conn}{relay}->mask(0,r=>1) if ! $self->{conn}{spool};
}



sub _send {
    my ($self,$to,$data,$type) = @_;
    my $from = $to ? 0:1;
    if ( my $filter = $self->{imp_filter} ) {
	$filter->in($from,$data,$type);
    } else {
	_forward($self,$from,$to,$data);
    }
}

sub _send_and_remove {
    my ($self,$to,$dataref,$type) = @_;
    _send($self,$to,$$dataref,$type);
    $$dataref = '';
}

sub _forward {
    my ($self,$from,$to,$data) = @_;
    $self->{acct}{"out$to"} += length($data);
    $self->{conn}{relay}->forward($from,$to,$data);
}


# callbacks from App::HTTP_Proxy_IMP::IMP --------------------------
# called on data to forward: (from,to,data)
*imp_forward = \&_forward;

# called when processing request header is done
sub imp_rqhdr {
    my ($self,$hdr,$changed) = @_;
    $self->request_header($hdr) if $changed;
    $self->_inrqhdr_connect_upstream(\$hdr);
}

# called on accounting
sub imp_acct {
    my ($self,$k,$v) = @_;
    $self->{acct}{$k} = $v
}

1;

