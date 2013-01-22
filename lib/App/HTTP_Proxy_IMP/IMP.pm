use strict;
use warnings;

package App::HTTP_Proxy_IMP::IMP;
use fields (
    'factory',   # factory from new_factory
    'analyzer',  # analyzer from new_analyzer
    'can_modify',# true if analyzer supports IMP_REPLACE or IMP_TOSENDER 
    'request',   # privHTTPrequest object (weak ref)
    # data, which might be modified be current inspection, need to be buffered
    # until we get the final decision
    'buf',       # per dir list of [pos,data,type] entries, with pos being the
		 # position of end of buf relative to input stream
    'inspos',    # position up to which data got forwarded to inspection (per dir)
    'canpass',   # can pass up to this position (for pass in future), per dir
    'prepass',   # canpass is for IMP_PREPASS, not IMP_PASS, per dir
);

use Net::Inspect::Debug qw(:DEFAULT $DEBUG);
use Net::IMP::Debug var => \$DEBUG, sub => \&debug;
use Net::IMP;
use Net::IMP::HTTP;
use Scalar::Util qw(weaken dualvar);
use Carp;

# we want plugins to suppport the HTTP Request innterface
my $interface = [
    IMP_DATA_HTTPRQ,
    [ 
	IMP_PASS,
	IMP_PREPASS,
	IMP_REPLACE,
	IMP_TOSENDER,
	IMP_DENY,
	IMP_LOG,
	IMP_ACCTFIELD,
    ]
];

sub can_modify {
    return shift->{can_modify};
}

# create a new factory object
sub new_factory {
    my ($class,@mod) = @_;
    my @factory;
    for my $module (@mod) {
	if ( ref($module)) {
	    # assume it is already an IMP factory object
	    push @factory, $module;
	    next;
	}

	# --filter mod=args
	my ($mod,$args) = $module =~m{^([a-z][\w:]*)(?:=(.*))?$}i
	    or die "invalid module $module";
	eval "require $mod" or die "cannot load $mod args=$args: $@";
	my %args = $mod->str2cfg($args//'');
	my $factory = $mod->new_factory(%args) 
	    or croak("cannot create Net::IMP factory for $mod");
	$factory = $factory->set_interface( $interface )
	    or croak("$mod does not implement the interface supported by us");
	push @factory,$factory;
    }

    @factory or return;
    if (@factory>1) {
	# for cascading filters we need Net::IMP::Cascade
	require Net::IMP::Cascade;
	my $cascade = Net::IMP::Cascade->new_factory( parts => [ @factory ]) 
	    or croak("cannot create Net::IMP::Cascade factory");
	@factory = $cascade;
    }

    my App::HTTP_Proxy_IMP::IMP $self = fields::new($class);
    $self->{factory} = $factory[0]->set_interface( $interface ) or 
	croak("factory[0] does not implement the interface supported by us");

    $self->{can_modify} = 0;
    CHKIF: for my $if ( $self->{factory}->get_interface ) {
	my ($dt,$rt) = @$if;
	for (@$rt) {
	    $_ ~~ [ IMP_REPLACE, IMP_TOSENDER ] or next;
	    $self->{can_modify} =1;
	    last CHKIF;
	}
    }
	
    return $self;
}

# create a new analyzer based on the factory
sub new_analyzer {
    my App::HTTP_Proxy_IMP::IMP $factory = shift;
    my ($request,$meta) = @_;

    # IMP plugins use different schema in meta than Net::Inspect
    my %meta = %$meta;
    $meta{$_->[1]} = delete $meta{$_->[0]} for(
	[ saddr => 'caddr' ], [ sport => 'cport' ], # [s]rc -> [c]lient
	[ daddr => 'saddr' ], [ dport => 'sport' ], # [d]st -> [s]erver
    );
    my $anl = $factory->{factory}->new_analyzer( meta => \%meta );

    my App::HTTP_Proxy_IMP::IMP $self = fields::new(ref($factory));
    %$self = (
	request    => $request,
	analyzer   => $anl,
	can_modify => $factory->{can_modify},
	buf        => [[ [0,'',undef] ],[ [0,'',undef] ]],
	inspos     => [0,0],
	canpass    => [0,0],
	prepass    => [0,0],
    );
    weaken($self->{request});
    weaken( my $wself = $self );
    $anl->set_callback( \&_imp_callback,$wself );

    return $self;
}

# process data
# called from Request.pm
# if we had IMP_PASS or IMP_PREPASS with an offset into the future we might
# forward received data instead or parallel to sending them to the inspection
sub in {
    my App::HTTP_Proxy_IMP::IMP $self = shift;
    my ($dir,$data,$type) = @_;
    my $anl = $self->{analyzer} or die;

    # FIXME: offset of 0 might not be correct
    return $anl->data($dir,'',0,$type) if $data eq ''; # eof

    # add data to buf
    my $buf = $self->{buf}[$dir];
    my $lastbuf = $buf->[-1];
    if ( ! defined $lastbuf->[2] ) {
	# dummy buf to preserve position in stream
	# set data and type
	$lastbuf->[1] = $data;
	$lastbuf->[2] = $type;
    } elsif ( $type < 0 and $type == $lastbuf->[2] ) {
	# streaming data: concatinate to existing buf
	$buf->[-1][1] .= $data;
    } else {
	# non-streaming, add new buf
	push @$buf, [
	    $lastbuf->[1] + length($lastbuf->[0]), # begin = end of last buf
	    $data,
	    $type
	];
    }

    my @inspect;

    # if we got a canpass in the future we can forward some data already
    # in case we are in prepass mode this will result in some data for
    # inspection
    @inspect = _fwdbuf($self,$dir) if $self->{canpass}[$dir];

    # if there is something to inspect, which we did not send to inspection
    # it has to be from the current call and should relate only to the last
    # entry in buf
    # send the trailing data from last buf to inspection, but at most 
    # length($data) (e.g. what we got in this call)
    # there should be no overlap with data already in @inspect, because they
    # got added only if prepass and got then removed from @$buf
    $lastbuf = $buf->[-1];
    if ( defined $lastbuf->[2] ) {
	my $len = length($data);
	my $blen = length($lastbuf->[1]);
	if ( $blen <= $len ) {
	    # full buffer
	    push @inspect, $lastbuf;
	} else {
	    # part of buffer
	    push @inspect, [
		$lastbuf->[0] + $blen - $len,
		substr( $lastbuf->[1],-$len,$len),
		$type
	    ];
	}
    }

    if (@inspect) {
	# add offset for previously passed data if necessary
	my $inspos = $self->{inspos}[$dir];
	while ( my $insp = shift @inspect) {
	    $self->{analyzer}->data(
		$dir,
		$insp->[1],   # data
		$inspos > $insp->[0] ? $insp->[0]:0, # offset || no gap
		$insp->[2],   # type
	    );
	    $inspos = $insp->[0] + length($insp->[1]);
	}
	$self->{inspos}[$dir] = $inspos;
    }
}

sub _fwdbuf {
    my App::HTTP_Proxy_IMP::IMP $self = shift;
    my ($dir,@modified) = @_;
    my $buf = $self->{buf}[$dir];
    my $canpass = $self->{canpass}[$dir];

    my @fwd;
    debug("dir=$dir canpass=$canpass buf.n=".int(@$buf)." mod.n=".int(@modified));
    if ( $canpass == IMP_MAXOFFSET ) {
	# fwd everything, but keep/insert dummy buf
	debug("forward everything because of IMP_MAXOFFSET dir=$dir");
	push @fwd,@$buf;
	if ( ! defined $fwd[-1][2] ) {
	    # don't fwd dummy buf
	    debug("don't forward dummy buf");
	    @$buf = pop(@fwd);
	} else {
	    # no dummy buf, create one with position at end of last buf
	    debug("create new dummy buf");
	    @$buf = [ $fwd[-1][0] + length($fwd[-1][1]),'',undef ];
	}

    } elsif ( $canpass ) {
	my $end = 0;
	debug("can pass up to $canpass");
	while ( @$buf and $canpass > $buf->[0][0] ) {
	    my $buf0 = $buf->[0];
	    last if ! defined $buf0->[2]; # no content
	    $end = $buf0->[0] + length($buf0->[1]);
	    if ( $canpass >= $end ) {
		# fwd full packet, remove from @$buf
		push @fwd,$buf0;
		shift(@$buf);
	    } elsif ( $buf0->[2] < 0 ) {
		# streaming - we can split buffer
		my $fwd = [
		    $buf0->[0], # keep start pos
		    # remove leadings bytes from buf0 and fwd them
		    substr($buf0->[1],0,$canpass-$end,''),
		    $buf0->[2], # keep type
		];
		# adjust position of remaining buf
		$buf0->[0] += length($fwd->[1]);
		# fwd part of data ($fwd), keep rest ($buf0) in @$buf
		push @fwd,$fwd;
	    } else {
		# non-streaming but canpass is not at chunk boundary
		croak("future (pre)pass offsets need to be at chunk boundary for non-streaming data");
	    }
	}
	if ( ! @$buf ) {
	    # all eaten, insert new dummy to maintain position
	    @$buf = [ $end,'',undef ];
	}

	# reset canpass if we reached it
	$self->{canpass}[$dir] = 0 if $canpass <= $end;
    }

    # do we need to inspect fwd content because of prepass ?
    my $inspos = $self->{prepass}[$dir] ? $self->{inspos}[$dir] : undef;


    my @inspect;
    push @fwd,@modified;
    while ( my $fwd = shift @fwd) {
	my ($pos,$data,$type,$changed) = @$fwd;
	if ( $dir == 0 and $type == IMP_DATA_HTTPRQ_HEADER ) {
	    $self->{request}->imp_rqhdr($data,$changed);
	} else {
	    $self->{request}->imp_forward($dir,$dir?0:1,$data);
	}
	if ( defined $inspos ) {
	    my $end = $pos + length($data);
	    if ( $inspos < $end ) {
		# not yet forwarded to inspection
		# buffers should already be created so that inspos,canpass..
		# are at chunk boundaries
		my $start = $pos - $inspos;
		die "pos($pos)-inspos($inspos) != 0" if $start != 0;
		push @inspect,$fwd;
		$inspos = $end;
	    }
	}
    }
    return @inspect
}

sub _imp_callback {
    my App::HTTP_Proxy_IMP::IMP $self = shift;
    my $req = $self->{request};

    for my $rv (@_) {
	my $typ = shift(@$rv);
	my ($fwd,$changed);
	if ( $typ == IMP_ACCTFIELD ) {
	    my ($k,$v) = @$rv;
	    $req->imp_acct($k,$v);
	    $req->xdebug("acct $k=$v");
	} elsif ( $typ == IMP_DENY ) {
	    my ($dir,$msg) = @$rv;
	    if ( defined $msg ) {
		$req->xdebug("deny($dir): $msg");
		$req->fatal($msg);
	    } else {
		$req->xdebug("deny($dir)");
		$req->{conn}{relay}->close;
	    }
	} elsif ( $typ == IMP_LOG ) {
	    my ($dir,$offset,$len,$lvl,$msg) = @$rv;
	    $req->xdebug("log($lvl,$dir): $msg");

	} elsif ( $typ ~~ [ IMP_PASS, IMP_PREPASS ] ) {
	    my ($dir,$offset) = @$rv;
	    my $canpass = $self->{canpass}[$dir];
	    if ( $canpass == IMP_MAXOFFSET 
		or $offset != IMP_MAXOFFSET and $offset <= $canpass ) {
		$req->xdebug("$typ($dir,$offset) - offset<canpass($canpass)");
		# nothing can override an earlier pass
		# except we can upgrade a prepass to pass
		$self->{prepass}[$dir] = 0 if $typ == IMP_PASS;
	    } else {
		$req->xdebug("$typ($dir,$offset)");
		$self->{canpass}[$dir] = $offset;
		$self->{prepass}[$dir] = ($typ == IMP_PREPASS);
		_fwdbuf($self,$dir);  # forward buffered data up to canpass
	    }

	} elsif ( $typ == IMP_REPLACE ) {
	    my ($dir,$offset,$newdata) = @$rv;
	    $req->xdebug("$typ($dir,$offset, repl.bytes=".length($newdata).")");

	    # remove the data from buf which should be replaced
	    # replacing future data is not supported, replacing already handled
	    # data obviously not too
	    my $buf = $self->{buf}[$dir];
	    my $buf0 = $buf->[0];
	    die "cannot replace already handled data: $typ($dir) ".
		"offset($offset)<=buf[0].pos($buf0->[0])"
		if $offset <= $buf0->[0];

	    # the data to replace should be all in the first buffer
	    my $len0 = length($buf0->[1]);
	    my $replace = $offset - $buf0->[0];
	    die "cannot cross buffer boundaries when replacing data: ".
		"$typ($dir) len=$len0 replace=$replace"
		if $len0 < $replace;

	    # if the buffer is non-stream, the offset should be at buffer boundary
	    my $fwd;
	    if ( $replace < $len0 ) {
		die "cannot replace parts of non-stream buffers" 
		    unless $buf0->[2] < 0;

		# create buffer to forward with new data
		$fwd = [
		    $buf0->[0],   # old pos
		    $newdata,     # new data
		    $buf0->[1],   # old type
		    1,            # changed
		];

		# remove replaced data and adjust pos
		substr($buf0->[1],0,$replace,'');
		$buf0->[0] += $replace;

	    } else {
		# replace complete buf

		# remove buf
		shift(@$buf);
		if ( ! @$buf ) {
		    # add dummy
		    push @$buf, [
			$buf0->[0] + $len0,
			'',
			undef
		    ];
		}

		$fwd = $buf0;
		$fwd->[1] = $newdata;
		$fwd->[3] = 1; # set as changed
	    }

	    # propagate change
	    _fwdbuf($self,$dir,$fwd);

	} elsif ( $typ == IMP_TOSENDER ) {
	    my ($dir,$data) = @$rv;
	    $req->xdebug("$typ($dir) data=".length($data));
	    $req->imp_forward($dir,$dir,$data); # from == to
	}
    }
}

1;

