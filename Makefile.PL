use ExtUtils::MakeMaker;
require 5.12.4;
WriteMakefile(
    NAME => 'App::HTTP_Proxy_IMP',
    VERSION_FROM => 'lib/App/HTTP_Proxy_IMP.pm',
    PREREQ_PM => {
	'Net::Inspect' => 0.27,
	'Net::IMP' => 0.60,
	'Net::IMP::HTTP' => 0.51,
	'AnyEvent' => 6.12,
    },
    EXE_FILES => [ 'bin/http_proxy_imp' ],
    LICENSE => 'perl',
);
