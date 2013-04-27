#!/use/bin/perl -w -T

package  OpenFlowFactory;

use strict;
use warnings;

sub instantiate {
    my $class = shift;
    my $version = shift;
    my $location = "OpenFlow/ver$version.pm";
    my $factoryclass = "OpenFlow::ver$version";

    require $location;

    return $factoryclass->new(@_);
}

1;
