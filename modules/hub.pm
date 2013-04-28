#!/usr/bin/perl -w -T

package OpenFlow::Modules::hub;

use strict;
use warnings;

use Data::Dumper;

use enum qw(:OFPR_
    NO_MATCH
    ACTION
);

sub new() {
    my $class = shift;
    my $self = {
    };

    print __PACKAGE__ . " Initialised\n";

    return bless $self, $class;
}

sub packet_in() {
    my $self = shift;
    my $switch = shift;
    my $ofp_header = shift;
    my $data = shift;

    my $packet = $switch->parse_packet_in($data);

    if ($packet->{reason} == OFPR_NO_MATCH) {
        $switch->flood($packet->{buffer_id}, $packet->{in_port}, $ofp_header);
    } else {
        print "We asked the switch to send us this packet\n";
    }

}
1;
