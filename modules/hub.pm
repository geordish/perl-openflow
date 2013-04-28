#!/usr/bin/perl -w -T

package OpenFlow::Modules::hub;

use strict;
use warnings;

use Data::Dumper;

use enum qw(:OFPT_
    HELLO
    ERROR
    ECHO_REQUEST
    ECHO_REPLY
    EXPERIMENTER
    FEATURES_REQUEST
    FEATURES_REPLY
    GET_CONFIG_REQUEST
    GET_CONFIG_REPLY
    SET_CONFIG
    PACKET_IN
    FLOW_REMOVED
    PORT_STATUS
    PACKET_OUT
    FLOW_MOD
    GROUP_MOD
    PORT_MOD
    TABLE_MOD
    STATS_REQUEST
    STATS_REPLY
    BARRIER_REQUEST
    BARRIER_REPLY
    QUEUE_GET_CONFIG_REQUEST
    QUEUE_GET_CONFIG_REPLY
);

use enum qw(:OFPR_
    NO_MATCH
    ACTION
);

my $of_switches;

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


sub process_packet() {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;
    my $data = shift;

    # Get reference to OF object for this switch
    my $obj;
    if (!defined $of_switches->{$sock->peerhost()}->{$sock->peerport()}->{obj}) {
        $obj = OpenFlowFactory->instantiate($ofp_header->{version}, $sock);
        $of_switches->{$sock->peerhost()}->{$sock->peerport()}->{obj} = $obj;
    } else {
       $obj =  $of_switches->{$sock->peerhost()}->{$sock->peerport()}->{obj};
    }

    if ($ofp_header->{type} == OFPT_HELLO) {
        $obj->hello($ofp_header);
    } elsif ($ofp_header->{type} == OFPT_FEATURES_REPLY) {
        $obj->process_features($ofp_header, $data);
        print "Switch Connected. Datapath ID: " . $obj->get_formatted_datapath_id() . "\n";
    } elsif ($ofp_header->{type} == OFPT_ECHO_REQUEST) {
        $obj->echo_reply($ofp_header);
    } elsif ($ofp_header->{type} == OFPT_PACKET_IN) {
        $self->packet_in($obj, $ofp_header, $data)
    } elsif ($ofp_header->{type} == OFPT_GET_CONFIG_REPLY) {
        $obj->process_config($ofp_header, $data);
    } else {
        print Dumper($ofp_header);
    }
}

1;
