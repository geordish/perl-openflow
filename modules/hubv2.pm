#!/usr/bin/perl -w -T

package OpenFlow::Modules::hubv2;

use strict;
use warnings;

use Data::Dumper;

use enum qw(:OFPT_
    HELLO
    ERROR
    ECHO_REQUEST
    ECHO_REPLY
    VENDOR
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
    PORT_MOD
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

use enum  qw(:OFPP_
    MAX=0xFF00
    IN_PORT=0xFFF8
    TABLE=0xFFF9
    NORMAL=0xFFFA
    FLOOD=0xFFFB
    ALL=0xFFFC
    CONTROLLER=0xFFFD
    LOCAL=0xFFFE
    NONE=0xFFFF
);

my $ofp_flow_wildcards = {
    'OFPFW_IN_PORT'      => 1 << 0,
    'OFPFW_DL_PORT'      => 1 << 1,
    'OFPFW_DL_SRC'       => 1 << 2,
    'OFPFW_DL_DST'       => 1 << 3,
    'OFPFW_DL_TYPE'      => 1 << 4,
    'OFPFW_NW_PROTO'     => 1 << 5,
    'OFPFW_TP_SRC'       => 1 << 6,
    'OFPFW_TP_DST'       => 1 << 7,
    'OFPFW_NW_SRC_SHIFT' => 8,
    'OFPFW_NW_SRC_BITS'  => 6,
    'OFPFW_NW_DST_SHIFT' => 14,
    'OFPFW_NW_DST_BITS'  => 6,
    'OFPFW_DL_VLAN_PCP'  => 1 << 20,
    'OFPFW_NW_TOS'       => 1 << 21,
    'OFPFW_ALL'          => ((1 << 22) - 1),
};


my $of_switches;

sub new() {
    my $class = shift;
    my $self = {
    };

    print __PACKAGE__ . " Initialised\n";

    return bless $self, $class;
}

sub new_switch() {

    my $self = shift;
    my $sock = shift;
    my $switch = shift;
    my $ofp_header = shift;
    my $data = shift;

    print "Have been notified about a new switch\n";

    $switch->remove_all_flows();
    my $ports = $switch->get_ports();

    foreach my $port (keys %{$ports}) {
        if($port == OFPP_LOCAL) {
            next;
        }
        $switch->add_flow( { in_port => $port, wildcards => $ofp_flow_wildcards->{OFPFW_ALL}, buffer_id => -1});
    }

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
        $self->new_switch($sock, $obj, $ofp_header, $data);
    } elsif ($ofp_header->{type} == OFPT_ECHO_REQUEST) {
        $obj->echo_reply($ofp_header);
    } elsif ($ofp_header->{type} == OFPT_PACKET_IN) {
        $self->packet_in($obj, $ofp_header, $data)
    } elsif ($ofp_header->{type} == OFPT_GET_CONFIG_REPLY) {
        $obj->process_config($ofp_header, $data);
    } elsif ($ofp_header->{type} == OFPT_STATS_REPLY) {
        $self->new_switch($sock, $obj, $ofp_header, $data);
    } else {
        print Dumper($ofp_header);
    }
}


1;
