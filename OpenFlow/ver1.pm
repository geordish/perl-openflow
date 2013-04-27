#!/usr/bin/perl -w -T

package OpenFlow::ver1;

use strict;
use warnings;

use Data::Dumper;
use Data::Hexdumper;
use Convert::Binary::C;

my $c = Convert::Binary::C->new( ByteOrder => 'BigEndian',
                                 LongSize  => 4,
                                 ShortSize => 2,);

$c->parse_file('OpenFlow/openflowv1.h');

$c->tag('ofp_switch_features.datapath_id', Format => 'Binary');
$c->tag('ofp_phy_port.hw_addr', Format => 'Binary');
$c->tag('ofp_phy_port.name', Format => 'String');


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

my $datapath_id;
my $buffers;
my $tables;
my $ports = {};


sub new {
    my $class = shift;
    my $self  = {
    };

    return bless $self, $class;
}

sub hello {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;

    my $response = pack("CCnN", 1, OFPT_HELLO, 8, $ofp_header->{xid});
    $sock->send($response);

    request_features($self, $sock, $ofp_header);
    request_config($self, $sock, $ofp_header);
}

sub echo_reply {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;

    my $response = pack("CCnN", 1, OFPT_ECHO_REPLY, 8, $ofp_header->{xid});
    $sock->send($response);
}

sub request_features() {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;

    my $response = pack("CCnN", 1, OFPT_FEATURES_REQUEST, 8, $ofp_header->{xid});
    $sock->send($response);
}

sub process_features() {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;
    my $data = shift;

    my $unpacked = $c->unpack('ofp_switch_features', $data);

    $datapath_id = $unpacked->{datapath_id};
    $buffers = $unpacked->{n_buffers};
    $tables = $unpacked->{n_tables};

    foreach my $key (keys $unpacked->{ports}) {
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{name} = $unpacked->{ports}[$key]->{name};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{hw_addr} = $unpacked->{ports}[$key]->{hw_addr};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{curr} = $unpacked->{ports}[$key]->{curr};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{supported} = $unpacked->{ports}[$key]->{supported};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{state} = $unpacked->{ports}[$key]->{state};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{advertised} = $unpacked->{ports}[$key]->{advertised};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{config} = $unpacked->{ports}[$key]->{config};
        $ports->{$unpacked->{ports}[$key]->{port_no}}->{peer} = $unpacked->{ports}[$key]->{peer};
    }
}

sub request_config() {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;
    my $data = shift;

    my $response = pack("CCnN", 1, OFPT_GET_CONFIG_REQUEST, 8, $ofp_header->{xid});

    $sock->send($response);
}


sub packet_in() {
    my $self = shift;
    my $sock = shift;
    my $ofp_header = shift;
    my $data = shift;

    my $unpacked = $c->unpack('ofp_packet_in', $data);
    print Dumper $unpacked;
}


sub get_datapath_id () {
    return $datapath_id;
}

sub get_buffers() {
    return $buffers;
}

sub get_tables() {
    return $tables;
}

sub get_formatted_datapath_id () {
 return sprintf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", unpack("C2C2C2C2C2C2C2C2", $datapath_id));
}

1;
