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

use enum qw(:OFPAT_
    OUTPUT
    SET_VLAN_VID
    SET_VLAN_PCP
    STRIP_VLAN
    SET_DL_SRC
    SET_DL_DST
    SET_NW_SRC
    SET_NW_DST
    SET_NW_TOS
    SET_TP_SRC
    SET_TP_DST
    ENQUEUE
    VENDOR=0xFFFF
);

my $datapath_id;
my $buffers;
my $tables;
my $flags;
my $miss_send_len;

my $ports = {};


sub new {
    my $class = shift;
    my $self  = {
        sock => shift,
    };

    return bless $self, $class;
}

sub hello {
    my $self = shift;
    my $ofp_header = shift;

    my $response = pack("CCnN", 1, OFPT_HELLO, 8, $ofp_header->{xid});
    $self->{sock}->send($response);

    request_features($self, $ofp_header);
    request_config($self, $ofp_header);
}

sub echo_reply {
    my $self = shift;
    my $ofp_header = shift;

    my $response = pack("CCnN", 1, OFPT_ECHO_REPLY, 8, $ofp_header->{xid});
    $self->{sock}->send($response);
}

sub request_features() {
    my $self = shift;
    my $ofp_header = shift;

    my $response = pack("CCnN", 1, OFPT_FEATURES_REQUEST, 8, $ofp_header->{xid});
    $self->{sock}->send($response);
}

sub process_features() {
    my $self = shift;
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
    my $ofp_header = shift;
    my $data = shift;

    my $response = pack("CCnN", 1, OFPT_GET_CONFIG_REQUEST, 8, $ofp_header->{xid});

    $self->{sock}->send($response);
}

sub process_config() {
    my $self = shift;
    my $ofp_header = shift;
    my $data = shift;
    
    my $unpacked = $c->unpack('ofp_switch_config', $data);

    $flags = $unpacked->{flags};
    $miss_send_len = $unpacked->{miss_send_len};
}

sub request_flows() {
    my $self = shift;
    my $ofp_header = shift;
    my $data = shift;

#struct ofp_match {
#uint32_t wildcards;
#uint16_t in_port;
#uint8_t dl_src[OFP_ETH_ALEN];
#uint8_t dl_dst[OFP_ETH_ALEN];
#uint16_t dl_vlan;
#uint8_t dl_vlan_pcp;
#uint8_t pad1[1];
#uint16_t dl_type;
#uint8_t nw_tos;
#uint8_t nw_proto;
#uint8_t pad2[2];
#uint32_t nw_src;
#uint32_t nw_dst;
#uint16_t tp_src;
#uint16_t tp_dst;
#};


#struct ofp_flow_stats_request {
#    #struct ofp_match match;
#    uint8_t table_id;
#    uint8_t pad;
#    uint16_t out_port;
#};



}

sub parse_packet_in() {
    my $self = shift;
    my $data = shift;

    return $c->unpack('ofp_packet_in', $data);
}

sub flood() {
    my $self = shift;
    my $buffer_id = shift;
    my $in_port = shift;
    my $ofp_header = shift;


print STDOUT "poop";

    my $ofp_action_output = create_ofp_action_output($self, OFPP_FLOOD);
    my $ofp_packet_out = {buffer_id => $buffer_id, in_port => $in_port, actions_len => length($ofp_action_output)};

    $ofp_packet_out = $c->pack('ofp_packet_out', $ofp_packet_out);
    $ofp_packet_out = pack ("C16", unpack("C8", $ofp_packet_out), unpack("C8", $ofp_action_output));


    my $response = pack("CCnNC16", 1, OFPT_PACKET_OUT, 24, $ofp_header->{xid}, unpack ("C16", $ofp_packet_out));

    $self->{sock}->send($response);

}

sub create_ofp_action_output () {
    my $self = shift;
    my $port = shift;
#    my $max_len = shift || 0;
    my $max_len =  0;

    my $output = {type => OFPAT_OUTPUT, len => 8, port => $port, max_len => $max_len };
    return $c->pack('ofp_action_output', $output);
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

