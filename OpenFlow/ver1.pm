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

my $xid = 0;

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

use enum qw(:OFPFC_
    ADD
    MODIFY
    MODIFY_STRICT
    DELETE
    DELETE_STRICT
);

use enum qw(:OFPFF_
    SEND_FLOW_REM=1<<0
    CHECK_OVERLAP=1<<1
    EMERG=1<<2
);

use enum qw(:OFPST_
    DESC
    FLOW
    AGGREGATE
    TABLE
    PORT
    QUEUE
    VENDOR=0xffff
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

$ofp_flow_wildcards->{'OFPFW_NW_SRC_MASK'}  = ((1 << $ofp_flow_wildcards->{'OFPFW_NW_SRC_BITS'} - 1) << $ofp_flow_wildcards->{'OFPFW_NW_SRC_SHIFT'});
$ofp_flow_wildcards->{'OFPFW_NW_SRC_ALL'}   = 32 << $ofp_flow_wildcards->{'OFPFW_NW_SRC_SHIFT'};
$ofp_flow_wildcards->{'OFPFW_NW_DST_MASK'}  = ((1 << $ofp_flow_wildcards->{'OFPFW_NW_DST_BITS'} - 1) << $ofp_flow_wildcards->{'OFPFW_NW_DST_SHIFT'});
$ofp_flow_wildcards->{'OFPFW_NW_DST_ALL'}   = 32 << $ofp_flow_wildcards->{'OFPFW_NW_DST_SHIFT'};

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


sub get_all_flows() {
    my $self = shift;

    my $ofp_match = { wildcards => $ofp_flow_wildcards->{'OFPFW_ALL'} };

    my $flow_stats_req = { match => $ofp_match, table_id => 0xFF, out_port => OFPP_NONE};

    my $ofp_flow_stats_req = $c->pack('ofp_flow_stats_request', $flow_stats_req);
    my $response = pack("CCnNnnC44", 1, OFPT_STATS_REQUEST, 56, $xid++, OFPST_FLOW, 0,  unpack ("C44", $ofp_flow_stats_req));

    $self->{sock}->send($response);

}

sub remove_all_flows() {
    my $self = shift;

    my $ofp_match = { wildcards => $ofp_flow_wildcards->{'OFPFW_ALL'} };

    my $ofp_flow_mod = { match => $ofp_match, out_port => OFPP_NONE, command => OFPFC_DELETE };
    $ofp_flow_mod = $c->pack('ofp_flow_mod', $ofp_flow_mod);

    my $response = pack("CCnNC64", 1, OFPT_FLOW_MOD, 72 ,$xid++,  unpack("C64", $ofp_flow_mod));

    $self->{sock}->send($response);
}

sub add_flow() {
    my $self = shift;
    my $args = shift;

    my $ofp_flow_mod = { match => $args, command => OFPFC_ADD, idle_timeout => 300, hard_timeout => 900, buffer_id => -1 };
    $ofp_flow_mod = $c->pack('ofp_flow_mod', $ofp_flow_mod);
    my $ofp_action_output = create_ofp_action_output($self, OFPP_FLOOD);

    my $response = pack("CCnNC64C8", 1, OFPT_FLOW_MOD, 80, $xid++, unpack ("C64", $ofp_flow_mod), unpack("C8", $ofp_action_output));

    $self->{sock}->send($response);


}

sub create_flow_match() {
    my $self = shift;
    my $wildcards = shift;
    my $in_port = shift || undef;
    my $dl_src = shift || undef;
    my $dl_dst = shift || undef;
    my $dl_vlan = shift || undef;
    my $dl_vlan_pcp = shift || undef;
    my $dl_type = shift || undef;
    my $nw_tos = shift || undef;
    my $nw_proto = shift || undef;
    my $nw_src = shift || undef;
    my $nw_dst = shift || undef;
    my $tp_src = shift || undef;
    my $tp_dst = shift || undef;

    my $tmp = { wildcards   => $wildcards,
                in_port     => $in_port,
                dl_src      => $dl_src,
                dl_dst      => $dl_dst,
                dl_vlan     => $dl_vlan,
                dl_vlan_pcp => $dl_vlan_pcp,
                dl_type     => $dl_type,
                nw_tos      => $nw_tos,
                nw_proto    => $nw_proto,
                nw_src      => $nw_src,
                nw_dst      => $nw_dst,
                tp_dst      => $tp_dst,
                tp_src      => $tp_src,
    };

    my $ofp_match = $c->pack('ofp_match', $tmp);

    return $ofp_match;

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
    my $max_len = shift || 0;

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

sub get_ports() {
    return $ports;
}

sub get_formatted_datapath_id () {
 return sprintf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", unpack("C2C2C2C2C2C2C2C2", $datapath_id));
}

1;

