#!/usr/bin/perl -w -T

package MyPackage;

use strict;
use warnings;

use base qw(Net::Server::PreFork);

MyPackage->run({
    port => 6633,
    log_level => 4,
});

use Convert::Binary::C;
use Data::Dumper;
use Data::Hexdumper;

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



sub process_request {
    my $self = shift;
    eval {

        local $SIG{'ALRM'} = sub { die "Timed Out!\n" };
        my $timeout = 30;

        my $previous_alarm = alarm($timeout);


        our $c = Convert::Binary::C->new( ByteOrder => 'BigEndian',
                                         LongSize  => 4,
                                         ShortSize => 2,);

        $c->parse_file('openflow.h');

        $c->tag('ofp_switch_features.datapath_id', Format => 'Binary');
        $c->tag('ofp_phy_port.hw_addr', Format => 'Binary');
        $c->tag('ofp_phy_port.name', Format => 'String');

        binmode(STDIN);

        my $header;
        my $data;

        while (read(STDIN, $header, 8)) {
            my $ofp_header = $c->unpack('ofp_header', $header);

            if ($ofp_header->{length} > 8) {
                read(STDIN, $data, $ofp_header->{length}-8);
            }
            process_packet($self, $ofp_header, $data);

            alarm($timeout);
        }
        alarm($previous_alarm);

    };

    if ($@ =~ /timed out/i) {
        print STDOUT "Timed Out.\r\n";
        return;
    }
}

sub process_packet() {
    my $self = shift;
    my $ofp_header = shift;
    my $data = shift;


    if ($ofp_header->{type} == OFPT_HELLO) {
        my $response = pack("CCnN", $ofp_header->{version}, OFPT_HELLO, 8, $ofp_header->{xid});
        print  $response;
        $self->log(4, "Hello");

        request_capabilities($self, $ofp_header->{version}, $ofp_header->{xid});

    } elsif ($ofp_header->{type} == OFPT_FEATURES_REPLY) {
        process_capabilities($self, $ofp_header, $data);
        request_config($self, $ofp_header->{version}, $ofp_header->{xid});

    } elsif ($ofp_header->{type} == OFPT_ECHO_REQUEST) {
        print STDOUT pack("CCnN", $ofp_header->{version}, OFPT_ECHO_REPLY, 8, $ofp_header->{xid});
    } elsif ($ofp_header->{type} == OFPT_PACKET_IN) {
        packet_in($self, $ofp_header, $data);
    } else {
        $self->log(4,  Dumper($ofp_header));
    }
}

sub packet_in() {
    my $self = shift;
    my $ofp_header = shift;
    my $data = shift;

    use vars qw($c);

     my $unpacked = $c->unpack('ofp_packet_in', $data);

     $self->log(4, Dumper $unpacked);
}

sub process_capabilities() {
    my $self = shift;
    my $ofp_header = shift;
    my $data = shift;

    use vars qw($c);

    my $unpacked = $c->unpack('ofp_switch_features', $data);
    $self->log(4, "Datapath ID: ");
    $self->log(4, sprintf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", unpack("C2C2C2C2C2C2C2C2",  $unpacked->{datapath_id})) . "\n");
    $self->log(4, "Buffers: " . $unpacked->{n_buffers} . "\n");
    $self->log(4, "Tables: " . $unpacked->{n_tables} . "\n");
    $self->log(4, "Actions: " . $unpacked->{actions} . "\n");
    $self->log(4, "\nPorts:\n");
    foreach my $key (keys $unpacked->{ports}) {
        $self->log(4, "Port:" . $unpacked->{ports}[$key]->{port_no} . " - " . $unpacked->{ports}[$key]->{name} . "\n");
        $self->log(4, sprintf("MAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", unpack("C2C2C2C2C2C2", $unpacked->{ports}[$key]->{hw_addr})) . "\n");

    }
}

sub request_capabilities() {
    my $self = shift;
    my $version = shift;
    my $xid = shift;

    print STDOUT pack("CCnN", $version, OFPT_FEATURES_REQUEST, 8, $xid);

}

sub request_config() {
    my $self = shift;
    my $version = shift;
    my $xid = shift;

    print STDOUT pack("CCnN", $version, OFPT_GET_CONFIG_REQUEST, 8, $xid);

}



1;

