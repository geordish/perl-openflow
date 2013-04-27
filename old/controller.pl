#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::INET;
use IO::Socket::SSL;
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

my ($socket,$client_socket);
my ($peeraddress,$peerport);

my $c = Convert::Binary::C->new( ByteOrder => 'BigEndian',
                                 LongSize  => 4,
                                 ShortSize => 2,);

$c->parse("
struct ofp_header {
    unsigned char version;
    unsigned char type;
    unsigned short  length;
    unsigned long xid;
};

struct ofp_phy_port {
    unsigned short port_no;
    unsigned char hw_addr[6];
    unsigned char name[16];
    unsigned long config;
    unsigned long state;
    unsigned long curr;
    unsigned long advertised;
    unsigned long supported;
    unsigned long peer;
};

struct ofp_switch_features {
    unsigned long long datapath_id;
    unsigned long n_buffers;
    unsigned char n_tables;
    unsigned char pad[3];
    unsigned long capabilities;
    unsigned long actions;
    struct ofp_phy_port ports[];
};


");
$c->tag('ofp_switch_features.datapath_id', Format => 'Binary');
$c->tag('ofp_phy_port.hw_addr', Format => 'Binary');
$c->tag('ofp_phy_port.name', Format => 'String');

$socket = new IO::Socket::INET (
#$socket = new IO::Socket::SSL (
        LocalHost => '127.0.0.1',
        LocalPort => '6633',
        Proto => 'tcp',
        Listen => 5,
        Reuse => 1,
        Blocking => 1,
        SSL_cert_file => '/etc/ssl/certs/ssl-cert-snakeoil.pem',
        SSL_key_file => 'ssl-cert-snakeoil.key',
    ) or die "ERROR in Socket Creation : $!\n";

print "SERVER Waiting for client connection on port 6633\n";

$socket->autoflush(1);
while(1)
{
        my ($header, $data);
        # waiting for new client connection.
        $client_socket = $socket->accept();
        my $connected = 1;

        # get the host and port number of newly connected client.
        $peeraddress = $client_socket->peerhost();
        $peerport = $client_socket->peerport();

        print "Accepted New Client Connection From : $peeraddress, $peerport\n ";

        while($connected && $client_socket->connected) {

                $client_socket->recv($header,8);

                my $ofp_header = $c->unpack('ofp_header', $header);
                print Dumper($ofp_header);

                if (!defined $ofp_header->{version}) {
                    print "Looks like the other end went away\n";
                    $connected = 0;
                    next;
                }

                if ($ofp_header->{length} > 8) {
                    $client_socket->recv($data,$ofp_header->{length}-8);
                }

                process_packet($ofp_header, $data);
      }
}

$socket->close();

sub process_packet() {
    my $ofp_header = shift;
    my $data = shift;

    if ($ofp_header->{type} == OFPT_HELLO) {
        print "The switch is saying hello!\n";
        print "Say hello back!\n";
        my $response = pack("CCnN", $ofp_header->{version}, OFPT_HELLO, 8, $ofp_header->{xid});
        $client_socket->send($response);
        print "We should ask what its capable of...\n";
        request_capabilities($ofp_header->{version}, $ofp_header->{xid});
    } elsif ($ofp_header->{type} == OFPT_FEATURES_REPLY) {
        print "Received the features\n";
        process_capabilities($ofp_header, $data);
        request_config($ofp_header->{version}, $ofp_header->{xid});
    } elsif ($ofp_header->{type} == OFPT_ECHO_REQUEST) {
        my $response = pack("CCnN", $ofp_header->{version}, OFPT_ECHO_REPLY, 8, $ofp_header->{xid});
        $client_socket->send($response);
    }
}

sub process_capabilities() {
    my $ofp_header = shift;
    my $data = shift;

    my $unpacked = $c->unpack('ofp_switch_features', $data);
    print "Datapath ID: ";
    print sprintf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", unpack("C2C2C2C2C2C2C2C2",  $unpacked->{datapath_id})) . "\n";
    print "Buffers: " . $unpacked->{n_buffers} . "\n";
    print "Tables: " . $unpacked->{n_tables} . "\n";
    print "\nPorts:\n";
    foreach my $key (keys $unpacked->{ports}) {
        print "\tPort:" . $unpacked->{ports}[$key]->{port_no} . " - " . $unpacked->{ports}[$key]->{name} . "\n";
        print sprintf("\tMAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", unpack("C2C2C2C2C2C2", $unpacked->{ports}[$key]->{hw_addr})) . "\n";

    }
}

sub request_capabilities() {
    my $version = shift;
    my $xid = shift;

    my $response = pack("CCnN", $version, OFPT_FEATURES_REQUEST, 8, $xid);

    $client_socket->send($response);
}

sub request_config() {
    my $version = shift;
    my $xid = shift;

    print OFPT_GET_CONFIG_REQUEST . "\n";
    my $response = pack("CCnN", $version, OFPT_GET_CONFIG_REQUEST, 8, $xid);

    $client_socket->send($response);
}

