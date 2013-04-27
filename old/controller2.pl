#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::INET;

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

# creating object interface of IO::Socket::INET modules which internally does
# socket creation, binding and listening at the specified port address.
$socket = new IO::Socket::INET (
        LocalHost => '127.0.0.1',
        LocalPort => '6633',
        Proto => 'tcp',
        Listen => 5,
        Reuse => 1,
        Blocking => 1,
    ) or die "ERROR in Socket Creation : $!\n";

print "SERVER Waiting for client connection on port 6633\n";

$socket->autoflush(1);
while(1)
{
        my $data;

        # waiting for new client connection.
        $client_socket = $socket->accept();
        # get the host and port number of newly connected client.
        $peeraddress = $client_socket->peerhost();
        $peerport = $client_socket->peerport();

        print "Accepted New Client Connection From : $peeraddress, $peerport\n ";

        while($client_socket) {
                $client_socket->recv($data,8);
                process_packet($data);
      }
}

$socket->close();

sub process_packet() {
    my $data = shift;

    #/* Header on all OpenFlow packets. */
    #struct ofp_header {
        #uint8_t version;   /* OFP_VERSION. */
        #uint8_t type;      /* One of the OFPT_ constants. */
        #uint16_t length;   /* Length including this ofp_header. */
        #uint32_t xid;      /* Transaction id associated with this packet.
        #Replies use the same id as was in the request to facilitate pairing. */
    #};
    #OFP_ASSERT(sizeof(struct ofp_header) == 8);


    my ($version, $type, $length, $xid) = unpack("CCnN", $data);

    # we can also read from socket through recv()  in IO::Socket::INET
    print "Received from Client : $version, $type, $length, $xid\n";
    if ($type == OFPT_HELLO) {
        print "The switch is saying hello!\n";
        print "We should ask what its capable of...\n";
        $data = <$client_socket>;
        get_capabilities($version, $xid);
    }
}

sub get_capabilities() {
    my $version = shift;
    my $xid = shift;

    my $response = pack("CCnN", $version, OFPT_FEATURES_REQUEST, 8, $xid+1);

    $client_socket->send($response);
}

