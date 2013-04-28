#!/usr/bin/perl

use strict;
use warnings;

use OpenFlowFactory;

use Getopt::Mixed;
use IO::Socket::INET;
use IO::Socket::SSL;
use Convert::Binary::C;
use Data::Dumper;
use Data::Hexdumper;
use IO::Select;

Getopt::Mixed::init( 'm=s module>m');

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

my $of_module;
my $of_switches = {};

while (my($option, $value, $pretty) = Getopt::Mixed::nextOption()) {
    OPTION: {
        $option eq 'm' and do {
            $of_module = $value;

            last OPTION;
        };
    }
}
Getopt::Mixed::cleanup();
die "No module loaded speficied by -m\n" unless $of_module;

my $location = "modules/$of_module.pm";
my $of_class = "OpenFlow::Modules::$of_module";

if (-e $location) {
    require $location;
} else {
    die "$of_module is not a valid module\n";
}

$of_class->new();

my $c = Convert::Binary::C->new( ByteOrder => 'BigEndian',
                                 LongSize  => 4,
                                 ShortSize => 2,);

$c->parse_file('openflow.h');

my $serversocket = new IO::Socket::INET (
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

my $sockselect = IO::Select->new();
$sockselect->add($serversocket);


while(1)
{
    my ($header, $data);

    my ($ready) = IO::Select->select($sockselect, undef, undef);

    foreach my $sock (@$ready) {
        if ($sock == $serversocket) {
            my $a = $serversocket->accept();

            $of_switches->{$a->peerhost()}->{$a->peerport()}->{socket} = $a;
            $of_switches->{$a->peerhost()}->{$a->peerport()}->{obj} = undef;

            $sockselect->add($a);

        } else {
            $sock->recv($header,8);

            my $ofp_header = $c->unpack('ofp_header', $header);

            if (!defined $ofp_header->{version}) {
                $sockselect->remove($sock);
                next;
            }

            if ($ofp_header->{length} > 8) {
                $sock->recv($data,$ofp_header->{length}-8);
            }

            &process_packet($sock, $ofp_header, $data);
        }
    }
}


sub process_packet() {
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
        $of_class->packet_in($obj, $ofp_header, $data);
    } elsif ($ofp_header->{type} == OFPT_GET_CONFIG_REPLY) {
        $obj->process_config($ofp_header, $data);
    } else {
        print Dumper($ofp_header);
    }
}
