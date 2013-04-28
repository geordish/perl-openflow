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

my $of_module;

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

            $of_class->process_packet($sock, $ofp_header, $data);
        }
    }
}
