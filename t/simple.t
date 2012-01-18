use strict;
use warnings;
use Test::More;

################################################################################
	
BEGIN {
    defined $> && $> == 0
    or BAIL_OUT("these tests require root privileges!");

    use_ok('IPTables::IPv4::IPQueue' => ':constants')
}

################################################################################

my $q = IPTables::IPv4::IPQueue->new(
    copy_mode => &IPQ_COPY_PACKET,
    copy_range => 1500,
);

isa_ok( $q, 'IPTables::IPv4::IPQueue' );

################################################################################

my $procfile_path = '/proc/net/ip_queue';
my $procfile_fh;

open $procfile_fh, '<', $procfile_path
or die "unable to open procfile_path $procfile_path: $!";

my @proc_lines = <$procfile_fh>;
$procfile_fh = undef;

ok(int(@proc_lines) > 0, '@proc_lines > 0');

my $peer_pid = '';
foreach my $line (@proc_lines) {
    if ($line =~ /^Peer pid\s+:\s+(\d+)/i) {
        $peer_pid = $1 and last;
    }
}

is($peer_pid, $$, "peer_pid ($peer_pid) == self_pid ($$)");

################################################################################

my $packet = $q->get_message(1000 * 2);

is($packet, undef, 'get_message should return undef');
is(IPTables::IPv4::IPQueue->errstr, 'Timeout', 'IPTables::IPv4::IPQueue->errstr eq Timeout');

################################################################################

done_testing();
