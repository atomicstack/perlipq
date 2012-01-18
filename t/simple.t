#
# $Id: simple.t,v 1.4 2001/10/22 13:47:16 jmorris Exp $
#
# Simple test.
#
package simple_t;
use strict;
$^W = 1;

my $tests = 5;

sub test
{
	my ($q, $procfile, $procpid);
	print "1..$tests\n";

	if ( defined $> and $> == 0 ) {
		print "ok 1\n";
	}
	else {
		print "not ok 1\n";
		die "test script must be run with root privs!";
	}

	#
	# Test 2 - Load module(s)
	#
	use IPTables::IPv4::IPQueue qw(:constants);
	
	print "ok 2\n";

	#
	# Test 3 - IPQueue object creation
	#
	$q = new IPTables::IPv4::IPQueue(copy_mode => &IPQ_COPY_PACKET,
	                                 copy_range => 1500);

	if (!defined $q) {
		print "not ok 3\n";
		die "Fatal: " . IPTables::IPv4::IPQueue->errstr;
	} else {
		print "ok 3\n";
	}

	#
	# Test 4 -  Verify against /proc entry
	#
	$procfile = '/proc/net/ip_queue';

	my @ip_queue_info = qx{cat /proc/net/ip_queue};
	
	if (not @ip_queue_info) {
		print "not ok 4\n";
		die "Fatal: unable to open $procfile: $!";
	}
	
	foreach (@ip_queue_info) {
		if (/^Peer pid\s+:\s+(\d+)/i) {
			$procpid = $1;
			last;
		}
	}
		
	if (!$procpid) {
		print "not ok 4\n";
	} else {
		if ($procpid != $$) {
			print "not ok 4\n";
		} else {
			print "ok 4\n";
		}
	}
	
	#
	# Test 5 - test get_message() with 20 millisecond
	# timeout, assumes no packet will arrive, may not return
	# on failure.
	#
	my $packet = $q->get_message(1000 * 2);
	if (defined $packet) {
		print "not ok 5\n";
	} else {
		if (IPTables::IPv4::IPQueue->errstr eq 'Timeout') {
			print "ok 5\n";
		} else {
			print "not ok 5\n";
		}
	}
	
}

test();

