#
# $Id: simple.t,v 1.3 2000/12/03 00:21:41 jmorris Exp $
#
# Simple test.
#
package simple_t;
use strict;
$^W = 1;

my $tests = 3;

sub test
{
	my ($q, $procfile, $procpid);
	
	print "1..$tests\n";

	#
	# Test 1 - Load module(s)
	#
	use IPTables::IPv4::IPQueue qw(:constants);
	
	print "ok 1\n";

	#
	# Test 2 - IPQueue object creation
	#
	$q = new IPTables::IPv4::IPQueue(copy_mode => &IPQ_COPY_PACKET,
	                                 copy_range => 1500);

	if (!defined $q) {
		print "not ok 2\n";
		die "Fatal: " . IPTables::IPv4::IPQueue->errstr;
	} else {
		print "ok 2\n";
	}

	#
	# Test 3 -  Verify against /proc entry
	#
	$procfile = '/proc/net/ip_queue';
	
	if (!open PROC, "<$procfile") {
		print "not ok 3\n";
		die "Fatal: unable to open $procfile: $!";
	}
	
	while (<PROC>) {
		if (/^Peer pid\s+:\s+(\d+)/) {
			$procpid = $1;
			last;
		}
	}
	close PROC;
	
	if (!$procpid) {
		print "not ok 3\n";
	} else {
		if ($procpid != $$) {
			print "not ok 3\n";
		} else {
			print "ok 3\n";
		}
	}
}

test();

