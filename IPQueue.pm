#
# $Id: IPQueue.pm,v 1.20 2001/01/08 10:04:07 jmorris Exp $
#
# Perlipq - Perl extension for iptables userspace queuing.
# This code is GPL.
#
package IPTables::IPv4::IPQueue;
use strict;
$^W = 1;

use Carp qw(cluck);
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD %EXPORT_TAGS);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT_OK = qw(IPQ_COPY_META IPQ_COPY_PACKET NF_DROP NF_ACCEPT);
%EXPORT_TAGS = (constants => \@EXPORT_OK);
$VERSION = '1.20';

sub AUTOLOAD
{
	# This AUTOLOAD is used to 'autoload' constants from the constant()
	# XS function.  If a constant is not found then control is passed
	# to the AUTOLOAD in AutoLoader.
	
	my $constname;
	
	($constname = $AUTOLOAD) =~ s/.*:://;
	cluck "& not defined" if $constname eq 'constant';
	
	my $val = constant($constname, @_ ? $_[0] : 0);
	
	if ($! != 0) {
		if ($! =~ /Invalid/) {
			$AutoLoader::AUTOLOAD = $AUTOLOAD;
			goto &AutoLoader::AUTOLOAD;
		} else {
			cluck "Your vendor has not defined ".
			      "IPTables::IPv4::IPQueue macro $constname";
		}
	}
	
	no strict 'refs';
	*$AUTOLOAD = sub { $val };
	goto &$AUTOLOAD;
}

bootstrap IPTables::IPv4::IPQueue $VERSION;

##############################################################################
#
# Public methods
#
##############################################################################

sub new
{
	my ($class, %args) = @_;
	
	my $self = { };
	bless $self, ref($class) || $class;
	return $self->_init(\%args);
}

sub set_mode
{
	my ($self, $mode, $range) = @_;
	
	$range ||= 0;
	return _ipqxs_set_mode($self->{_ctx}, $mode, $range);
}

sub get_message
{
	my ($self) = @_;
	return _ipqxs_get_message($self->{_ctx}, 0);
}

sub set_verdict
{
	my ($self, $id, $verdict, $data_len, $buf) = @_;
	
	$data_len ||= 0;
	$buf ||= 0;
	return _ipqxs_set_verdict($self->{_ctx}, $id, $verdict, $data_len, $buf);
}

sub close
{
	my ($self) = @_;
	
	if (defined $self->{_ctx}) {
		_ipqxs_destroy_ctx($self->{_ctx});
		undef $self->{_ctx};
	}
}

sub errstr
{
	my ($class, $message) = @_;
	
	if (ref($class)) {
		cluck "Class method 'errstr' called as instance method";
		return;
	}
	
	my $text = _ipqxs_errstr();
	$text .= ": $!" if $!;
	return $text;
}

##############################################################################
#
# Private methods
#
##############################################################################

#
# Initialise IPQ XSUB context, set the queuing mode.
# Default queuing mode is to copy metadata only.
#
sub _init
{
	my ($self, $args) = @_;
	
	$self->{_ctx} = _ipqxs_init_ctx(0)
		or return;
	
	my $copy_mode = defined $args->{copy_mode}
		? $args->{copy_mode} : &IPQ_COPY_META;
	
	my $copy_range = defined $args->{copy_range}
		? $args->{copy_range} : 0;

	$self->set_mode($copy_mode, $copy_range) >= 0
		or return;
	
	return $self;
}

#
# Destructor
#
sub DESTROY
{
	my ($self) = @_;
	$self->close();
}

1;
__END__

=head1 NAME

IPTables::IPv4::IPQueue - Perl extension for libipq.

=head1 SYNOPSIS

  use IPTables::IPv4::IPQueue qw(:constants);
  
  $queue = new IPTables::IPv4::IPQueue();
  $msg = $queue->get_message();
  $queue->set_verdict($msg->packet_id(), NF_ACCEPT)

  $queue->set_mode(IPQ_COPY_PACKET, 2048);
  
  IPTables::IPv4::IPQueue->errstr;
  
  undef $queue;

=head1 DESCRIPTION

Perlipq (IPTables::IPv4::IPQueue) is a Perl extension for iptables userspace
packet queuing via libipq.

Packets may be selected from the stack via the iptables QUEUE target
and passed to userspace.  Perlipq allows these packets to be manipulated in
Perl and passed back to the stack.

More information on userspace packet queueing may be found in
L<libipq(3)>.


=head1 CONSTANTS

=over 4

=item Copy Mode

  IPQ_COPY_META       -    Copy only packet metadata to userspace.
  IPQ_COPY_PACKET     -    Copy metatdata and packet to userspace.

=item Packet Verdicts

  NF_DROP             -    Ask kernel to drop packet.
  NF_ACCEPT           -    Ask kernel to accept packet and continue processing.

=back

=head1 ATTRIBUTES

None.

=head1 METHODS

=over 4

=item new( [param => value, ... ] )

Constructor.

Creates userspace queuing object and sets the queuing mode.

Parameters:
  copy_mode
  copy_range

The default copy mode is IPQ_COPY_META.

=item set_mode(mode [, range])

Set the queuing mode.

The mode parameter must be one of:
  IPQ_COPY_META
  IPQ_COPY_PACKET

When specifying IPQ_COPY_PACKET mode, the range parameter specifies the number
of bytes of payload data to copy to userspace.

If the range is not provided and the mode is IPQ_COPY_PACKET, the range will
default to zero.  Typically, a range of 1500 will suffice.

This method is called by the constructor.

=item get_message()

Waits for a packet message from the kernel, returning a tainted
IPTables::IPv4::IPQueue::Packet object.

This is a helper object with the following read only attributes:

	packet_id         ID of queued packet.
	mark              Netfilter mark value.
	timestamp_sec     Packet arrival time (seconds).
	timestamp_usec    Packet arrvial time (+useconds).
	hook              Netfilter hook we rode in on.
	indev_name        Name of incoming interface.
	outdev_name       Name of outgoing interface.
	hw_protocol       Hardware protocol.
	hw_type           Hardware media type.
	hw_addrlen        Hardware address length.
	hw_addr           Hardware address.
	data_len          Length of payload data.
	payload           Payload data.

Payload data, if present, is a scalar byte string suitable for use
with packages such as I<NetPacket>.

=item set_verdict(id, verdict [, data_len, buf ])

Sets verdict on packet with specified id, and optionally sends modified
packet data back to the kernel.

The verdict must be one of:
  NF_DROP
  NF_ACCEPT

=item close()

Destroys userpsace queue context and all associated resources.

This is called by the destructor, which means you can just do:

  undef $queue;

instead.  

=item errstsr()

Class method, returns an error message based on the most recent library
error condition and global errno value.

=back

=head1 EXAMPLE

	package example;
	use strict;
	$^W = 1;

	use IPTables::IPv4::IPQueue qw(:constants);
	
	my ($queue, $msg);
	
	$queue = new IPTables::IPv4::IPQueue(copy_mode => IPQ_COPY_META)
		or die IPTables::IPv4::IPQueue->errstr;
			
	$msg = $queue->get_message()
		or die IPTables::IPv4::IPQueue->errstr;
		
	$queue->set_verdict($msg->packet_id(), NF_ACCEPT) > 0
		or die IPTables::IPv4::IPQueue->errstr;

=head1 TODO

=over 4

=item * Verify working on 64-bit systems with a 32-bit userspace.

=item * Fix lame error message if issuing a verdict on an invalid packet id.

=back

=head1 BUGS

None known.

=head1 COPYRIGHT

Copyright (c) 2000-2001 James Morris <jmorris@intercode.com.au>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

=head1 AUTHOR

James Morris <jmorris@intercode.com.au>

=head1 SEE ALSO

L<iptables(8)>

L<libipq(3)>

L<NetPacket(3)>

The example scripts, passer.pl and dumper.pl.

=cut
