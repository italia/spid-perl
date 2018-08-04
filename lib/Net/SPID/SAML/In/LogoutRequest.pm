package Net::SPID::SAML::In::LogoutRequest;
use Moo;

has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML
has 'xml'   => (is => 'ro', required => 1);

# Net::SPID::SAML::IdP object
has '_idp' => (
    is          => 'ro',
    required    => 1,
);

# Net::SAML2::Protocol::LogoutRequest object
has '_logoutreq' => (
    is          => 'ro',
    required    => 1,
    handles     => [qw(id)],
);

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # initialize our SPID object
    my $spid = Net::SPID->new(...);
    
    # parse a LogoutRequest
    my $logutreq = $spid->parse_logoutrequest;

=head1 ABSTRACT

This class represents an incoming LogoutRequest. You can use this to parse a logout request in case the user initiated a logout procedure elsewhere and an Identity Provider is requesting logout to you.

=head1 CONSTRUCTOR

This class is not supposed to be instantiated directly. You can get one by calling L<Net::SPID::SAML/parse_logoutrequest>.

=head1 METHODS

=head2 xml

This method returns the raw message in XML format.

    my $xml = $logoutreq->xml;

=cut
