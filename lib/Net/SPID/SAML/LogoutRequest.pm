package Net::SPID::SAML::LogoutRequest;
use Moo;

has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML

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

use Carp;

sub redirect_url {
    my ($self) = @_;
    
    my $xml = $self->_logoutreq->as_xml;
    print STDERR $xml, "\n";
    
    # Check that this IdP offers a HTTP-Redirect SLO binding.
    croak sprintf "IdP '%s' does not have a HTTP-Redirect SLO binding", $self->_idp->entityid,
        if !$self->_idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    
    my $redirect = $self->_spid->_sp->slo_redirect_binding($self->_idp, 'SAMLRequest');
    return $redirect->sign($xml);
}

1;
