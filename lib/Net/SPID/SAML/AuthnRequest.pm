package Net::SPID::SAML::AuthnRequest;
use Moo;

has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML

# Net::SPID::SAML::IdP object
has '_idp' => (
    is          => 'ro',
    required    => 1,
);

# Net::SAML2::Protocol::AuthnRequest object
has '_authnreq' => (
    is          => 'ro',
    required    => 1,
    handles     => [qw(id)],
);

use Carp;

sub redirect_url {
    my ($self, %args) = @_;
    
    my $xml = $self->_authnreq->as_xml;
    print STDERR $xml, "\n";
    
    # Check that this IdP offers a HTTP-Redirect SSO binding
    # (current SPID specs do not enforce its presence, and an IdP
    # might only have a HTTP-POST binding).
    croak sprintf "IdP '%s' does not have a HTTP-Redirect SSO binding", $self->_idp->entityid,
        if !$self->_idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    
    my $redirect = $self->_spid->_sp->sso_redirect_binding($self->_idp, 'SAMLRequest');
    return $redirect->sign($xml, $args{relaystate});
}

1;
