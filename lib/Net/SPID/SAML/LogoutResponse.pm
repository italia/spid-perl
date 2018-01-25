package Net::SPID::SAML::LogoutResponse;
use Moo;

has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML
has 'xml'   => (is => 'ro', required => 1);                 # original unparsed XML

# Net::SAML2::Protocol::LogoutResponse object
has '_logoutres' => (
    is          => 'ro',
    required    => 1,
    handles     => [qw(id)],
);

use Carp;

sub redirect_url {
    my ($self) = @_;
    
    my $xml = $self->_logoutres->as_xml;
    print STDERR $xml, "\n";
    
    # Check that this IdP offers a HTTP-Redirect SLO binding.
    croak sprintf "IdP '%s' does not have a HTTP-Redirect SLO binding", $self->_idp->entityid,
        if !$self->_idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    
    # TODO: make sure slo_redirect_binding() uses ResponseLocation is any.
    my $redirect = $self->_spid->_sp->slo_redirect_binding($self->_idp, 'SAMLResponse');
    return $redirect->sign($xml);
}

# Returns 'success', 'partial', or 0.
sub success {
    my ($self) = @_;
    
    return $self->_logoutres->substatus eq $self->_logoutres->status_uri('partial')
        ? 'partial'
        : $self->_logoutres->success ? 'success' : 0;
}

1;
