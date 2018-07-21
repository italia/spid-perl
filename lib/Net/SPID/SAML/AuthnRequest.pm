package Net::SPID::SAML::AuthnRequest;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage::Outgoing';

has 'acs_url'       => (is => 'rw', required => 0);
has 'acs_index'     => (is => 'rw', required => 0);
has 'attr_index'    => (is => 'rw', required => 0);
has 'level'         => (is => 'rw', required => 0, default => sub { 1 });
has 'comparison'    => (is => 'rw', required => 0, default => sub { 'minimum' });

use Carp;

sub BUILD {
    my ($self) = @_;
    
    if (!grep defined, $self->acs_url, $self->_spid->sp_acs_url,
        $self->acs_index, $self->_spid->sp_acs_index) {
        croak "acs_url or acs_index are required\n";
    }
}

sub xml {
    my ($self) = @_;
    
    my ($x, $saml, $samlp) = $self->SUPER::xml;

    my $req_attrs = {
        ID              => $self->ID,
        IssueInstant    => $self->IssueInstant->strftime('%FT%TZ'),
        Version         => '2.0',
        Destination     => $self->_idp->sso_url($self->binding),
        ForceAuthn      => ($self->level > 1) ? 'true' : 'false',
    };
    if (defined (my $acs_url = $self->acs_url // $self->_spid->sp_acs_url)) {
        $req_attrs->{AssertionConsumerServiceURL} = $acs_url;
        $req_attrs->{ProtocolBinding} = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    }
    if (defined (my $acs_index = $self->acs_index // $self->_spid->sp_acs_index)) {
        $req_attrs->{AssertionConsumerServiceIndex} = $acs_index;
    }
    if (defined (my $attr_index = $self->attr_index // $self->_spid->sp_attr_index)) {
        $req_attrs->{AttributeConsumingServiceIndex} = $attr_index;
    }
    $x->startTag([$samlp, 'AuthnRequest'], %$req_attrs);
    
    $x->dataElement([$saml, 'Issuer'], $self->_spid->sp_entityid,
        Format          => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        NameQualifier   => $self->_spid->sp_entityid,
    );
    
    $x->dataElement([$samlp, 'NameIDPolicy'], undef, 
        Format => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient');
    
    $x->startTag([$samlp, 'RequestedAuthnContext'], Comparison => $self->comparison);
    $x->dataElement([$saml, 'AuthnContextClassRef'], 'https://www.spid.gov.it/SpidL' . $self->level);
    $x->endTag();
    
    $x->endTag(); #AuthnRequest
    $x->end();
    
    my $xml = $x->to_string;
    
    # TODO: if we're using HTTP-POST, sign this document
    
    return $xml;
}

sub redirect_url {
    my ($self, %args) = @_;
    
    my $xml = $self->xml;
    print STDERR $xml, "\n";
    
    # Check that this IdP offers a suitable SSO binding
    # (current SPID specs do not enforce that all bindings are made available).
    croak sprintf "IdP '%s' does not have a %s SSO binding",
        $self->_idp->entityid, $self->binding
        if !$self->_idp->sso_url($self->binding);
    
    my $redirect = $self->_spid->_sp->sso_redirect_binding($self->_idp, 'SAMLRequest');
    return $redirect->sign($xml, $args{relaystate});
}

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # initialize our SPID object
    my $spid = Net::SPID->new(...);
    
    # get an IdP
    my $idp = $spid->get_idp('https://www.prova.it/');
    
    # generate an AuthnRequest
    my $authnreq = $idp->authnrequest(
        acs_index   => 0,   # index of AssertionConsumerService as per our SP metadata
        attr_index  => 1,   # index of AttributeConsumingService as per our SP metadata
        level       => 1,   # SPID level
    );
    
    my $url = $authnreq->redirect_url;

=head1 ABSTRACT

This class represents an outgoing AuthnRequest.

=head1 CONSTRUCTOR

This class is not supposed to be instantiated directly. You can craft an AuthnRequest by calling the L<Net::SPID::SAML::IdP/authnrequest> method on a L<Net::SPID::SAML::IdP> object.

=head1 METHODS

=head2 xml

This method returns the raw message in XML format (signed).

    my $xml = $authnreq->xml;

=head2 redirect_url

This method returns the full URL of the Identity Provider where user should be redirected in order to initiate their Single Sign-On. In SAML words, this implements the HTTP-Redirect binding.

    my $url = $authnreq->redirect_url(relaystate => 'foobar');

The following arguments can be supplied:

=over

=item I<relaystate>

(Optional.) An arbitrary payload can be written in this argument, and it will be returned to us along with the Response/Assertion. Please note that since we're passing this in the query string it can't be too long otherwise the URL will be truncated and the request will fail. Also note that this is transmitted in clear-text and that you are responsible for making sure the value is coupled with this AuthnRequest either cryptographycally or by using a lookup table on your side.

=back

=cut

=for Pod::Coverage BUILD
