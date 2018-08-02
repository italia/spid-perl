package Net::SPID::SAML::LogoutRequest::Outgoing;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage::Outgoing';

has 'session'       => (is => 'ro', required => 1);
has 'binding'       => (is => 'rw', required => 1,
    default => sub { 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' });

use Carp;

sub xml {
    my ($self) = @_;
    
    my ($x, $saml, $samlp) = $self->SUPER::xml;

    my $req_attrs = {
        ID              => $self->ID,
        IssueInstant    => $self->IssueInstant->strftime('%FT%TZ'),
        Version         => '2.0',
        Destination     => $self->_idp->sso_url($self->binding),
    };
    $x->startTag([$samlp, 'LogoutRequest'], %$req_attrs);
    
    $x->dataElement([$saml, 'Issuer'], $self->_spid->sp_entityid,
        Format          => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        NameQualifier   => $self->_spid->sp_entityid,
    );
    
    $x->dataElement([$saml, 'NameID'], $self->session->nameid, 
        Format => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        NameQualifier => $self->_idp->entityid);
    
    $x->dataElement([$samlp, 'SessionIndex'], $self->session->session);
    
    $x->endTag(); #LogoutRequest
    $x->end();
    
    my $xml = $x->to_string;
    
    # TODO: if we're using HTTP-POST, sign this document
    
    return $xml;
}

sub redirect_url {
    my ($self, %args) = @_;
    
    my $url = $self->_idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    return $self->SUPER::redirect_url($url, %args);
}

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # initialize our SPID object
    my $spid = Net::SPID->new(...);
    
    # get an IdP
    my $idp = $spid->get_idp($spid_session->idp_id);
    
    # generate a LogoutRequest
    my $logoutreq = $idp->logoutrequest(
        session => $spid_session,
    );
    my $url = $logoutreq->redirect_url;

=head1 ABSTRACT

This class represents an outgoing LogoutRequest. You can use it to generate such a request in case you're initiating a logout procedure on behalf of your user.

=head1 CONSTRUCTOR

This class is not supposed to be instantiated directly. You can craft a LogoutRequest by calling the L<Net::SPID::SAML::IdP/logoutrequest> method on a L<Net::SPID::SAML::IdP> object.

=head1 METHODS

=head2 xml

This method generates the message in XML format (signed, if using the HTTP-POST binding).

    my $xml = $logoutreq->xml;

=head2 redirect_url

This method returns the full URL of the Identity Provider where user should be redirected in order to initiate their Single Logout. In SAML words, this implements the HTTP-Redirect binding.

    my $url = $logoutreq->redirect_url;

=cut

=for Pod::Coverage BUILD
