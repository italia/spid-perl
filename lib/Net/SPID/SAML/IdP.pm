package Net::SPID::SAML::IdP;
use Moo;

extends 'Net::SAML2::IdP';
has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML

use Carp;

sub authnrequest {
    my ($self, %args) = @_;
    
    my $authnreq = $self->_spid->_sp->authn_request(
        $self->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        $self->format,  # always urn:oasis:names:tc:SAML:2.0:nameid-format:transient
    );
    
    if (defined $args{acs_url} || defined $self->_spid->sp_acs_url) {
        $authnreq->assertion_url($args{acs_url} // $self->_spid->sp_acs_url);
    } elsif (defined $args{acs_index} || defined $self->_spid->sp_acs_index) {
        $authnreq->assertion_index($args{acs_index} // $self->_spid->sp_acs_index);
    } else {
        croak "sp_acs_url or sp_acs_index are required\n";
    }
    
    if (defined $args{attr_index} || defined $self->_spid->sp_attr_index) {
        $authnreq->attribute_index($args{attr_index} // $self->_spid->sp_attr_index);
    }
    
    $authnreq->protocol_binding('HTTP-POST');
    $authnreq->issuer_namequalifier($self->_spid->sp_entityid);
    $authnreq->issuer_format('urn:oasis:names:tc:SAML:2.0:nameid-format:entity');
    $authnreq->nameidpolicy_format('urn:oasis:names:tc:SAML:2.0:nameid-format:transient');
    $authnreq->AuthnContextClassRef([ 'https://www.spid.gov.it/SpidL' . ($args{level} // 1) ]);
    $authnreq->RequestedAuthnContext_Comparison($args{comparison} // 'minimum');
    $authnreq->ForceAuthn(1) if ($args{level} // 1) > 1;
    
    return Net::SPID::SAML::AuthnRequest->new(
        _spid       => $self->_spid,
        _idp        => $self,
        _authnreq   => $authnreq,
    );
}

sub logoutrequest {
    my ($self, %args) = @_;
    
    my $req = $self->_spid->_sp->logout_request(
        $self->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        $args{session}->nameid,
        $self->format,  # always urn:oasis:names:tc:SAML:2.0:nameid-format:transient
        $args{session}->session,
    );
    
    return Net::SPID::SAML::LogoutRequest->new(
        _spid       => $self->_spid,
        _idp        => $self,
        _logoutreq  => $req,
    );
}

sub logoutresponse {
    my ($self, %args) = @_;
    
    my $res = $self->_spid->_sp->logout_response(
        # FIXME: what is the correct Destination for a LogoutResponse?
        $self->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
        'success',
        $args{in_response_to},
    );
    
    if ($args{status} && $args{status} eq 'partial') {
        $res->status($res->status_uri('requester'));
        $res->substatus($res->status_uri('partial'));
    }
    
    return Net::SPID::SAML::LogoutResponse->new(
        _spid       => $self->_spid,
        _idp        => $self,
        _logoutres  => $res,
    );
}

1;
