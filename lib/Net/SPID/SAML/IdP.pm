package Net::SPID::SAML::IdP;
use Moo;

extends 'Net::SAML2::IdP';
has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML

use Carp;
use Crypt::OpenSSL::X509;

sub authnrequest {
    my ($self, %args) = @_;
    
    return Net::SPID::SAML::Out::AuthnRequest->new(
        _spid       => $self->_spid,
        _idp        => $self,
        %args,
    );
}

sub logoutrequest {
    my ($self, %args) = @_;
    
    return Net::SPID::SAML::Out::LogoutRequest->new(
        _spid       => $self->_spid,
        _idp        => $self,
        %args,
    );
}

sub logoutresponse {
    my ($self, %args) = @_;
    
    return Net::SPID::SAML::Out::LogoutResponse->new(
        _spid       => $self->_spid,
        _idp        => $self,
        %args,
    );
}

sub cert {
    my ($self) = @_;
    
    # legacy, until we ditch Net::SAML2
    return $self->SUPER::cert('signing') if caller =~ /^Net::SAML2/;
    
    return Crypt::OpenSSL::X509->new_from_string(
        $self->SUPER::cert('signing'),
        Crypt::OpenSSL::X509::FORMAT_PEM,
    );
}

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # get an IdP
    my $idp = $spid->get_idp('https://www.prova.it/');
    
    # generate an AuthnRequest
    my $authnreq = $idp->authnrequest(
        #acs_url    => 'https://...',   # URL of AssertionConsumerServiceURL to use
        acs_index   => 0,   # index of AssertionConsumerService as per our SP metadata
        attr_index  => 1,   # index of AttributeConsumingService as per our SP metadata
        level       => 1,   # SPID level
    );

    # generate a LogoutRequest
    my $logoutreq = $idp->logoutrequest(session => $spid_session);
    
    # generate a LogoutResponse
    my $logoutres = $idp->logoutresponse(in_response_to => $logoutreq->id, status => 'success');

=head1 ABSTRACT

This class represents an Identity Provider.

=head1 CONSTRUCTOR

This method is not supposed to be instantiated directly. Use the C<Net::SPID::SAML/get_idp> method in L<Net::SPID::SAML>.

=head1 METHODS

=head2 authnrequest

This method generates an AuthnRequest addressed to this Identity Provider. Note that this method does not perform any network call, it just generates a L<Net::SPID::SAML::Out::AuthnRequest> object.

    my $authnrequest = $idp->authnrequest(
        #acs_url    => 'https://...',   # URL of AssertionConsumerServiceURL to use
        acs_index   => 0,   # index of AssertionConsumerService as per our SP metadata
        attr_index  => 1,   # index of AttributeConsumingService as per our SP metadata
        level       => 1,   # SPID level
    );

The following arguments can be supplied to C<authnrequest()>:

=over

=item I<acs_url>

The value to use for C<AssertionConsumerServiceURL> in AuthnRequest. This is the URL where the user will be redirected (via GET or POST) by the Identity Provider after Single Sign-On. This must be one of the URLs contained in our Service Provider metadata. This is required if L<acs_index> is not set, but it can be omitted if the L<Net::SPID/sp_acs_url> option was set in L<Net::SPID>.

=item I<acs_index>

The value to use for C<AssertionConsumerServiceIndex> in AuthnRequest. As an alternative to specifying the URL explicitely in each AuthnRequest using L<acs_url>, a numeric index referring to the URL(s) specified in the Service Provider metadata can be supplied. It can be omitted if the L<Net::SPID/sp_acs_index> option was set in L<Net::SPID>. This is required if L<acs_url> is not set, but it can be omitted if the L<Net::SPID/acs_index> option was set in L<Net::SPID>.

=item I<attr_index>

(Optional.) The value to use for C<AttributeConsumingServiceIndex> in AuthnRequest. This refers to the C<AttributeConsumingService> specified in the Service Provider metadata. If omitted, the L<Net::SPID/sp_attr_index> option set in L<Net::SPID> will be used. If that was not set, no attributes will be requested at all.

=item I<level>

(Optional.) The SPID level requested (as an integer; can be 1, 2 or 3). If omitted, 1 will be used.

=back

=head2 logoutrequest

This method generates a LogoutRequest addressed to this Identity Provider. Note that this method does not perform any network call, it just generates a L<Net::SPID::SAML::LogoutRequest> object.

    my $logoutreq = $idp->logoutrequest(session => $spid_session);

The following arguments can be supplied to C<logoutrequest()>:

=over

=item I<session_index>

The L<Net::SPID::Session> object (originally returned by L<Net::SPID::SAML/parse_assertion> through a L<Net::SPID::SAML::In::Assertion> object) representing the SPID session to close.

=back

=head2 logoutresponse

This method generates a LogoutResponse addressed to this Identity Provider. You usually need to generate a LogoutResponse when user initiated a logout on another Service Provider (or from the Identity Provider itself) and thus you got a LogoutRequest from the Identity Provider. Note that this method does not perform any network call, it just generates a L<Net::SPID::SAML::LogoutResponse> object.

    my $logoutres = $idp->logoutresponse(
        status          => 'success',
        in_response_to  => $logoutreq->id,
    );

The following arguments can be supplied to C<logoutresponse()>:

=over

=item I<status>

This can be either C<success>, C<partial>, C<requester> or C<responder> according to the SAML specs.

=back

=head2 cert

Returns the signing certificate for this Identity Provider as a L<Crypt::OpenSSL::X509> object.

=cut
