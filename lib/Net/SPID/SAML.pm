package Net::SPID::SAML;
use Moo;

use Carp;
use MIME::Base64 qw(decode_base64);
use Net::SAML2;
use Net::SPID::SAML::Assertion;
use Net::SPID::SAML::AuthnRequest;
use Net::SPID::SAML::IdP;
use Net::SPID::SAML::LogoutRequest;
use Net::SPID::SAML::LogoutResponse;
use URI::Escape qw(uri_escape);

has 'sp_entityid'   => (is => 'ro', required => 1);
has 'sp_key_file'   => (is => 'ro', required => 1);
has 'sp_cert_file'  => (is => 'ro', required => 1);
has 'sp_acs_url'    => (is => 'ro', required => 0);
has 'sp_acs_index'  => (is => 'ro', required => 0);
has 'sp_attr_index' => (is => 'ro', required => 0);
has 'cacert_file'   => (is => 'ro', required => 0);
has '_idp'          => (is => 'ro', default => sub { {} });
has '_sp'           => (is => 'lazy');

extends 'Net::SPID';

sub _build__sp {
    my ($self) = @_;
    
    return Net::SAML2::SP->new(
        id               => $self->sp_entityid,
        url              => 'xxx',
        key              => $self->sp_key_file,
        cert             => $self->sp_cert_file,
        cacert           => $self->cacert_file,
        org_name         => 'xxx',
        org_display_name => 'xxx',
        org_contact      => 'xxx',
    );
}

# TODO: generate the actual SPID button.
sub get_button {
    my ($self, $url_cb) = @_;
    
    # If $url_cb is a sprintf pattern, turn it into a callback.
    if (!ref $url_cb) {
        my $pattern = $url_cb;
        $url_cb = sub {
            sprintf $pattern, uri_escape(shift);
        };
    }
    
    my $html = '';
    foreach my $idp_id (sort keys %{$self->_idp}) {
        $html .= sprintf qq!<p><a href="%s">Log In (%s)</a></p>\n!,
            $url_cb->($idp_id), $idp_id;
    }
    return $html;
}

sub load_idp_metadata {
    my ($self, $dir) = @_;
    
    $self->load_idp_from_xml_file($_) for glob "$dir/*.xml";
}

sub load_idp_from_xml_file {
    my ($self, $xml_file) = @_;
    
    # slurp XML from file
    my $xml = do { local $/ = undef; open my $fh, '<', $xml_file; scalar <$fh> };
    
    return $self->load_idp_from_xml($xml);
}

sub load_idp_from_xml {
    my ($self, $xml) = @_;
    
    my $idp = Net::SPID::SAML::IdP->new_from_xml(
        _spid   => $self,
        xml     => $xml,
        cacert  => $self->cacert_file,
    );
    $self->_idp->{$idp->entityid} = $idp;
    
    if ($self->cacert_file) {
        # TODO: verify IdP certificate and return 0 if invalid
    }
    
    # Since we only support HTTP-Redirect SSO and SLO requests, warn user if the loaded
    # Identity Provider does not expose such bindings (they are not mandatory).
    warn sprintf "IdP '%s' does not have a HTTP-Redirect SSO binding", $idp->entityid,
        if !$idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    warn sprintf "IdP '%s' does not have a HTTP-Redirect SLO binding", $idp->entityid,
        if !$idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    
    return 1;
}

sub idps {
    my ($self) = @_;
    
    return $self->_idp;
}

sub get_idp {
    my ($self, $idp_entityid) = @_;
    
    return $self->_idp->{$idp_entityid};
}

sub parse_assertion {
    my ($self, $payload, $in_response_to) = @_;
    
    my $xml = decode_base64($payload);
    print STDERR $xml;
    
    # verify signature and CA
    my $post = Net::SAML2::Binding::POST->new(
        cacert => $self->cacert_file,
    );
    $post->handle_response($payload)
        or croak "Failed to parse SAML LogoutResponse";
    
    # parse assertion
    my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml => $xml,
    );
    
    my $a = Net::SPID::SAML::Assertion->new(
        _spid       => $self,
        _assertion  => $assertion,
        xml         => $xml,
    );
    
    # Validate audience and timestamps. This will throw an exception in case of failure.
    $a->validate($self->sp_entityid, $in_response_to);
    
    return $a;
}

sub parse_logoutresponse {
    my ($self, $payload, $in_response_to) = @_;
    
    my $xml = decode_base64($payload);
    print STDERR $xml;
    
    # verify signature and CA
    my $post = Net::SAML2::Binding::POST->new(
        cacert => $self->cacert_file,
    );
    $post->handle_response($payload)
        or croak "Failed to parse SAML LogoutResponse";
    
    # parse message
    my $response = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
        xml => $xml,
    );
    
    # validate response
    croak "Invalid SAML LogoutResponse"
        if !$response->valid($in_response_to);
    
    return Net::SPID::SAML::LogoutResponse->new(
        _spid       => $self,
        _logoutres  => $response,
        xml         => $xml,
    );
}

sub parse_logoutrequest {
    my ($self, $payload) = @_;
    
    my $xml = decode_base64($payload);
    print STDERR $xml;
    
    # verify signature and CA
    my $post = Net::SAML2::Binding::POST->new(
        cacert => $self->cacert_file,
    );
    $post->handle_response($payload)
        or croak "Failed to parse SAML LogoutResponse";
    
    # parse message
    my $request = Net::SAML2::Protocol::LogoutRequest->new_from_xml(
        xml => $xml,
    );
    
    return Net::SPID::SAML::LogoutRequest->new(
        _spid       => $self,
        _logoutreq  => $request,
        xml         => $xml,
    );
}

1;
