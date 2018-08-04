package Net::SPID::SAML::LogoutResponse::Incoming;
use Moo;

use Carp qw(croak);

extends 'Net::SPID::SAML::ProtocolMessage::Incoming';

has 'StatusCode' => (is => 'lazy', builder => sub {
    $_[0]->xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value')->value
});

has 'StatusCode2' => (is => 'lazy', builder => sub {
    $_[0]->xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value')->value
});

has 'status' => (is => 'lazy', builder => sub {
    my ($sc, $sc2) = ($_[0]->StatusCode, $_[0]->StatusCode2);
    $sc eq 'urn:oasis:names:tc:SAML:2.0:status:Success'
        ? 'success'
        : $sc2 eq 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout'
            ? 'partial'
            : croak "Invalid status '$sc'/'$sc2'";
});

sub _build_Issuer {
    $_[0]->xpath->findvalue('/samlp:LogoutResponse/saml:Issuer')->value;
}

sub validate {
    my ($self, %args) = @_;
    
    $self->SUPER::validate(%args) or return 0;
    
    my $xpath = $self->xpath;
    
    # if message is signed, validate that signature;
    # otherwise validate $args{URL}
    if ($xpath->findnodes('/samlp:LogoutResponse/dsig:Signature')->size > 0) {
        my $pubkey = Crypt::OpenSSL::RSA->new_public_key($self->_idp->cert->pubkey);
        Mojo::XMLSig::verify($self->xml, $pubkey)
            or croak "Signature verification failed";
    } else {
        # this is supposed to be a HTTP-Redirect binding
        $self->_validate_redirect($args{URL});
    }
    
    # TODO: make this check required (and update the checklist in README)
    if (defined $args{in_response_to}) {
        my $in_response_to = $xpath->findvalue('/samlp:LogoutResponse/@InResponseTo')->value;
        croak sprintf "Invalid InResponseTo: '%s' (expected: '%s')",
            $in_response_to, $args{in_response_to}
            if $in_response_to ne $args{in_response_to};
    }
    
    # TODO: make this check required (and update the checklist in README)
    if (exists $args{acs_url}) {
        my $destination  = $xpath->findvalue('/samlp:Response/@Destination')->value;
        croak "Invalid Destination: '%s' (expected: '%s')",
            $destination, $args{slo_url},
            if $destination ne $args{slo_url};
    }
    
    my $status = $xpath->findvalue('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value')->value;
    
    return 1;
}

1;
