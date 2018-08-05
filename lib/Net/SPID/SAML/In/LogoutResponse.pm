package Net::SPID::SAML::In::LogoutResponse;
use Moo;

use Carp qw(croak);

extends 'Net::SPID::SAML::In::Base';

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

sub validate {
    my ($self, %args) = @_;
    
    $self->SUPER::validate(%args) or return 0;
    
    my $xpath = $self->xpath;
    
    # if message is signed, validate that signature;
    # otherwise validate $args{URL}
    $self->_validate_post_or_redirect($args{URL});
    
    # TODO: make this check required (and update the checklist in README)
    if (defined $args{in_response_to}) {
        my $in_response_to = $xpath->findvalue('/samlp:LogoutResponse/@InResponseTo')->value;
        croak sprintf "Invalid InResponseTo: '%s' (expected: '%s')",
            $in_response_to, $args{in_response_to}
            if $in_response_to ne $args{in_response_to};
    }
    
    # TODO: make this check required (and update the checklist in README)
    if (exists $args{slo_url}) {
        my $destination  = $xpath->findvalue('/samlp:LogoutResponse/@Destination')->value;
        croak "Invalid Destination: '%s' (expected: '%s')",
            $destination, $args{slo_url},
            if $destination ne $args{slo_url};
    }
    
    return 1;
}

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # initialize our SPID object
    my $spid = Net::SPID->new(...);
    
    # parse a LogoutResponse
    my $logoutres = $spid->parse_logoutresponse($payload, $url, $in_response_to);

=head1 ABSTRACT

This class represents an incoming LogoutResponse. You can use this to parse the response coming from the Identity Provider after you sent a LogoutRequest for a SP-initiated logout.

=head1 CONSTRUCTOR

This class is not supposed to be instantiated directly. You can get one by calling L<Net::SPID::SAML/parse_logoutresponse>.

=head1 METHODS

=head2 xml

This method returns the raw message in XML format.

    my $xml = $logoutres->xml;

=head2 validate

This method performs validation of the incoming message according to the SPID rules. In case of success it returns a true value; in case of failure it will die with the relevant error.

    eval { $logoutres->validate };
    if ($@) {
        warn "Bad LogoutResponse: $@";
    }

=head2 status

This method returns I<success>, I<failure> or I<partial> according to the status code returned by the Identity Provider.

    my $result = $logoutres->status;

=cut
