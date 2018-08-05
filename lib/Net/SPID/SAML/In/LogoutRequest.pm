package Net::SPID::SAML::In::LogoutRequest;
use Moo;

extends 'Net::SPID::SAML::In::Base';

use Carp qw(croak);

sub validate {
    my ($self, %args) = @_;
    
    $self->SUPER::validate(%args) or return 0;
    
    my $xpath = $self->xpath;
    
    # if message is signed, validate that signature;
    # otherwise validate $args{URL}
    $self->_validate_post_or_redirect($args{URL});
    
    # TODO: make this check required (and update the checklist in README)
    if (exists $args{slo_url}) {
        my $destination  = $xpath->findvalue('/samlp:LogoutRequest/@Destination')->value;
        croak "Invalid Destination: '%s' (expected: '%s')",
            $destination, $args{slo_url},
            if $destination ne $args{slo_url};
    }
    
    return 1;
}

sub make_response {
    my ($self, %args) = @_;
    
    return $self->_idp->logoutresponse(in_response_to => $self->ID, %args);
}

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # initialize our SPID object
    my $spid = Net::SPID->new(...);
    
    # parse a LogoutRequest
    my $logoutreq = $spid->parse_logoutrequest($payload, $url);

=head1 ABSTRACT

This class represents an incoming LogoutRequest. You can use this to parse a logout request in case the user initiated a logout procedure elsewhere and an Identity Provider is requesting logout to you.

=head1 CONSTRUCTOR

This class is not supposed to be instantiated directly. You can get one by calling L<Net::SPID::SAML/parse_logoutrequest>.

=head1 METHODS

=head2 xml

This method returns the raw message in XML format.

    my $xml = $logoutreq->xml;

=head2 validate

This method performs validation of the incoming message according to the SPID rules. In case of success it returns a true value; in case of failure it will die with the relevant error.

    eval { $logoutreq->validate };
    if ($@) {
        warn "Bad LogoutRequest: $@";
    }

=head2 make_response

This is a shortcut for L<Net::SPID::SAML::IdP/logoutresponse>. See its documentation for the required parameters (C<in_response_to> is automatically supplied).

    my $logoutres = $logoutreq->make_response(
        status => 'success',
    );

=cut
