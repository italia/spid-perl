package Net::SPID::SAML::Assertion;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage::Incoming';

has 'NotBefore' => (is => 'lazy', builder => sub {
    DateTime::Format::XSD->parse_datetime
        ($_[0]->xpath->findvalue('//saml:Conditions/@NotBefore')->value)
});

has 'NotOnOrAfter' => (is => 'lazy', builder => sub {
    DateTime::Format::XSD->parse_datetime
        ($_[0]->xpath->findvalue('//saml:Conditions/@NotOnOrAfter')->value)
});

has 'SubjectConfirmationData_NotOnOrAfter' => (is => 'lazy', builder => sub {
    DateTime::Format::XSD->parse_datetime
        ($_[0]->xpath->findvalue('//saml:SubjectConfirmationData/@NotOnOrAfter')->value)
});

has 'NameID' => (is => 'lazy', builder => sub {
    $_[0]->xpath->findvalue('//saml:Subject/saml:NameID')->value
});

has 'SessionIndex' => (is => 'lazy', builder => sub {
    $_[0]->xpath->findvalue('//saml:AuthnStatement/@SessionIndex')->value
});

has 'spid_level' => (is => 'lazy', builder => sub {
    my $classref = $_[0]->xpath->findvalue('//saml:AuthnContextClassRef')->value
        or return undef;
    $classref =~ /SpidL(\d)$/ or return undef;
    return $1;
});

has 'attributes' => (is => 'lazy', builder => sub {
    {
        map { $_->getAttribute('Name') => $_->findnodes("*[local-name()='AttributeValue']")->[0]->string_value }
            $_[0]->xpath->findnodes("//saml:Assertion/saml:AttributeStatement/saml:Attribute"),
    }
});

use Carp;
use DateTime;
use DateTime::Format::XSD;
use Mojo::XMLSig;

sub validate {
    my ($self, %args) = @_;
    
    $self->SUPER::validate(%args) or return 0;
    
    my $xpath = $self->xpath;
    
    {
        my $response_issuer  = $xpath->findvalue('/samlp:Response/saml:Issuer')->value;
        my $assertion_issuer = $xpath->findvalue('//saml:Assertion/saml:Issuer')->value;
    
        croak "Response/Issuer ($response_issuer) does not match Assertion/Issuer ($assertion_issuer)"
            if $response_issuer ne $assertion_issuer;
    }
    
    # this validates all the signatures in the given XML, and requires that at least one exists
    #Mojo::XMLSig::verify($self->xml, $self->_idp->cert->pubkey)
    #    or croak "Signature verification failed";
    
    # SPID regulations require that Assertion is signed, while Response can be not signed
    croak "Response/Assertion is not signed"
        if $xpath->findnodes('//saml:Assertion/dsig:Signature')->size == 0;
    
    {
        my $audience = $xpath->findvalue('//saml:Conditions/saml:AudienceRestriction/saml:Audience')->value;
        croak sprintf "Invalid Audience: '%s' (expected: '%s')",
            $audience, $self->_spid->sp_entityid
            if $audience ne $self->_spid->sp_entityid;
    }
    
    if (defined $args{in_response_to}) {
        my $in_response_to = $xpath->findvalue('//saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo')->value;
        croak sprintf "Invalid InResponseTo: '%s' (expected: '%s')",
            $in_response_to, $args{in_response_to}
            if $in_response_to ne $args{in_response_to};
    }
    
    my $now = DateTime->now;
    
    # exact match is ok
    croak sprintf "Invalid NotBefore: '%s' (now: '%s')",
        $self->NotBefore->iso8601, $now->iso8601
        if DateTime->compare($now, $self->NotBefore) < 0;
    
    # exact match is *not* ok
    croak sprintf "Invalid NotOnOrAfter: '%s' (now: '%s')",
        $self->NotOnOrAfter->iso8601, $now->iso8601
        if DateTime->compare($now, $self->NotOnOrAfter) > -1;
    
    # exact match is *not* ok
    croak sprintf "Invalid SubjectConfirmationData/NotOnOrAfter: '%s' (now: '%s')",
        $self->SubjectConfirmationData_NotOnOrAfter->iso8601, $now->iso8601
        if DateTime->compare($now, $self->SubjectConfirmationData_NotOnOrAfter) > -1;
    
    # TODO: make this check required (and update the checklist in README)
    if (exists $args{acs_url}) {
        my $destination  = $xpath->findvalue('//samlp:Response/@Destination')->value;
        croak "Invalid Destination: '%s' (expected: '%s')",
            $destination, $args{acs_url},
            if $destination ne $args{acs_url};
        
        my $recipient  = $xpath->findvalue('//saml:SubjectConfirmationData/@Recipient')->value;
        croak "Invalid SubjectConfirmationData/\@Recipient: '%s' (expected: '%s')",
            $recipient, $args{acs_url},
            if $recipient ne $args{acs_url};
    }
    
    return 1;
}

sub spid_session {
    my ($self) = @_;
    
    return Net::SPID::Session->new(
        idp_id          => $self->Issuer,
        nameid          => $self->NameID,
        session         => $self->SessionIndex,
        attributes      => $self->attributes,
        level           => $self->spid_level,
        assertion_xml   => $self->xml,
    );
}

1;

=head1 SYNOPSIS

    use Net::SPID;
    
    # initialize our SPID object
    my $spid = Net::SPID->new(...);
    
    # parse a response from an Identity Provider
    my $assertion = eval {
        $spid->parse_assertion($saml_response_xml, $authnreq_id);
    };
    
    # perform validation
    die "Invalid assertion!" if !$assertion->validate($our_entityid, $request_id);
    
    # read the SPID level
    print "SPID Level: ", $assertion->spid_level, "\n";
    
    # get a Net::SPID::Session object (serializable for later reuse, such as logout)
    my $session = $assertion->spid_session;

=head1 ABSTRACT

This class represents an incoming SPID Response/Assertion message. We get such messages either after an AuthnRequest (Single Sign-On) or after an AttributeQuery.

=head1 CONSTRUCTOR

This class is not supposed to be instantiated directly. It is returned by L<Net::SPID::SAML/parse_assertion>.

=head1 METHODS

=head2 xml

This method returns the raw assertion in its XML format.

    my $xml = $assertion->xml;

=head2 validate

This method performs validation by calling all of the C<valid_*> methods described below.

On success it returns a true value. On failure it will throw an exception.

    eval {
        $assertion->validate(
            in_response_to  => $authnrequest_id,
            acs_url         => $acs_url,
        );
    };
    die "Invalid assertion: $@" if $@;

The following arguments are expected:

=item I<in_response_to>

This must be the ID of the AuthnRequest we sent, which you should store in the user's session in order to supply it to this method. It will be used for checking that the I<InResponseTo> field of the assertion matches our request.

=item I<acs_url>

This must be the URL of the AssertionConsumerService endpoint which received this assertion. It will be used for checking that it matches the I<Destination> value claimed in the assertion itself.

=back

=head2 spid_level

This method returns the SPID level asserted by the Identity Provider, as an integer (1, 2 or 3). Note that this may not coincide with the level requested in the AuthnRequest.

=head2 spid_session

This method returns a L<Net::SPID::Session> object populated with information from this Assertion. It's serializable and you might want to store it for later reuse (i.e. for generating a logout request).

=head2 attributes

This method returns a hashref containing the attributes.

=cut
