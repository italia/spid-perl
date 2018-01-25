package Net::SPID::SAML::Assertion;
use Moo;

has '_spid'         => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML
has '_assertion'    => (is => 'ro', required => 1);                 # Net::SAML2::Protocol::Assertion
has 'xml'           => (is => 'ro', required => 1);                 # original unparsed XML

use Carp;
use DateTime;

sub validate {
    my ($self, $audience, $in_response_to) = @_;
    
    croak sprintf "Invalid Audience: '%s' (expected: '%s')",
        $self->_assertion->audience, $audience
        if defined $audience && !$self->valid_audience($audience);
    
    croak sprintf "Invalid InResponseTo: '%s' (expected: '%s')",
        $self->_assertion->in_response_to, $in_response_to
        if defined $in_response_to && !$self->valid_in_response_to($in_response_to);
    
    croak sprintf "Invalid NotBefore: '%s' (now: '%s')",
        $self->_assertion->not_before, DateTime->now->iso8601
        if !$self->valid_not_before;
    
    croak sprintf "Invalid NotAfter: '%s' (now: '%s')",
        $self->_assertion->not_after, DateTime->now->iso8601
        if !$self->valid_not_after;
    
    return 1;
}

sub valid_audience {
    my ($self, $audience) = @_;
    
    return $audience eq $self->_assertion->audience;
}

sub valid_in_response_to {
    my ($self, $in_response_to) = @_;
    
    return $in_response_to eq $self->_assertion->in_response_to;
}

sub valid_not_before {
    my ($self) = @_;
    
    # exact match is ok
    return DateTime->compare(DateTime->now, $self->_assertion->not_before) > -1;
}

sub valid_not_after {
    my ($self) = @_;
    
    # exact match is *not* ok
    return DateTime->compare($self->_assertion->not_after, DateTime->now) > 0;
}

sub spid_level {
    my ($self) = @_;
    
    if ($self->_assertion->AuthnContextClassRef->[0]) {
        $self->_assertion->AuthnContextClassRef->[0] =~ /SpidL(\d)$/;
        return $1;
    }
    
    return undef;
}

sub spid_session {
    my ($self) = @_;
    
    return Net::SPID::Session->new(
        idp_id          => $self->_assertion->issuer->as_string,
        nameid          => $self->_assertion->nameid,
        session         => $self->_assertion->session,
        assertion_xml   => $self->xml,
        attributes      => $self->_assertion->attributes,
        level           => $self->spid_level,
    );
}

1;
