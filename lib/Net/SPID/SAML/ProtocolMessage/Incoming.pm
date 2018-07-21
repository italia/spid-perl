package Net::SPID::SAML::ProtocolMessage::Incoming;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage';

has '_idp'  => (is => 'rw', required => 0); # Net::SPID::SAML::IdP
has 'xml'   => (is => 'ro', required => 1);
has 'xpath' => (is => 'lazy');

has 'Issuer' => (is => 'lazy', builder => sub {
    $_[0]->xpath->findvalue('/samlp:Response/saml:Issuer')->value;
});

use Carp qw(croak);
use MIME::Base64 qw(decode_base64);
use XML::XPath;

sub BUILDARGS {
    my ($class, %args) = @_;
    
    if (exists $args{base64}) {
        $args{xml} = decode_base64(delete $args{base64});
    }
    
    return {%args};
}

sub BUILD {
    my ($self) = @_;
    
    print STDERR $self->xml;
}

sub _build_xpath {
    my ($self) = @_;
    
    my $xpath = XML::XPath->new(xml => $self->xml);
    $xpath->set_namespace('saml',  'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->set_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->set_namespace('dsig',  'http://www.w3.org/2000/09/xmldsig#');
    return $xpath;
}

sub validate {
    my ($self, %args) = @_;
    
    my $xpath = $self->xpath;
    
    # detect IdP
    my $idp = $self->_idp($self->_spid->get_idp($self->Issuer))
        or croak "Unknown Issuer: " . $self->Issuer;
    
    # TODO: validate IssueInstant
    
    return 1;
}

1;

=for Pod::Coverage *EVERYTHING*
