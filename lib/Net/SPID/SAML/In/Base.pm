package Net::SPID::SAML::In::Base;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage';

has '_idp'  => (is => 'rw', required => 0); # Net::SPID::SAML::IdP
has 'xml'   => (is => 'ro', required => 0);
has 'url'   => (is => 'ro', required => 0);
has 'xpath' => (is => 'lazy');

has 'Issuer' => (is => 'lazy');  # Derived classes implement this

has 'RelayState' => (is => 'lazy', builder => sub { URI->new($_[0]) });

use Carp qw(croak);
use IO::Uncompress::RawInflate qw(rawinflate);
use MIME::Base64 qw(decode_base64);
use XML::XPath;
use URI;

sub BUILDARGS {
    my ($class, %args) = @_;
    
    if (exists $args{base64}) {
        $args{xml} = decode_base64(delete $args{base64});
    }
    
    croak "xml or url required"
        if !$args{xml} && !$args{url};
    
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
    
    return 1;
}

sub _validate_redirect {
    my ($self, $url) = @_;
    
    my $u = URI->new($url);
        
    # verify the response
    my $SigAlg = $u->query_param('SigAlg');
    croak "Unsupported SigAlg: $SigAlg"
         unless $SigAlg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    
    my $pubkey = Crypt::OpenSSL::RSA->new_public_key($self->_idp->cert->pubkey);
    my $sig = decode_base64($u->query_param_delete('Signature'));
    $pubkey->verify($u->query, $sig)
        or croak "Signature verification failed";
    
    return 1;
    
    # unpack the SAML request
    my $payload = decode_base64($u->query_param('SAMLResponse'));
    rawinflate \$payload => \$payload;
    
    # unpack the relaystate
    my $relaystate = $u->query_param('RelayState');

    return ($payload, $relaystate);
}

1;

=for Pod::Coverage *EVERYTHING*
