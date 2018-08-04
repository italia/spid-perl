package Net::SPID::SAML::ProtocolMessage::Outgoing;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage';

has '_idp'              => (is => 'ro', required => 1); # Net::SPID::SAML::IdP
has 'ID'                => (is => 'lazy');
has 'IssueInstant'      => (is => 'lazy');

use Crypt::OpenSSL::Random;
use DateTime;
use IO::Compress::RawDeflate qw(rawdeflate);
use MIME::Base64 qw(encode_base64);
use XML::Writer;
use URI;

sub _build_ID {
    my ($self) = @_;
    
    # first character must not be a digit
    return "_" . unpack 'H*', Crypt::OpenSSL::Random::random_pseudo_bytes(16);
}

sub _build_IssueInstant {
    my ($self) = @_;
    
    return DateTime->now(time_zone => 'UTC');
}

sub xml {
    my ($self) = @_;
    
    my $saml  = 'urn:oasis:names:tc:SAML:2.0:assertion';
    my $samlp = 'urn:oasis:names:tc:SAML:2.0:protocol';
    my $x = XML::Writer->new( 
        OUTPUT          => 'self', 
        NAMESPACES      => 1,
        FORCED_NS_DECLS => [$saml, $samlp],
        PREFIX_MAP      => {
            $saml   => 'saml2',
            $samlp  => 'saml2p'
        }
    );
    
    return ($x, $saml, $samlp);
}

sub redirect_url {
    my ($self, $url, %args) = @_;
    
    my $xml = $self->xml;
    print STDERR $xml, "\n";
    
    my $payload = '';
    rawdeflate \$xml => \$payload;
    $payload = encode_base64($payload, '');
    
    my $u = URI->new($url);
    $u->query_param('SAMLRequest', $payload);
    $u->query_param('RelayState', $args{relaystate}) if defined $args{relaystate};
    $u->query_param('SigAlg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    
    my $sig = encode_base64($self->_spid->sp_key->sign($u->query), '');
    $u->query_param('Signature', $sig);

    return $u->as_string;
}

1;

=for Pod::Coverage *EVERYTHING*
