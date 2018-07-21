package Net::SPID::SAML::ProtocolMessage::Outgoing;
use Moo;

extends 'Net::SPID::SAML::ProtocolMessage';

has '_idp'              => (is => 'ro', required => 1); # Net::SPID::SAML::IdP
has 'ID'                => (is => 'lazy');
has 'IssueInstant'      => (is => 'lazy');
has 'binding'           => (is => 'rw', required => 1,
    default => sub { 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' });

use Crypt::OpenSSL::Random;
use DateTime;
use XML::Writer;

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

1;

=for Pod::Coverage *EVERYTHING*
