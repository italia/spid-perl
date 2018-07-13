package Net::SPID::SAML::ProtocolMessage;
use Moo;

has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML
has '_idp'  => (is => 'ro', required => 1 );                # Net::SPID::SAML::IdP

has 'ID'                => (is => 'rw', required => 0);
has 'IssueInstant'      => (is => 'rw', required => 0);
has 'ProtocolBinding'   => (is => 'rw', required => 0,
    default => sub { 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' });

use XML::Writer;

sub BUILD {
    my ($self) = @_;
    
    if (!defined $self->ID) {
        # TODO: first character should not be a digit
        $self->id(unpack 'H*', Crypt::OpenSSL::Random::random_pseudo_bytes(16));
    }
    
    if (!defined $self->IssueInstant) {
        $self->IssueInstant(DateTime->now(time_zone => 'UTC'));
    }
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
