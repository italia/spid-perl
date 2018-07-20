package Net::SPID::SAML::ProtocolMessage;
use Moo;

has '_spid' => (is => 'ro', required => 1, weak_ref => 1);  # Net::SPID::SAML

1;
