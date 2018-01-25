package Net::SPID::Session;
use Moo;

has 'idp_id'        => (is => 'ro', required => 1);
has 'nameid'        => (is => 'ro', required => 1);
has 'session'       => (is => 'ro', required => 1);
has 'assertion_xml' => (is => 'ro', required => 1);
has 'attributes'    => (is => 'ro', default => sub { {} });

1;
