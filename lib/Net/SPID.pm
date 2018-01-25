package Net::SPID;

use strict;
use warnings;

use Net::SPID::OpenID;
use Net::SPID::SAML;
use Net::SPID::Session;

sub new {
    my ($class, %args) = @_;
    
    my $protocol = exists $args{protocol}
        ? lc delete $args{protocol}
        : 'saml';
    
    return $protocol eq 'openid'
        ? Net::SPID::OpenID->new(%args)
        : Net::SPID::SAML->new(%args);
}

1;
