#Ldap Entry
Configures a dns host entry per network for this node.

##Configuration
* `$base` - The base dn for this host
* `$domains` - The domains this host can be part of

##Example configuration
Using hiera:

    ldap_entry::base: 'dc=example,dc=com'
    ldap_entry::domains:
      'ip6.example.com': '2001:1234:'
      'ip6-local.example.com': 'fe80:'
