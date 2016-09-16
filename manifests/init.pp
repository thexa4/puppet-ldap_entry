class ldap_entry(
  $base,
  $domains,
){

  $all_ifs = $::facts['networking']['interfaces']
  $physical_ifs = $all_ifs.filter |$if| { $if[0] =~ /^eth/ }
  $cn = $::trusted['hostname'];

  $macs = $physical_ifs.map |$if| { $if[1]['mac'] }
  $ip4 = flatten($all_ifs.map |$if| {
    if empty($if[1]['bindings']) {
      []
    } else {
      $filtered = $if[1]['bindings'].filter |$bind| {
        $bind['address'] =~ /^192/
      }
      if (empty($filtered)) {
        []
      } else {
        $filtered.map |$bind| { $bind['address'] }
      }
    }

  })
  $ip6 = flatten($all_ifs.map |$if| {
    if empty($if[1]['bindings6']) {
      []
    } else {
      $filtered = $if[1]['bindings6'].filter |$bind| {
        $bind['address'] =~ /^[23]/
      }
      if (empty($filtered)) {
        []
      } else {
        $filtered.map |$bind| { $bind['address'] }
      }
    }

  })
  
  ldap::object { "cn=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    attributes => {
      'cn'           => $cn,
      'objectClass'  => [
        'device',
        'ipHost',
        'ieee802Device',
        'puppetClient',
      ],
      'ipHostNumber' => $ip4 + $ip6,
      'macAddress'   => $macs,
      'environment'  => $::envirionment,
    },
  }

  ldap::object { "ou=dns,cn=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    require    => Ldap::Object["cn=${cn},${base}"],
    attributes => {
      'objectClass' => [
        'organizationalUnit',
      ],
      'ou'          => 'dns',
    },
  }

  $zones = keys($domains)

  $zones.map |$zone|  {
    $prefix = $domains[$zone]
    $ip6.map |$ip| {
      $first = $ip[0,size($prefix)]

      if $first == $prefix {
        ldap::object { "zonename=${zone},ou=dns,cn=${cn},${base}":
          ensure     => present,
          authtype   => 'EXTERNAL',
          require    => Ldap::Object["ou=dns,cn=${cn},${base}"],
          attributes => {
            'objectClass'        => [
              'dNSZone',
            ],
            'relativeDomainName' => $cn,
            'zonename'           => $zone,
            'AAAARecord'         => $ip,
          },
        }
      }
    }
  }
}
