class ldap_entry(
  $base,
  $domains,
){

  $cn = $::trusted['hostname'];
  if $::facts['networking'] == undef {
    $all_ifs = split($::facts['interfaces'],',')
    $physical_ifs = $all_ifs.filter |$if| { $if =~ /^eth/ }
    
    $macs = $physical_ifs.map |$if| { $::facts["macaddress_$if"] }
    $ip4 = $physical_ifs.map |$if| { $::facts["ipaddress_$if"] }
    $ip6 = $physical_ifs.map |$if| { $::facts["ipaddress6_$if"] }
  } else {
    $all_ifs = $::facts['networking']['interfaces']
    $physical_ifs = $all_ifs.filter |$if| { $if[0] =~ /^eth/ }

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
  }

  if empty($ip6) and empty($ip4) {
    notify { "Unable to detect ip addresses. Interfaces detected: ${all_ifs}": }
  }

  ldap::object { "dc=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    attributes => {
      'objectClass' => [
        'domain',
        'top',
        'gosaDepartment',
      ],
      'dc'          => $cn,
      'ou'          => $cn,
      'description' => $cn,
    },
  }
  
  ldap::object { "ou=systems,dc=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    attributes => {
      'objectClass' => [
        'organizationalUnit',
      ],
      'ou'          => 'systems',
    },
    require    => Ldap::Object["dc=${cn},${base}"],
  }
  
  ldap::object { "ou=servers,ou=systems,dc=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    attributes => {
      'objectClass' => [
        'organizationalUnit',
      ],
      'ou'          => 'servers',
    },
    require    => Ldap::Object["ou=systems,dc=${cn},${base}"],
  }

  ldap::object { "cn=${cn},ou=servers,ou=systems,dc=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    attributes => {
      'cn'           => $cn,
      'objectClass'  => [
        'device',
        'ipHost',
        'goServer',
        'puppetClient',
      ],
      'ipHostNumber' => $ip4 + $ip6,
      'macAddress'   => $macs,
      'environment'  => $server_facts['environment'],
    },
    require    => Ldap::Object["ou=servers,ou=systems,dc=${cn},${base}"],
  }

  ldap::object { "ou=dns,dc=${cn},${base}":
    ensure     => present,
    authtype   => 'EXTERNAL',
    require    => Ldap::Object["dc=${cn},${base}"],
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
        ldap::object { "zonename=${zone},ou=dns,dc=${cn},${base}":
          ensure     => present,
          authtype   => 'EXTERNAL',
          require    => Ldap::Object["ou=dns,dc=${cn},${base}"],
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
