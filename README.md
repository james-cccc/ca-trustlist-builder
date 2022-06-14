# ca-trustlist-builder

## Configuring the RHCOS CA Bundle

[Red Hat Enterprise Linux Root Certificate Authority Frequently Asked Questions](https://access.redhat.com/solutions/46025)

Just like in RHEL and other major Linux distributions, RHCOS uses the 'ca-certificates' package and thus bundles in the set of CA certificates chosen by the Mozilla Foundation for use with the Internet PKI (the default trust bundle has ~140 CAs). Limiting trust to only what is required has been a long-standing good security practice and if you wish to perform some additional security hardening and remove some of the trusted CAs it is possible to do so as documented [here](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-shared-system-certificates_security-hardening), however, as RHCOS is managed in an immutable fashion changes to the OS have to be done through [machine config](https://docs.openshift.com/container-platform/4.10/post_installation_configuration/machine-configuration-tasks.html).

### Why?

The concern is that one of these CAs could sign fraudulent certificates, which could then be used to trick a service into trusting a MITM or otherwise fraudulent service. However, if/when that is done, it would mean that the world is equally vulnerable at the same time. The likelihood of this could be classed as low, however, it's arguably still worth doing especially in regulated industries and organisations which dictate strict security policies.

### How?

The aforementioned the ca-certificates package provides a method in which certificates to be blacklisted (as defined within a machineconfig) can be placed in the relevant subdirectory /etc/pki/ca-trust/source/blacklist/ in order to treat them as distrusted. However, as the ca-certificate package will update so will the Mozilla trust DB, so this would have to be a task you'd keep on top of due to the bundle's evolving nature.

## Procedure

This repo contains an Ansible playbook that uses a jinja2 template to generate machineconfigs based on certificates in the blacklisted_certs and whitelisted_certs directories.

### Verify CAs

Please be careful in what is blacklisted e.g. registry.redhat.io requires a DigiSign CA and quay.io requires an Amazon CA. You can verify the CA by doing:
```bash
openssl s_client -connect registry.redhat.io:443
openssl s_client -connect quay.io:443
```
NOTE: Please do not blindly blacklist all CAs without first considering what is required in your environment.

### Prepare Certificates

If your starting off building your certificate whitelists/blacklists from a bundle e.g. ca-bundle.crt you can do the following to cut the bundle into individual certificates

1. Cut bundle into individual files
```bash
csplit -z ca-bundle.crt /#/ '{*}'
```

2. Remove blank lines
```bash
sed -i '/^$/d' xx*
```

3. Rename files
```bash
for file in xx*; do mv $file $(head -n 1 $file | tr -d \#" "); done
```
You can then remove/move these individual certificates into the blacklisted_certs or whitelisted_certs directories.

### Example

The below example shows adding Naver certs into whitelisted_certs and Hellenic certs into blacklisted_certs.

#### Whitelisted
```bash
sh-4.4# trust list --filter=ca-anchors | grep NAVER
    label: NAVER Secure Certification Authority 1
    label: NAVER Global Root Certification Authority
```
```bash
pkcs11:id=%e9%f9%eb%97%be%21%f2%54%c7%e9%26%37%02%39%ba%fc%b1%9b%0c%e9;type=cert
    type: certificate
    label: NAVER Secure Certification Authority 1
    trust: anchor
    category: authority

pkcs11:id=%d2%9f%88%df%a1%cd%2c%bd%ec%f5%3b%01%01%93%33%27%b2%eb%60%4b;type=cert
    type: certificate
    label: NAVER Global Root Certification Authority
    trust: anchor
    category: authority
```

#### Blacklisted
```bash
sh-4.4# trust list --filter=blacklist | grep Hellenic
    label: Hellenic Academic and Research Institutions RootCA 2011
    label: Hellenic Academic and Research Institutions ECC RootCA 2015
    label: Hellenic Academic and Research Institutions RootCA 2015
```
```bash
pkcs11:id=%b4%22%0b%82%99%24%01%0e%9c%bb%e4%0e%fd%bf%fb%97%20%93%99%2a;type=cert
    type: certificate
    label: Hellenic Academic and Research Institutions ECC RootCA 2015
    trust: blacklisted
    category: authority

pkcs11:id=%71%15%67%c8%c8%c9%bd%75%5d%72%d0%38%18%6a%9d%f3%71%24%54%0b;type=cert
    type: certificate
    label: Hellenic Academic and Research Institutions RootCA 2015
    trust: blacklisted
    category: authority

pkcs11:id=%a6%91%42%fd%13%61%4a%23%9e%08%a4%29%e5%d8%13%04%23%ee%41%25;type=cert
    type: certificate
    label: Hellenic Academic and Research Institutions RootCA 2011
    trust: blacklisted
    category: authority
```

## Related Reading

### Configuration

* [System trust store configuration](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-shared-system-certificates_security-hardening)
* [Machine config overview](https://docs.openshift.com/container-platform/4.10/post_installation_configuration/machine-configuration-tasks.html#machine-config-overview-post-install-machine-configuration-tasks)
* [Supported ignition config changes](https://github.com/openshift/machine-config-operator/blob/master/docs/MachineConfigDaemon.md#supported-vs-unsupported-ignition-config-changes)
* [Ignition config spec](https://coreos.github.io/ignition/configuration-v3_2)

### Mozilla CA Bundle
* [Mozilla CA FAQ](https://wiki.mozilla.org/CA/FAQ)
* [CA Information Report](https://ccadb-public.secure.force.com/mozilla/CAInformationReport)
* [CA certificates extracted from Mozilla](https://curl.se/docs/caextract.html)
