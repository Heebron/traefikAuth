# traefikAuth - PKI authentication and access control

Provides a [traefik](https://github.com/traefik/traefik)
[forwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
service that implements access whitelisting based on client PKI certificate 'CN' and 'O' attributes.

The configuration file is monitored for changes. This allows one to dynamically update the access control policy.

## Configuration

```yaml
source cidr: [ 10.0.0.0/8 ]
listen port: 7980
bind addr: 0.0.0.0
cache size: 1000


```

The above constrains the service to only accept traefik forwardAuth connections coming from IP addresses in the
10.0.0.0/8 range; configures the service to listen on port 7980 using all network devices; and sets an LRU cache size
of 1000 entries.

## Policy File

```yaml
# the Flintstones SOHO
- service name: '^.*\.flintstones\.com'
  o: '^Family|Friends$' # regexp match
  cn:
    - Fred|Wilma Flintstone
```

This policy file authorizes only those presenting client certificates with an 'O' of 'Family' and a 'CN' that matches
'Fred Flintstone' or 'Wilma Flintstone' and targeting a service name that has a domain portion matching
flintstones.com.

## Systemd

Here is an example systemd unit file. I run traefic in Docker The below sets the service to start
before the Docker service starts.

```unit file (systemd)
[Unit]
Description=traefik PKI client cert whitelisting agent
After=network.target

[Service]
ExecStart=/opt/auth/traefikAuth

[Install]
WantedBy=docker.service
```

## traefic labels

traefik uses the concept of 'middleware' to process incoming requests. The middleware setup is provided using Docker
labels.
Here is an example that controls access to a [Portainer](https://www.portainer.io/) deployment.

```yaml
labels:
  - "traefik.http.routers.portainer.middlewares=pkiwhitelist"
  - "traefik.http.routers.portainer.tls=true"
  - "traefik.http.routers.portainer.tls.options=certRequired@file"
  - "traefik.http.middlewares.authserver.forwardauth.address=http://192.168.10.99:7980"
  - "traefik.http.middlewares.passCertInfo.passtlsclientcert.info.subject.commonName=true"
  - "traefik.http.middlewares.passCertInfo.passtlsclientcert.info.issuer.organization=true"
  - "traefik.http.middlewares.pkiwhitelist.chain.middlewares=passCertInfo,authserver"
```
