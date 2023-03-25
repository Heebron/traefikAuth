# traefikAuth - PKI authentication and access control

Provides a [traefik](https://github.com/traefik/traefik)
[forwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
service that implements access whitelisting based on client service host name, PKI certificate CN and O
attributes.

The policy file is monitored for changes. This allows one to update it without restarting the service.

## Command line

```
Usage of ./traefikAuth:
  -bindAddr string
        which network device to bind (default "0.0.0.0")
  -caFile string
        pem encoded file containing X.509 trusted issuer certificates to add to platform truststore
  -cacheSize int
        identity decision working set size (default 53)
  -certFile string
        pem encoded file containing a X.509 server certificate
  -cidrs string
        incoming connections must come from within this list of comma separated CIDRs
  -keyFile string
        pem encoded file containing an unencrypted X.509 certificate key
  -listenPort int
        upon which TCP/IP port to listen for traefik connections (default 7980)
  -policy string
        policyMap file (default "/home/kjpratt/.traefikForwardAuthPolicy.yaml")
  -version
        show the version and quit
```

The service also provides [Prometheus](https://prometheus.io/) metrics at the context /metrics. Make sure to add the
CIDR for the clients
that will be using the /metrics context.

In order to use TLS, you must provide both the server cert *-certFile* and matching key *-keyFile* on the command
line.

## Policy File

```yaml
# the Flintstones SOHO
- o: '^Family|Friends$' # regexp match on organization
  cn:
    allow:
      - Fred Flintstone
      - Wilma Flintstone
```

This policy file authorizes only those presenting client certificates with an O of 'Family' and a CN that matches
'Fred Flintstone' or 'Wilma Flintstone' and targeting a service name that has a domain portion matching
'flintstones.com'.

## Systemd

Here is an example systemd unit file. I run traefik in Docker. The below sets the service to start
before the Docker service starts.

```unit file (systemd)
[Unit]
Description=traefik PKI client cert whitelisting agent
After=network.target
Before=docker.service

[Service]
ExecStart=/opt/auth/traefikAuth
ExecReload=/bin/kill -SIGUSR1 $MAINPID

[Install]
WantedBy=docker.service
```

## traefik labels

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
