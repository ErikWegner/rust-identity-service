# rust-identity-service

This service provides login session capabilities and authenticated proxying to
implement a _Backend for Frontend_ pattern.

## Features

- Authentication
  - Login through OpenID connect (e.g. [Keycloak](https://keycloak.org))
  - Store JWT in server side session
  - Provide session to a frontend through a http-only cookie
- API proxy
  - Proxy requests to a backend
  - Attach JWT to proxied requests
  - Protect proxy requests with CSRF token
  - Match request path to select different proxy targets
- File serving
  - Serve files from a local directory
  - Serve each directory with an index.html as a single page app

## Configuration parameters

`RIDSER_DANGER_ACCEPT_INVALID_CERTS`: Accept any certificate when proxying requests.

## Generate key

    openssl genrsa -out local.pem 2048

## Reexport keycloak realm

1. Enter running keycloak container:
   ```bash
   docker exec -it rust-identity-service_devcontainer-keycloak-1 /bin/bash
   ```
2. Export realm
   ```bash
   cd /opt/keycloak/
   ./bin/kc.sh export --file /tmp/multcorp.json --realm multcorp --users same_file
   exit
   ```
3. Copy export file from container to local filesystem
   ```bash
   docker cp rust-identity-service_devcontainer-keycloak-1:/tmp/multcorp.json dev_realm.json
   ```
