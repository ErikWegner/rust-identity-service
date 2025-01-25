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

## Development

You can use VSCode with devcontainer extension, or run the containers yourself:

1. `$ cd .devcontainer`
2. `docker compose up -d`
3. `docker compose exec -u ${UID}:${GID} -it ridser /bin/bash`
4. `rustup update stable`
5. `export RUST_LOG=ridser=debug,info`

## Testing
