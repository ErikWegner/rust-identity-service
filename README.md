# rust-identity-service


## Generate key

    openssl genrsa -out local.pem 2048

## Reexport keycloak realm

```
docker-compose exec keycloak /opt/jboss/keycloak/bin/standalone.sh \
 -Djboss.socket.binding.port-offset=100 -Dkeycloak.migration.action=export \
 -Dkeycloak.migration.provider=singleFile \
 -Dkeycloak.migration.realmName=multcorp \
 -Dkeycloak.migration.usersExportStrategy=REALM_FILE \
 -Dkeycloak.migration.file=/tmp/multcorp.json
docker-compose cp keycloak:/tmp/multcorp.json dev_realm.json
```
