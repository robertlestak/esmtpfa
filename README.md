# esmtpfa - ESMTP Federated Auth

A small ESMTP relay with a pluggable federated authentication system.

This service will listen on a local port for incoming SMTP connections, and will validate the client's provided authentication credentials against the configured remote authentication service(s). If the credentials are valid, the client will be allowed to send mail through the relay. The relay then authenticates with the upstream SMTP server using conventional SMTP AUTH mechanisms to forward the mail.

## SMTP AUTH

Before we dive into the details of how `esmtpfa` works, we need to understand how SMTP AUTH works. SMTP AUTH is a mechanism for authenticating a client to an SMTP server. It is a fairly simple protocol, and is defined in [RFC 4954](https://tools.ietf.org/html/rfc4954). The basic flow is as follows:

1. The client connects to the server and sends the `EHLO` command.
2. The server responds with a list of supported authentication mechanisms.
3. The client selects an authentication mechanism and sends the `AUTH` command.
4. The server responds with a challenge.
5. The client responds with a response to the challenge.
6. The server responds with a success or failure message.

The client and server can repeat steps 4-6 as many times as necessary to complete the authentication process.

The authentication mechanism is selected by the client, and is not necessarily the same as the mechanism used by the server. For example, the client may select the `PLAIN` mechanism, but the server may use `LOGIN` to authenticate with the upstream server.

The client will send the `AUTH` command with the mechanism name as an argument. The server will respond with a challenge, which is a base64-encoded string. The client will decode the challenge, and respond with a base64-encoded response. The server will decode the response, and respond with a success or failure message.

The base64 encoded string sent by the client to the server is the username and password concatenated together, separated by a null byte. For example:

```bash
echo -ne "\0username\0password" | base64
```

### esmtpfa AUTH

To enable full compatibility with SMTP clients, `esmtpfa` utilizes the same auth flow, but instead of validating the static username / password, the username field is used to select a configured remote authentication provider by name, and the password field is used as the authentication token.

See below for more details on backwards compatibility with "normal" SMTP AUTH format username / password.

## Auth Providers

`esmtpfa` implements a generic interface which allows for multiple authentication providers to be implemented. Providers can be configured in a local yaml or json configuration file, or can be loaded from a remote service over a JSON REST API. Providers are configured with a unique name, type, and a set of param values. The name is used to select the provider when the client sends the `AUTH` command. The type is used to select the provider implementation. The param values are specific to the provider type.

The following providers are currently implemented:

* [http_basic](#http_basic)
* [http_header](#http_header)
* [jwt](#jwt)
* [ldap](#ldap)
* [userpass](#userpass)

### Provider Selection

When a client opens a SMTP connection, `esmtpfa` will authenticate the client using the configured providers before allowing the client to send mail through the relay. esmtpfa uses the server hostname and username provided by the client to select the appropriate provider. If the provider is not found, the client will be rejected.

By default, esmtpfa will use the username field in the AUTH request to select the provider by name, and the password provided will be sent to the corresponding IdP as the token value. For auth providers which require both a username and a token, the username and token are concatenated together, separated by a colon (`:`), and passed in the password field.

To enable a "more conventional" SMTP auth flow for providers which require both a username and a token, you can use a unique domain name to enable the client to specify the desired provider, and the username and password/token will be passed as-is to the provider.

The following optional fields are evaluated for all provider configurations:

* `domain` - The domain name of the provider. If provided, the provider will only be selected if the client connects to the relay using the specified domain name.

* `fallback` - If `true`, the provider will be added to the pool of fallback providers which will be evaluated if no other providers are found.

* `unique_domain_auth` - If `true`, the provider will be selected if the client connects to the relay using the specified unique domain name, and the username and password/token will be passed as-is to the provider, as opposed to the username containing the provider name and the password containing the username/password concatenated with a colon (`:`).

If you have configured your provider with a unique `domain` (eg `my-ldap-provider.example.com`), you can set `unique_domain_auth` to `true` in the provider config. This will use the `domain` mapping to select the provider rather than the `username` field, and the username and password/token will be passed as-is to the provider. For example:

```bash
# create a normal SMTP user/pass with our ldap credentials
echo -ne "\0username\0password" | base64
# telnet to the relay at the unique ldap domain
telnet my-ldap-provider.example.com 25
# then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

The above is the same as:

```bash
# create LDAP user/pass with our ldap credentials
echo -ne "\0my-ldap-provider\0username:password" | base64
# telnet to the relay at the normal domain
telnet generic-esmtpfa.example.com 25
# then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

#### Fallback Providers

If a provider is configured with `fallback: true`, the provider will be added to the pool of fallback providers which will be evaluated if no other providers are found. This is useful for providers which are not specific to a domain, but are used as a "catch-all" for users who do not have a domain-specific provider.

When a client auths to the relay, if a provider is not found for their request using either unique domain matching or username field selection, the fallback providers will be evaluated sequentially until a provider with valid auth is found. If no fallback providers are found, the client will be rejected. Since this evaluates the client's auth against each fallback provider sequentially, it is recommended to use fallback providers sparingly and only if absolutely necessary, and to continue monitoring metrics to ensure that they can be removed as clients are updated to more specific providers.

As the username is not used to select the provider, fallback providers will receive the username and password/token as-is.

For example, if you have `jwt`, `ldap`, and `userpass` providers configured, and you have `userpass` configured as a fallback provider, the following auth flows will be evaluated successfully:

```bash
# create a JWT with configured IdP
echo -ne "\0jwt-provider\0<jwt>" | base64
# telnet to the relay at the normal domain
telnet generic-esmtpfa.example.com 25
# then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

```bash
# create a ldap user/pass with our ldap credentials
echo -ne "\0ldap-provider\0username:password" | base64
# telnet to the relay at the normal domain
telnet generic-esmtpfa.example.com 25
# then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

```bash
# create a userpass SMTP user/pass with our credentials
echo -ne "\0userpass-provider\0username:password" | base64
# telnet to the relay at the normal domain
telnet generic-esmtpfa.example.com 25
# then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

```bash
# create a normal SMTP user/pass with our credentials
echo -ne "\0username\0password" | base64
# telnet to the relay at the normal domain
telnet generic-esmtpfa.example.com 25
# then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

## Providers

Providers are configured with a JSON or YAML file, provided as an array of `provider` objects. A `provider` object is defined as follows:

```yaml
# provider-wide meta config
meta:
    name: <string> # required
    type: <string> # required
    domain: <string> # optional
    fallback: <bool> # optional
    unique_domain_auth: <bool> # optional
# provider-specific config
params:
    exampleParam: <string>
    anotherParam: <int>
```

### http_basic

The `http_basic` provider is a generic HTTP Basic Auth provider which will validate the provided username and password against a remote HTTP endpoint which must reply with a configured success status code. If no status code is configured, the provider will accept 200. If no method is configured, the provider will use `GET`.

```yaml
meta:
    name: my-http-basic-provider
    type: http_basic
    domain: "" # optional
    unique_domain_auth: false # optional
params:
    url: https://example.com/auth
    method: GET # optional
    success_codes: [200, 301] # optional
```

The client will send the following request:

```bash
echo -ne "\0my-http-basic-provider\0username:password" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

### http_header

The `http_header` provider is a generic HTTP Header provider which will validate the provided password value against a remote HTTP endpoint which must reply with a configured success status code. If no status code is configured, the provider will accept 200. If no method is configured, the provider will use `GET`.

```yaml
meta:
    name: my-http-header-provider
    type: http_header
    domain: "" # optional
    unique_domain_auth: false # optional
params:
    url: https://example.com/auth
    header: X-Bearer-Token
    method: GET # optional
    success_codes: [200, 301] # optional
```

The client will send the following request:

```bash
echo -ne "\0my-http-header-provider\0Bearer my-token-here" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

### jwt

The `jwt` provider is a generic JWT/OIDC provider which will validate the provided JWT against a remote OIDC provider. The JWT must be signed with a key which is trusted by the OIDC provider (i.e. the OIDC provider must be configured with the public key presented in a public / network-available JWKS).

In addition to validating the JWT is valid and from the specified IdP, the provider can also validate the JWT claims. The following claims are supported:

- `iss` - Issuer
- `aud` - Audience
- `sub` - Subject
- `exp` - Expiration

Additionally, any custom claims can be validated against a `map[string]any` value. If not provided, the claim will be ignored. If provided, the claim must be present in the JWT, and the value must _match_ (not simply _contain_) the provided value.

```yaml
meta:
    name: my-jwt-provider
    type: jwt
    domain: "" # optional
    unique_domain_auth: false # optional
    fallback: false # optional
params:
    jwks_url: "https://www.googleapis.com/oauth2/v3/certs"
    iss: "https://accounts.google.com"
    sub: "110169484474386276334"
    aud: "my-project-id"
    claims:
      foo: ["bar"]
      another: claim-value
```

Before sending an email through the relay, the client must first obtain a JWT from the OIDC provider. 

The client will then send the following `AUTH` command:

```bash
echo -ne "\0my-jwt-provider\0eyLongJWTBase64.String.Here" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

### ldap

The `ldap` provider is a generic LDAP provider which will validate the provided username and password against a remote LDAP server. The username and password are validated using the specified username filter string.

```yaml
meta:
    name: my-ldap-provider
    type: ldap
    domain: "" # optional
    unique_domain_auth: false # optional
    fallback: false # optional
params:
    server: "ldap.example.com"
    port: 636
    enable_tls: true
    tls_ca: "/etc/ssl/certs/ca-certificates.crt"
    tls_cert: "/etc/ssl/certs/client.crt"
    tls_key: "/etc/ssl/certs/client.key"
    tls_insecure_skip_verify: false
    bind_user: "${LDAP_BIND_USER}"
    bind_pass: "${LDAP_BIND_PASS}"
    base_dn: "ou=users,dc=example,dc=com"
    filter_string: "(&(objectClass=person)(uid=%s))"
    attributes: ["dn"]
```

Before sending an email through the relay, the client must first be authenticated against the LDAP server.

The client will then send the following `AUTH` command:

```bash
echo -ne "\0my-ldap-provider\0username:password" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

The `ldap` provider will also support fallback to traditional SMTP AUTH, where the username and password are sent concatenated with a null byte in between. This is the default behavior of most SMTP clients, and is supported by the `ldap` provider. See [Provider Selection](#provider-selection) for more information.

```bash
# encode the username and password
echo -ne "\0username\0password" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

### userpass

The `userpass` provider is a simple username/password provider, and is "conventional SMTP AUTH".

If a domain is provided, it will be validated against the server provided in the `EHLO` command. If no domain is provided, any domain will be accepted.

Values for the `username` and `password` fields can either be provided as string-literal values, or prefixed with `${` and suffixed with `}` to indicate that the value should be read from the environment. This is the recommended way to provide sensitive information, such as passwords, and enables decoupling of the configuration into a separate driver such as HashiCorp Vault to enable dynamic secrets.

```yaml
meta:
    name: my-userpass-provider
    type: userpass
    domain: "" # optional
    unique_domain_auth: false # optional
    fallback: false # optional
params:
    username: "${MY_USERNAME}"
    password: "${MY_PASSWORD}"
```

To send the username and password to the provider, the client would send the following `AUTH` command:

```bash
# encode the username and password
echo -ne "\0my-userpass-provider\0username:password" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

The `userpass` provider will also support fallback to traditional SMTP AUTH, where the username and password are sent concatenated with a null byte in between. This is the default behavior of most SMTP clients, and is supported by the `userpass` provider.

```bash
# encode the username and password
echo -ne "\0username\0password" | base64
# telnet to the relay, then when prompted ...
AUTH PLAIN <base64-encoded-string>
```

## Provider Configuration

Providers can be configured in a local yaml or json configuration file, or can be loaded from a remote service over a JSON REST API. The configuration file or remote service must return an array of providers. The following is an example of a configuration file:

```yaml
providers:
- meta:
    name: my-jwt-provider
    type: jwt
    domain: "" # optional
    unique_domain_auth: false # optional
    fallback: false # optional
  params:
    jwks_url: "https://www.googleapis.com/oauth2/v3/certs"
    iss: "https://accounts.google.com"
    sub: "110169484474386276334"
    aud: "my-project-id"
    claims:
      foo: ["bar"]
      another: claim-value
- meta:
    name: my-userpass-provider
    type: userpass
    domain: "example.com" # optional
    unique_domain_auth: true # optional
    fallback: false # optional
  params:
    username: "${MY_USERNAME}"
    password: "${MY_PASSWORD}"
```

```json
{
    "providers": [
        {
            "meta": {
                "name": "my-jwt-provider",
                "type": "jwt",
                "domain": "",
                "unique_domain_auth": false,
                "fallback": false
            },
            "params": {
                "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
                "iss": "https://accounts.google.com",
                "sub": "110169484474",
                "aud": "my-project-id",
                "claims": {
                    "foo": ["bar"],
                    "another": "claim-value"
                }
            }
        },
        {
            "meta": {
                "name": "my-userpass-provider",
                "type": "userpass",
                "domain": "example.com",
                "unique_domain_auth": true,
                "fallback": false
            },
            "params": {
                "username": "${MY_USERNAME}",
                "password": "${MY_PASSWORD}"
            }
        }
    ]
}
```

## esmtpfa Configuration

`esmtpfa` can be configured with command line flags or environment variables.

### Command Line Flags

```bash
Usage of esmtpfa:
  -addr string
    	SMTP server address
  -allow-anonymous-auth
    	Allow anonymous authentication
  -allow-insecure-auth
    	Allow insecure authentication
  -config string
    	Configuration file (default "config.yaml")
  -config-svc string
    	Configuration service
  -enable-binary-mime
    	Enable BINARYMIME
  -enable-require-tls
    	Enable REQUIRETLS
  -enable-smtp-utf8
    	Enable SMTPUTF8
  -http
    	Enable HTTP server
  -http-allow-anonymous
    	Allow anonymous access to HTTP server
  -http-port int
    	HTTP server port (default 8080)
  -http-tls-cert string
    	TLS certificate for HTTP server
  -http-tls-key string
    	TLS key for HTTP server
  -log-level string
    	Log level (default "info")
  -metrics-namespace string
    	Metrics namespace (default "esmtpfa")
  -metrics-port int
    	Metrics port (default 9090)
  -plain
    	Enable plain-text server
  -port int
    	SMTP server port (default 25)
  -relay-addr string
    	Relay server address
  -relay-from string
    	Relay server from. If set, the client-provided value will be set to reply-to header
  -relay-pass string
    	Relay server password
  -relay-port int
    	Relay server port (default 25)
  -relay-tls
    	Enable TLS for Relay
  -relay-tls-ca-cert string
    	TLS CA certificate for Relay
  -relay-tls-cert string
    	TLS certificate for Relay
  -relay-tls-key string
    	TLS key for Relay
  -relay-tls-skip-verify
    	Skip TLS verification for Relay
  -relay-user string
    	Relay server user
  -tls
    	Enable TLS server
  -tls-ca-cert string
    	TLS CA certificate
  -tls-cert string
    	TLS certificate
  -tls-key string
    	TLS key
  -tls-port int
    	TLS port (default 465)
```

### Environment Variables

```bash
HTTP_ALLOW_ANONYMOUS
HTTP_ENABLE
HTTP_PORT
HTTP_TLS_CERT
HTTP_TLS_KEY
LOG_LEVEL
METRICS_NAMESPACE
METRICS_PORT
PROVIDER_CONFIG
PROVIDER_CONFIG_SERVICE
RELAY_ADDR
RELAY_FROM
RELAY_PASS
RELAY_PORT
RELAY_TLS_CA_CERT
RELAY_TLS_CERT
RELAY_TLS_ENABLE
RELAY_TLS_KEY
RELAY_TLS_SKIP_VERIFY
RELAY_USER
SMTP_ADDR
SMTP_ALLOW_ANONYMOUS_AUTH
SMTP_ALLOW_INSECURE_AUTH
SMTP_ENABLE_BINARY_MIME
SMTP_ENABLE_REQUIRE_TLS
SMTP_ENABLE_SMTP_UTF8
SMTP_PLAIN_ENABLE
SMTP_PORT
SMTP_TLS_CA_CERT
SMTP_TLS_CERT
SMTP_TLS_ENABLE
SMTP_TLS_KEY
SMTP_TLS_PORT
```

Environment variables will override command line flags if defined.

## Listener Configuration

By default, no listeners will be started. You must explicitly enable the listeners you want to use with the `-plain` and / or `-tls` flags, or the `SMTP_PLAIN_ENABLE` and / or `SMTP_TLS_ENABLE` environment variables.

### SMTP TLS Listener

The TLS Listener will default to port 465. You can change this with the `-tls-port` flag or the `SMTP_TLS_PORT` environment variable. You must provide a TLS certificate and key with the `-tls-cert` and `-tls-key` flags or the `SMTP_TLS_CERT` and `SMTP_TLS_KEY` environment variables. You can optionally provide a CA certificate with the `-tls-ca-cert` flag or the `SMTP_TLS_CA_CERT` environment variable.

#### Example

```bash
esmtpfa -tls \
    -tls-cert /path/to/cert.pem \
    -tls-key /path/to/key.pem \
    -relay-smtp-addr smtp.example.com \
    -relay-smtp-from user@example.com \
    -relay-smtp-user user@example.com \
    -relay-smtp-pass pass \
    -relay-smtp-tls \
    -relay-smtp-port 465 \
    -tls-port 4465 &

openssl s_client -starttls smtp -crlf -connect localhost:4465
EHLO example.com
...
```

### SMTP Plain Listener

The Plain Listener will default to port 25. You can change this with the `-port` flag or the `SMTP_PORT` environment variable. If the plain listener is enabled, you will also need to enable insecure auth with the `-allow-insecure-auth` flag or the `SMTP_ALLOW_INSECURE_AUTH` environment variable. This is required to acknowledge the fact that the connection is not encrypted and yet the client is sending a credential. This is not recommended for obvious reasons.

#### Example

```bash
esmtpfa \
    -plain \
    -allow-insecure-auth \
    -relay-smtp-addr smtp.example.com \
    -relay-smtp-from user@example.com \
    -relay-smtp-user user@example.com \
    -relay-smtp-pass pass \
    -relay-smtp-tls \
    -relay-smtp-port 465 \
    -port 2225 &

telnet localhost 2225
EHLO example.com
...
```

### HTTP/S Listener

The HTTP/S Listener enables downstream clients to send emails via the `POST /` REST endpoint, passing the following JSON payload:

```json
{
    "from": "<string>",
    "to": ["<string>"],
    "data": "<base64 encoded string>"
}
```

The HTTP/S Listener will default to port 8080. You can change this with the `-http-port` flag or the `HTTP_PORT` environment variable. If no TLS certificate and key are provided, the listener will default to HTTP. You can provide a TLS certificate and key with the `-http-tls-cert` and `-http-tls-key` flags or the `HTTP_TLS_CERT` and `HTTP_TLS_KEY` environment variables. When provided, the listener will be configured to use HTTPS.

To disable authentication for the HTTP/S listener, you can use the `-http-allow-anonymous` flag or the `HTTP_ALLOW_ANONYMOUS` environment variable. If this is not set, the listener will require the client to provide a valid Basic Auth credential.

When provided, the Basic Auth credentials will be validated against the corresponding auth provider, just like the SMTP listener.

#### Example

```bash
esmtpfa \
    -http \
    -relay-addr smtp.example.com \
    -relay-from user@example.com \
    -relay-user user@example.com \
    -relay-pass pass \
    -relay-tls \
    -relay-port 465 \
    -http-port 8080 &

message=$(cat <<EOF
From: foo@bar
To: bar@foo
Subject: Hello World

Hello World!

EOF
)

message_base64=$(echo -n "$message" | base64)

curl -X POST \
    -H "Content-Type: application/json" \
    -u userpass:username:password \
    -d '{"from": "foo@bar", "to": ["bar@foo"], "data": "'"$message_base64"'"}' \
    http://localhost:8080/
```

## ESMTP Options

`esmtpfa` supports the following ESMTP options:

- `BINARYMIME`
- `REQUIRETLS`
- `SMTPUTF8`

These options can be enabled with the `-enable-binary-mime`, `-enable-require-tls`, and `-enable-smtp-utf8` flags or the `SMTP_ENABLE_BINARY_MIME`, `SMTP_ENABLE_REQUIRE_TLS`, and `SMTP_ENABLE_SMTP_UTF8` environment variables. These options will be advertised to the client in the `250-ENHANCEDSTATUSCODES` response. `esmtpfa` does not validate these options, so if you enable them, you must ensure that the upstream server supports them, otherwise a client with support may attempt to use them and the connection will be dropped.

## Metrics

`esmtpfa` exposes a Prometheus metrics endpoint at `/metrics` which can be used to monitor the relay. The following metrics are exposed:

- `esmtpfa_connections_total` - Total number of connections
- `esmtpfa_bytes_sent_total` - Total number of bytes sent
- `esmtpfa_bytes_sent_from_address_total` - Total number of bytes sent from address
- `esmtpfa_bytes_sent_to_address_total` - Total number of bytes sent to address
- `esmtpfa_messages_sent_total` - Total number of messages sent
- `esmtpfa_auth_successes_total` - Total number of successful authentications
- `esmtpfa_auth_failures_total` - Total number of failed authentications
- `esmtpfa_fallback_connections_total` - Total number of fallback connections
- `esmtpfa_configured_providers` - Configured auth providers
- `esmtpfa_mail_from_to` - Mail from/to
- `esmtpfa_smtp_server_request_duration_seconds` - SMTP server request duration

## Reputation Management

As a relay, `esmtpfa` will forward messages from authenticated clients to the upstream SMTP server. If your downstream client is sending spam, you may find that your upstream SMTP server starts rejecting messages. You are responsible for the reputation of the messages sent through your SMTP server, and a client found to be sending spam should be disabled in your auth system until you can resolve the issue.

`esmtpfa` exposes [metrics](#metrics) that can be used to monitor the send profiles of your clients. You can use these metrics to identify clients that are sending spam and disable them in your auth system.

## Placement in Messaging Infrastructure

As an authenticating relay, `esmtpfa` must sit in front of your downstream clients (MUAs) and upstream SMTP server (MTA). `esmtpfa` is a MTA relay itself, but does not handle final delivery (MDA). For this, you should use another MTA such as Postfix or Exim.

Below is an example of a simple messaging infrastructure using `esmtpfa`:

```
Downstream Client (MUA) -> esmtpfa (MTA) -> SMTP Relay (MTA) -> MDA -> Upstream Client (MUA)
```

Since the overhead of managing IP reputation for a true MTA is high, most users will rely on a third-party SMTP relay. This is a common setup for users of services such as SendGrid, Mailgun, or Amazon SES. In this setup, `esmtpfa` will be used to authenticate the downstream client and relay the message to the upstream SMTP relay. The upstream SMTP relay will then handle the final delivery to the upstream client.

## Deployment

`esmtpfa` is a single binary that can be deployed as a standalone application or as a Docker container. This guide will walk through deploying `esmtpfa` in a Kubernetes cluster using the provided manifest files (see the [deploy](deploy) directory).

```bash
# fill in .env file with appropriate values
cp .env-sample .env
# create secret from .env file
kubectl create secret generic esmtpfa --from-env-file=.env
# edit deploy/providers-configmap.yaml to add auth providers
# apply manifests
kubectl apply -f deploy/
```