# goauthproxy

Simple reverse proxy that supports client certificate verification and dynamic URLs

## Building

To build the binary with version and build time information:

```bash
BUILDTIME=$(date -u '+%Y-%m-%d_%H:%M:%S') BUILDVERSION="$(git describe --tags)" && go build -race -ldflags "-X main.buildtime=$BUILDTIME -X main.buildversion=${BUILDVERSION}" && ./goauthproxy -version
```

## Refreshing Go Modules

To refresh and update all Go modules:

```bash
rm go.??? ; rm -rf vendor ; go mod init ; go get -u && go mod tidy && go mod vendor ; echo GOREFRESH
```

## Configuration

```
---
listen_address: 127.0.0.1
listen_port: 8443
ssl_private_key: ssl/key.pem
ssl_certificate_file: ssl/cert.pem
ssl_require_and_verify_client_cert: true
ssl_client_cert_ca_file: ssl/ca.pem

#requests_trusted_root_cas:
#  - 'ssl/rootca.pem'

endpoints:
  '/foo':
    url: 'https://jsonplaceholder.typicode.com/posts'
    headers:
      'Content-Type': 'application/json; charset=UTF-8'
    http_type: 'POST'
    post_data: |
      {"title": "foo", "body": "bar", "userId": 1}
  '/bar':
    url: 'https://jsonplaceholder.typicode.com/posts/1'
    http_type: 'GET'
    headers:
      'Content-Type': 'application/json'
  '/protected':
    allowed_cns:
      - 'CN=COMMON_NAME'
    url: 'https://jsonplaceholder.typicode.com/posts'
    headers:
      'Content-Type': 'application/json; charset=UTF-8'
    http_type: 'POST'
    post_data: |
      {"title": "foo", "body": "bar", "userId": 1}
  '/dynamic_url': # let's you call /dynamic_url/1 which internally requests https://jsonplaceholder.typicode.com/posts/1
    url_dynamic: true
    url: 'https://jsonplaceholder.typicode.com/posts/{{.Arg1}}'
    argument_regexes:
      1: '^\d+$'
	'/passthrough':
    url: 'https://jsonplaceholder.typicode.com/posts'
    pass_through: true
  '/passthrough_with_proxy':
    url: 'https://jsonplaceholder.typicode.com/posts'
    pass_through: true
    proxy: http://yourproxy:8080
  '/passthrough_with_dynamic_url':
    url_dynamic: true
    url: 'https://jsonplaceholder.typicode.com/posts/{{.Arg1}}'
    pass_through: true
    argument_regexes:
      1: '^\d+$'
```

#### example for dynamic URLs

Calling
`/passthrough_with_dynamic_url/3`
would then pass through the request body to `https://jsonplaceholder.typicode.com/posts/3`
