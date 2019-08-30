# goauthproxy

Simple reverse proxy that supports client certificate verification.


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
```
