# certbot-dns-ngenix

[NGENIX](https://ngenix.net) DNS Authenticator plugin for [Certbot](https://certbot.eff.org)

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using [NGENIX Platform API](https://developer.ngenix.net/platformApi).
Plugin checks for DNS propagation every 60 seconds during 15 minutes.

## Configuration of NGENIX

In the `Settings -> My profile` you have to have a user, with the following permissions:

* Service management

## Installation
```
mkdir certbot-dns-ngenix
curl -L "https://github.com/cheopslab/certbot-dns-ngenix/archive/master.tar.gz" | tar -xz -C certbot-dns-ngenix --strip-components=1 
pip install ./certbot-dns-ngenix
```

## Named Arguments

To start using DNS authentication for NGENIX, pass the following arguments on
certbot's command line:

| Name | Usage |
| --- | --- |
| `--authenticator dns-ngenix` | Select the authenticator plugin (required) |
| `--dns-ngenix-customer-id 12345` | NGENIX customer ID (required) |
| `--dns-ngenix-name username` | NGENIX username (required) |
| `--dns-ngenix-token token` | NGENIX token (required) |

## Examples

To acquire a single certificate for both `example.com` and
`*.example.com`:

``` bash
certbot certonly \
  --authenticator dns-ngenix \
  --dns-ngenix-customer-id 12345 \
  --dns-ngenix-name username \
  --dns-ngenix-token token \
  --preferred-challenges=dns \
  --agree-tos \
  --register-unsafely-without-email \
  -d 'example.com' \
  -d '*.example.com'
```

## Docker

In order to create a docker container with a certbot-dns-ngenix installation, create an empty directory with the following Dockerfile:

```
FROM certbot/certbot
COPY certbot-dns-ngenix /certbot-dns-ngenix
RUN pip install /certbot-dns-ngenix
```

Proceed to build the image:

```
docker build -t certbot/dns-ngenix .
```

Once that's finished, the application can be run as follows:

```
docker run --rm \
   -v /var/lib/letsencrypt:/var/lib/letsencrypt \
   -v /etc/letsencrypt:/etc/letsencrypt \
   --cap-drop=all \
   certbot/dns-ngenix certonly \
      --authenticator dns-ngenix \
      --dns-ngenix-customer-id 12345 \
      --dns-ngenix-name username \
      --dns-ngenix-token token \
      --preferred-challenges=dns \
      --agree-tos \
      --register-unsafely-without-email \
      -d 'example.com' \
      -d '*.example.com'
```
