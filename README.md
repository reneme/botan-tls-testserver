# Botan Hybrid TLS Test Server

This simple web app can be used to test your client against Botan's TLS
implementation. The server itself is using Boost asio for TCP, [Botan's asio
stream](https://botan.randombit.net/handbook/api_ref/tls.html#tls-stream) for
TLS and Boost beast for HTTP.

The app displays a web page inspired by [Cloudflare's post-quantum TLS test
page](https://pq.cloudflareresearch.com), that visualizes what key exchange
algorithm was used to establish the TLS connection from the user's browser and
the test server.

## Online Test

A running version of the app is deployed here:
[https://pq.botan-crypto.org](https://pq.botan-crypto.org).

## Build

At the moment, you'll need the latest (i.e. unreleased) revision of Botan.
Therefore, this repository contains it as a submodule. As soon as Botan 3.3.0 is
released (expected in January 2024), we'll remove the submodule and will rely on
Conan for the dependencies.

Additionally, a fairly recent version of Boost is required. The steps below
assume that it is available on your system.

```bash
git submodule init
git submodule update

(cd 3rdparty/botan; ./configure.py --with-boost --without-documentation --disable-shared-library)
(cd 3rdparty/botan; make -j8 libs cli)

cmake -B build -S .
make -C build
```

## Run

You'll need a certificate for your test server. If you don't have one, you can
create a basic certificate with Botan's CLI tool. After building Botan as
described above, from the repository's root run:

```bash
mkdir certs

3rdparty/botan/botan keygen --algo=ECDSA --params=secp384r1 --output=certs/ca.key
3rdparty/botan/botan keygen --algo=ECDSA --params=secp384r1 --output=certs/server.key
3rdparty/botan/botan gen_self_signed --ca --country=DE --dns=localhost --hash=SHA-384 --output=certs/ca.pem certs/ca.key localhost
3rdparty/botan/botan gen_pkcs10 --output=certs/server.req certs/server.key localhost
3rdparty/botan/botan sign_cert --output=certs/server.pem certs/ca.pem certs/ca.key certs/server.req
```

Now, it's time to start the server application:

```bash
build/testserver --cert certs/server.pem --key certs/server.key --port 50443 --policy policies/pqc_basic.txt
```

Using the browser of you choice, visit: [https://localhost:50443](https://localhost:50443) to see it in action.