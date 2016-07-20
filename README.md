# SentryUDPToHTTP #
SentryUDPToHTTP is a simple service that works to route legacy UDP packets to
HTTP requests to support old clients of Sentry with our newer installation.

## Getting Started ##
We use the [GB tool](https://getgb.io/) in order to support future vendoring if needed.
```
git clone <this repo> SentryUDPToHTTP
cd SentryUDPToHTTP
gb build
```
Your output binary will be in ``` ./bin/SentryToHTTP ```
This can then be executed and will run - it works best with a process manager
such as systemd or supervisord.

## Using SentryUDPToHTTP ##
The package is quite simple - incoming UDP packets on port 9002 are deciphered,
turned into a modern HTTP style response and relayed to the sentry installation
running on port 80.
It will log errors to stderr.

## Issues ##
 * Add config support

## Contributors ##
nglynn@freelancer.com