# WiredShield

> [!WARNING]
> This project is currently under constant development. Code, structures and functionality **will** break every few days.
> It is mostly work-in-progress and consists of proof-of-concept code.

## What does it do?
WiredShield is planned to cover a lot of infrastructure management features, such as:
- [80%] DNS Management (+ DNS-based geolocation-routing, because IPv4 transit for AS214428 (my own network) will cost me all of my organs)
- [70%] Web Reverse Proxy + AutoSSL
- [05%] Web-Application-Firewall
- [00%] Layer 3/4 Firewall with eBPF/XDP in C
- [50%] Minecraft Reverse Proxy (utilizing [Northernside/wiredproxy](https://github.com/Northernside/wiredproxy)) -> pre-packed with tons of features and optimizations
- [00%] General TCP Reverse Proxy + Firewall

> NOTE: [XX%] declares the current progress for each feature-set (progress isn't being updated regularly).

## How does it work?
No clue yet! Design & structure changes every few commits. Though, it is generally inspired by Cloudflare patterns & their product suite.

## How can I use it?
Documentations will appear shortly after I deem WiredShield as production-ready. Besides self-hosting, I'll try to offer free & managed services for WiredShield under AS214428.net and the respective internet presence of said network / project - just like Cloudflare. Don't expect high limits and great network capacity. Enjoy it as a kind of playground or fun thing!
