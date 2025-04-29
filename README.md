# 📡 wired network system™

![Wired Banner](public/website/wired-banner.png)

Wired is a distributed network services platform designed for scalable DNS hosting, HTTP reverse proxying, automatic SSL configurations and much more. It features geolocation-aware DNS routing, live master-node communication and synchronization and an event-driven architecture.

> [!IMPORTANT]
> **Note**: This project is in its early stages and is not yet ready for production use. The following key features are mostly already implemented, but the list serves more as a roadmap for the current development status.
>
> This project is a recode of https://github.com/wirednetworks/WiredShield-Backup, which was being developed for a few months but has grown to be too messy to maintain and extend. The new codebase is being developed from scratch, with a focus on modularity and extensibility.

## Key Features

- **Distributed Architecture**: Master-node system for scalable service deployment
- **DNS Service**:
    - **Geolocation-based DNS Routing**: Direct users to the nearest node for optimal performance
    - **Dynamic DNS**: Automatic updates for changing IP addresses
    - **DNS Caching**: Reduce latency and improve response times
- **HTTP Reverse Proxy**:
    - **Web-Application-Firewall**: Basic protection against common web attacks with a custom rule language
    - **Rate Limiting**: Control traffic to prevent abuse
    - **Caching**: Reduce server load and improve response times
    - **Custom Error Pages**: User-friendly error handling
    - **HTTP/2 Support**: Multiplexing
    - **Automatic SSL Management**: Simplified certificate generation and renewal
- **Modular Design**:
    - **Plugin System**: Extend functionality with custom plugins
    - **Event-Driven Architecture**: Respond to system events and changes
- **Web-based Management Interface**:
    - **DNS Management**: Add, edit, and delete DNS records
    - **HTTP Proxy Management**: Configure reverse proxy settings
    - **Real-time Monitoring**: View system performance and health
    - **Logging and Analytics**: Track DNS queries, HTTP requests, and system events
    - **Configuration Management**: Easy setup and management of services
    - **User Management**: Role-based access control for users and nodes

## Getting Started

### Prerequisites
- Go 1.20 or later
    - `go_install.sh` script included for easy installation, tested on Debian, Arch Linux and macOS Sequoia
- MaxMindDB GeoLite2 database
    - Download from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/)
    - Place the database in `node/geolite2-city-ipvx.mmdb` (both v4 and v6 .mmdb files are required)

### Environment Variables
#### Master
- `MASTER_PORT`: Port for the master node to listen on (default: `2000`)
- `NODE_KEY`: Displayname for the master node (default: `master`)

#### Node
- `GATEWAY`: Address of the master node (default: `localhost`)
- `NODE_KEY`: Displayname for the node (default: `node`)
- `SNOWFLAKE_MACHINE_ID`: Unique identifier for the node (default: `0`)

> `SNOWFLAKE_MACHINE_ID` is subject to change in the future. Unique identifiers will be assigned through an internally handled node id in an upcoming update.
> 
> `NODE_KEY` for node should ideally be set to the hostname of the node. For example `fr01.de.as214428.net`.

### Building
1. Clone the repository:
   ```bash
    git clone https://github.com/Northernside/WiredShield
    cd WiredShield
    ```
2. Build the project:
    ```bash
    go build -o node ./node/node.go
    go build -o master ./master/master.go
    ```

> [!NOTE]
> A systemd installation script will be added in an upcoming update.