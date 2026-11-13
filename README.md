# NetGraph — Check Point Firewall Log Visualizer

A Django + D3.js tool for visualizing Check Point firewall logs as an interactive force-directed graph. Supports CSV upload and live log pull via the Check Point Management API.

## Features

- **Interactive graph** — force-directed layout with a hierarchical tree option
- **CSV upload** — drag-and-drop or file picker; auto-detects source/destination IP columns
- **Check Point Management API** — connect via API key, pull logs in paginated chunks (100 per request), stitch into a single graph
- **Node panel** — click any node to see IP, type, stats, inbound/outbound connections, country (GeoIP), domain names, NSLookup, and copy-to-clipboard
- **Log viewer modal** — sortable columns, aggregate deduplication (src IP + dst IP + dst port), aggregate count column
- **Zoom controls** — 25 / 50 / 100% presets and fit-to-screen
- **Node filtering** — filter by internal, external, or loopback type
- **Drag and pin** — drag nodes to reposition; they stay pinned where dropped

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Django 5, pandas |
| Frontend | Vanilla JS, D3.js v7 |
| Container | Docker (single container, whitenoise static files) |

## Quick Start

```bash
docker compose up -d --build
```

App is available at `http://localhost:8090`.

## Check Point API Setup

1. Open the **Pull via API** modal in the top toolbar
2. Enter your Management Server hostname/IP and API key
3. Click **Connect** — a session is established with SSL verification bypassed (supports self-signed certs)
4. Choose a time frame and log count, then click **Pull Logs**
5. Logs are fetched in 100-record pages and stitched together automatically

## SSH Config (for pushing from this machine)

The deploy key is at `~/.ssh/netgraph_deploy_key`. Add to `~/.ssh/config`:

```
Host github.com
  IdentityFile ~/.ssh/netgraph_deploy_key
```
