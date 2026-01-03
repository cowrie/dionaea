# Quick reference

- **Maintained by**:
  [dionaea Community](https://github.com/cowrie/dionaea/)

- **Where to get help**:
  [dionaea GitHub issues](https://github.com/cowrie/dionaea/issues)

# Tags

- nightly - Build every night from the default branch
- edge - Build when pushed to default branch
- x.y.z - Specific version (Example: 0.9.2)
- latest - The latest specific version

# What is dionaea?

dionaea is a low interaction honeypot.
The code from the [official dionaea repository](https://github.com/cowrie/dionaea) is used to build the service during the image build process.

# How to use this image

## Quick start (no persistence)

```console
docker run --rm -it \
  -p 21:21 -p 80:80 -p 443:443 -p 445:445 -p 1433:1433 -p 3306:3306 \
  cowrie/dionaea
```

This runs dionaea with default settings. Data is lost when the container stops.

## With persistent storage (recommended)

There are two ways to persist data: **named volumes** (simpler) or **bind mounts** (more control).

### Option 1: Named volumes (recommended)

Named volumes are managed by Docker and automatically initialized with default config on first run.

```console
docker run -d --name dionaea \
  -v dionaea-config:/opt/dionaea/etc \
  -v dionaea-data:/opt/dionaea/var/lib \
  -v dionaea-logs:/opt/dionaea/var/log \
  -p 21:21 -p 80:80 -p 443:443 -p 445:445 -p 1433:1433 -p 3306:3306 \
  cowrie/dionaea
```

To edit config files:
```console
docker exec -it dionaea vi /opt/dionaea/etc/dionaea/dionaea.cfg
docker restart dionaea
```

To reset to defaults, remove the volume:
```console
docker rm dionaea
docker volume rm dionaea-config
```

### Option 2: Bind mounts (host directories)

Bind mounts give you direct access to files on the host, but require initialization on first run.

```console
# Create directories
mkdir -p ./dionaea/{etc,var/lib,var/log}

# First run: initialize with defaults
docker run --rm \
  -v ./dionaea/etc:/opt/dionaea/etc \
  -v ./dionaea/var/lib:/opt/dionaea/var/lib \
  -v ./dionaea/var/log:/opt/dionaea/var/log \
  -e DIONAEA_FORCE_INIT=1 \
  cowrie/dionaea --help

# Now run normally
docker run -d --name dionaea \
  -v ./dionaea/etc:/opt/dionaea/etc \
  -v ./dionaea/var/lib:/opt/dionaea/var/lib \
  -v ./dionaea/var/log:/opt/dionaea/var/log \
  -p 21:21 -p 80:80 -p 443:443 -p 445:445 -p 1433:1433 -p 3306:3306 \
  cowrie/dionaea
```

You can now edit `./dionaea/etc/dionaea/dionaea.cfg` directly on the host.

## Docker Compose

```yaml
services:
  dionaea:
    image: cowrie/dionaea
    restart: always
    ports:
      - "21:21"
      - "80:80"
      - "443:443"
      - "445:445"
      - "1433:1433"
      - "3306:3306"
    volumes:
      - dionaea-config:/opt/dionaea/etc
      - dionaea-data:/opt/dionaea/var/lib
      - dionaea-logs:/opt/dionaea/var/log

volumes:
  dionaea-config:
  dionaea-data:
  dionaea-logs:
```

# Volume initialization

The image stores default config/data in `/opt/dionaea/template/`. The entrypoint script copies these to the actual locations if they don't exist.

**Why this is needed:** Docker only auto-populates named volumes, not bind mounts. The entrypoint script ensures both work correctly.

| Storage type | First run behavior |
|--------------|-------------------|
| Named volume | Docker auto-populates from image |
| Bind mount   | Entrypoint copies from template/ |
| No volume    | Uses image defaults directly |

## Environment variables

### `DIONAEA_FORCE_INIT`

Force copy default files even if directories exist. Useful for:
- Initializing empty bind mounts
- Resetting to defaults after config changes

Only missing files are copied (won't overwrite your modifications).

### `DIONAEA_SKIP_INIT`

Skip all initialization. Use when you've manually prepared the config directories.

# Building a custom image

```dockerfile
FROM cowrie/dionaea:latest
COPY my-service.yaml /opt/dionaea/etc/dionaea/services-enabled/
COPY my-ihandler.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled/
```

```console
docker build -t my-dionaea .
```

# User Feedback

## Issues

If you have any problems with or questions about this image, please create a [GitHub issue](https://github.com/cowrie/dionaea/issues).

## Contributing

You are invited to contribute new features, fixes or updates.
We recommend discussing your ideas through a [GitHub issue](https://github.com/cowrie/dionaea/issues), before you start.
