# Installation

>[!TIP]
> Existing `cync_mesh.yaml`? simply use the config as it is: bind mount into the docker container.

## Docker
This project is bundled as a docker image, you can build it locally.

### Build
- Clone the repo 
- `cd` into the repo directory
- `docker compose -f ./docker/Dockerfile build` will output a `baudneo/cync-lan:latest` tagged image
- Copy the example `docker-compose.yaml` file and edit it for your setup.
- Set up env vars using the docker-compose `environment` section or uncomment the `env_file` option and create an .env file (See [example](../docker/example.env))

#### Upgrading
- Rebuild the image (use no-cache for a clean build): `docker compose -f ./docker/Dockerfile build --no-cache`