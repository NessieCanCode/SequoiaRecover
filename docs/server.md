# Local Backup Server

SequoiaRecover includes an optional HTTP server for storing backups on your own infrastructure. This server accepts uploads from the CLI and can list or download stored archives.

## Running the server

Use the `serve` subcommand to start the server:

```bash
sequoiarecover serve --address 0.0.0.0:3030 --dir /path/to/storage
```

- `--address` sets the IP and port to listen on.
- `--dir` is the directory where uploaded backups are saved.

## Uploading to the server

Pass `--cloud server` and the `--server_url` option when running the `backup` command:

```bash
sequoiarecover backup --source /data \
    --bucket my-bucket \
    --cloud server \
    --server_url http://localhost:3030
```

The `schedule`, `list`, and `restore` commands also support `--cloud server` with `--server_url`.

The graphical interface exposes the same functionality. Select **Server** as the
destination in the Backup tab and enter the bucket and server URL to upload
archives from the GUI.

## Listing stored backups

```bash
sequoiarecover history --cloud server --server_url http://localhost:3030 --bucket my-bucket
```

## Restoring from the server

```bash
sequoiarecover restore --cloud server \
    --server_url http://localhost:3030 \
    --bucket my-bucket \
    --backup backup.tar \
    --destination /restore/path
```
