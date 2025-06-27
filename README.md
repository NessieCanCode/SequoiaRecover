# SequoiaRecover

**SequoiaRecover** is a free, cross-platform backup tool designed for Windows, macOS, and Linux that securely backs up your data to cloud storage services like Backblaze, AWS S3 and Azure Blob Storage. Built with performance and safety in mind using **Rust**, SequoiaRecover aims to provide reliable disaster recovery and business continuity solutions for individuals and organizations alike.

---

## Features


- Cross-platform support: Windows, macOS, and Linux
- Incremental and full backups
- Plugin-based storage providers via `providers.json`
- Secure, zero-knowledge encryption with hardware key support
- Resumable uploads with deduplication
- Network throttling and multi-threaded compression
- Automated backup scheduling
- Easy CLI with `init`, `keygen`, and `keyrotate`
- Management server and modern GUI
- Ransomware detection with optional upload refusal
- Focus on disaster recovery and business continuity
- View past backup history and inspect archives
- Restore files from any provider
- Compliance reports with PDF/HTML summaries
---

## Getting Started

### Prerequisites

- Rust toolchain installed (via [rustup](https://rustup.rs/))
- Access to a cloud storage account (Backblaze B2, AWS S3 or Azure Blob)

### Installation

Clone the repository:

```bash
git clone https://github.com/YourUsername/SequoiaRecover.git
cd SequoiaRecover
```
Build the project:
```bash
cargo build --release
# Add hardware key support
# cargo build --release --features hardware-auth
```

Run the backup tool:
```bash
./target/release/sequoiarecover --help
```

### Usage
Example command to perform a backup replicated to Backblaze and AWS:
```bash
sequoiarecover backup --source /path/to/data --cloud backblaze,aws --bucket my-bucket --mode full
```
The `--mode` flag controls whether a **full** or **incremental** backup is performed.
Add `--keyring` to read Backblaze credentials from your keychain if you used `sequoiarecover init --keyring`.
Incremental mode only archives files that have changed since the previous backup.
You can control compression with `--compression`. Passing `auto` lets
SequoiaRecover choose a compression method based on your network speed (measured
over about 5 seconds) to help reduce transfer costs. Use `--compression-threshold`
to provide a link speed in Mbps and override the automatic detection when needed.
Add `--reject-suspicious` to refuse uploading a backup if ransomware patterns are detected.
Use `--max-upload-mbps` or `--max-download-mbps` to limit how much bandwidth the tool
consumes when transferring data.
To run automated backups every hour:
```bash
sequoiarecover schedule --source /path/to/data --bucket my-bucket --interval 3600 --mode incremental
```
Include `--keyring` when scheduling if credentials are stored in your keychain.
Show previous backups stored in Backblaze (use `--cloud aws` or `--cloud azure` for other providers):
```bash
sequoiarecover history --bucket my-bucket
```
List the contents of a backup archive from Backblaze without downloading:
```bash
sequoiarecover list --backup backup.tar --bucket my-bucket
```
Restore a backup automatically from any provider:
```bash
sequoiarecover restore --backup backup.tar --bucket my-bucket --cloud auto --destination /restore/path
```
Verify that all providers have a given archive:
```bash
sequoiarecover verify --backup backup.tar --bucket my-bucket
```
Check available commands and options:
```bash
sequoiarecover --help
```

### Generate a man page

You can create a manual page to ship with precompiled binaries:

```bash
sequoiarecover manpage > sequoiarecover.1
```

Install `sequoiarecover.1` under your system's `man1` directory so users can run
`man sequoiarecover` for full documentation.

### CLI Usage

You can build and run the command-line application on any supported platform using Cargo:

```bash
cargo run -- backup --source /path/to/data --bucket my-bucket
```

### Backblaze Authentication

Run one of the following commands once to store your Backblaze credentials:

```bash
# Save credentials in an encrypted file (default)
sequoiarecover init

# Save credentials in your OS keychain
sequoiarecover init --keyring
```

You'll be prompted for the account ID and application key. When using the `--keyring` flag no password is required. Subsequent `backup` and `schedule` commands can retrieve the credentials by passing `--keyring` or by decrypting the config file if `--keyring` was not used.

### AWS and Azure Authentication

AWS and Azure credentials are read from the environment. Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_REGION` when using `--cloud aws`. For Azure Blob Storage set `AZURE_STORAGE_ACCOUNT` and `AZURE_STORAGE_KEY` when using `--cloud azure`.



### Plugin-based Storage Providers

Custom providers can be defined in `~/.sequoiarecover/providers.json`. Each entry specifies a name, a provider type such as `backblaze`, `aws` or `azure`, and any necessary credentials. The CLI loads this file on startup to register the providers.

### Management Server

The `management-server/` crate implements a lightweight web service for administering users and orchestrating backups across machines. Launch it with `cargo run -p management-server` and use the REST API to register users, assign roles and inspect the audit log.
Clients can POST security alerts to the `/alert` endpoint. Set the `MGMT_CONSOLE_URL` environment variable on backup hosts so alerts are delivered automatically.

### Graphical Interface

A modern GUI lives under `ui/`. Build it with `cargo run -p ui` to open a cross-platform interface for scheduling and monitoring backups.

### Encryption & Key Management

Use `sequoiarecover init` to store cloud credentials. Run `sequoiarecover keygen` once to create a zero‑knowledge archive key stored in `~/.sequoiarecover/archive_key`. This key is required for all backup and restore operations and is never uploaded. Rotate it at any time with `sequoiarecover keyrotate`.
The CLI automatically loads this key when encrypting or decrypting archives.
If compiled with the `hardware-auth` feature and a YubiKey or HSM is present,
run `sequoiarecover keygen --hardware-key` to store the archive key on the
device. Subsequent operations will retrieve the key from hardware.
On Linux systems, ensure the `pcscd` service and `libpcsclite` development
files are installed so the YubiKey can be accessed.

### Resumable Uploads & Deduplication

Backups are uploaded in chunks so interrupted transfers resume automatically. A deduplication index avoids re-uploading identical data.

### Upcoming Tasks

Planned enhancements include a zero-knowledge architecture, hardware security key support and network throttling options.
### Logging

SequoiaRecover uses the `tracing` crate for logging. Enable detailed output by
setting the `RUST_LOG` environment variable before running commands:

```bash
RUST_LOG=info sequoiarecover backup --source /data --bucket my-bucket
```

Use `debug` for even more verbose logs.

## Typical Workflows

The commands below illustrate a common backup cycle.

1. Configure providers in `~/.sequoiarecover/providers.json` and store credentials with `sequoiarecover init`.
2. Generate an encryption key using `sequoiarecover keygen`.
3. Run a full backup:
   ```bash
   sequoiarecover backup --source /data --bucket my-bucket --mode full
   ```
4. Schedule incremental backups:
   ```bash
   sequoiarecover schedule --source /data --bucket my-bucket --interval 3600 \
       --mode incremental
   ```
5. Review stored archives or monitor jobs from the GUI or management server:
   ```bash
   sequoiarecover history --bucket my-bucket
   ```
6. Restore files when needed:
   ```bash
   sequoiarecover restore --backup backup.tar --bucket my-bucket \
       --destination /restore/path
   ```


## Troubleshooting

- **Authentication errors** – Rerun `sequoiarecover init` to ensure your
  Backblaze credentials are correct and unlocked. Verify the encryption password
  matches the one used during initialization.
- **Network failures** – Check your internet connectivity and proxy settings.
  Retry the command after a stable connection is established. Use
  `RUST_LOG=debug` for more verbose output.
- **File permission issues** – Confirm the user running the command has read
  access to source files and write access to the destination directory or
  server.

## Release Process

SequoiaRecover uses GitHub Actions to build binaries for Windows, macOS and Linux whenever a new version tag is pushed. The workflow is defined in `.github/workflows/release.yml` and can also be triggered manually from the GitHub web UI.

1. Create a version tag locally and push it:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

2. GitHub Actions will compile the project on all three platforms, sign the executables when signing keys are provided, and package them as zip archives.
3. The workflow uploads the archives as assets on the GitHub release page.

You can download the prebuilt binaries from the "Releases" section once the workflow completes.
