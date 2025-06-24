# SequoiaRecover

**SequoiaRecover** is a free, cross-platform backup tool designed for Windows, macOS, and Linux that securely backs up your data to cloud storage services like Backblaze. Built with performance and safety in mind using **Rust**, SequoiaRecover aims to provide reliable disaster recovery and business continuity solutions for individuals and organizations alike.

---

## Features

- Cross-platform support: Windows, macOS, and Linux
- Incremental and full backups
- Integration with cloud storage providers (initially Backblaze B2)
- Secure, efficient data transfer and storage
- Recursive directory backups
- Multi-threaded compression support
- Automated backup scheduling
- Easy-to-use command-line interface (CLI) with plans for a GUI
- Focus on disaster recovery and business continuity
- View past backup history
- Inspect backup contents without extracting
- Restore files from archives
- Retrieve and restore backups directly from Backblaze

---

## Getting Started

### Prerequisites

- Rust toolchain installed (via [rustup](https://rustup.rs/))
- Access to a cloud storage account (e.g., Backblaze B2)

### Installation

Clone the repository:

```bash
git clone https://github.com/YourUsername/SequoiaRecover.git
cd SequoiaRecover
```
Build the project:
```bash
cargo build --release
```

Run the backup tool:
```bash
./target/release/sequoiarecover --help
```

### Usage
Example command to perform a backup:
```bash
sequoiarecover backup --source /path/to/data --cloud backblaze --bucket my-bucket --mode full
```
The `--mode` flag controls whether a **full** or **incremental** backup is performed.
Incremental mode only archives files that have changed since the previous backup.
You can control compression with `--compression`. Passing `auto` lets
SequoiaRecover choose a compression method based on your network speed to help
reduce transfer costs.
To run automated backups every hour:
```bash
sequoiarecover schedule --source /path/to/data --bucket my-bucket --interval 3600 --mode incremental
```
Show previous backups stored in Backblaze:
```bash
sequoiarecover history --bucket my-bucket
```
List the contents of a backup archive from Backblaze without downloading:
```bash
sequoiarecover list --backup backup.tar --bucket my-bucket
```
Restore a backup directly from Backblaze:
```bash
sequoiarecover restore --backup backup.tar --bucket my-bucket --destination /restore/path
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

### Linux CLI

You can build and run the command-line application on Linux using Cargo:

```bash
cargo run -- backup --source /path/to/data --bucket my-bucket
```

### Backblaze Authentication

Run the following command once to create an encrypted configuration file for your Backblaze credentials:

```bash
sequoiarecover init
```

You'll be prompted for your account ID, application key, and an encryption password. After that, the `backup` and `schedule` commands will automatically decrypt the credentials when uploading to Backblaze.
