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
sequoiarecover backup --source /path/to/data --cloud backblaze --bucket my-bucket
```
Check available commands and options:
```bash
sequoiarecover --help
```

### Linux CLI

You can build and run the command-line application on Linux using Cargo:

```bash
cargo run -- backup --source /path/to/data --bucket my-bucket
```
