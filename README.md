```markdown
# VpcCtl: Simplified VPC Management on Linux 🌐

A lightweight command-line tool built with Python for creating and managing isolated network environments on Linux. `vpcctl` simplifies the process of setting up network bridges, namespaces, and subnets, mimicking the functionality of a cloud Virtual Private Cloud (VPC) on your local machine. Built as a submission for my HNG Stage 4 Task.

## ✨ Features

- **VPC Creation**: Easily scaffold a new virtual network with a specified CIDR block.
- **Network Isolation**: Utilizes Linux network namespaces to create completely isolated environments.
- **Bridge Networking**: Automatically creates and configures a network bridge for the VPC.
- **Smart IP Assignment**: Intelligently selects and assigns an available IP address from the VPC's CIDR range to the bridge.
- **Dry Run Mode**: Preview all network changes before applying them with the `--dry-run` flag.

## 🚀 Getting Started

Follow these steps to get `vpcctl` running on your system.

### Prerequisites

This tool is designed for Debian-based Linux distributions (like Ubuntu) and requires root privileges to manage network interfaces.

- Python 3.x
- `iproute2` package
- `iptables` package
- `bridge-utils` package
- `python3-venv` package

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/whotterre/HNG13_DevOps_Task_4.git
    cd HNG13_DevOps_Task_4
    ```

2.  **Run the Setup Script**
    The `pre-run.sh` script will check for and install the required `iproute2` package.

    ```bash
    chmod +x pre-run.sh
    sudo ./pre-run.sh
    ```

## ⚙️ Usage

`vpcctl` is operated from the command line. The primary command is `create`, which sets up a new VPC environment. The project also implements `list` to enumerate created VPCs and `inspect` to view details for a single VPC (reads persisted metadata).

> Note: All commands that modify networking must be run with root privileges (sudo).

### Create a VPC

To create a new VPC, you need to specify its name, a primary CIDR block, public/private subnets, and the host's main network interface.

**Command Structure:**
```bash
sudo python3 -m vpcctl.cli create --name <VPC_NAME> --cidr <CIDR_BLOCK> --public-subnet <PUBLIC_SUBNET_CIDR> --private-subnet <PRIVATE_SUBNET_CIDR> --interface <HOST_INTERFACE>
```

**Example:**

This command creates a VPC named `my-test-vpc` with a main CIDR of `10.10.0.0/16`.

```bash
sudo python3 -m vpcctl.cli create \
  --name "my-test-vpc" \
  --cidr "10.10.0.0/16" \
  --public-subnet "10.10.1.0/24" \
  --private-subnet "10.10.2.0/24" \
  --interface "eth0"
```

### Dry Run

To see what commands the tool will execute without making any changes to your system, use the `--dry-run` flag.

```bash
sudo python3 -m vpcctl.cli create \
  --name "my-test-vpc" \
  --cidr "10.10.0.0/16" \
  --public-subnet "10.10.1.0/24" \
  --private-subnet "10.10.2.0/24" \
  --interface "eth0" \
  --dry-run
```

### List VPCs

Shows the names of VPCs previously created via `vpcctl`. It prefers reading persisted metadata from `/var/lib/vpcctl/vpcs.ndjson` and falls back to scanning bridge interfaces if that file is missing.

```bash
sudo python3 -m vpcctl.cli list
```

Example output:

```
Existing VPCs
--------------
test-vpc
my-test-vpc
```

### Inspect a VPC

Displays detailed information about a single VPC. This looks up the persisted record in `/var/lib/vpcctl/vpcs.ndjson` and pretty-prints it. If no persisted record exists, it will try to show the bridge's `ip link` output.

```bash
sudo python3 -m vpcctl.cli inspect --name my-test-vpc
```

Example output (JSON):

```json
{
  "name": "my-test-vpc",
  "bridge": "br-abc123",
  "public_ns": "vpc-pub-ns-...",
  "private_ns": "vpc-pr-ns-...",
  "public_subnet": "10.10.1.0/24",
  "private_subnet": "10.10.2.0/24",
  "interface": "eth0",
  "bridge_ip": "10.10.0.2/16"
}
```

## Storage / metadata

Created VPCs are appended as newline-delimited JSON records to:

```
/var/lib/vpcctl/vpcs.ndjson
```

This file is used by `list` and `inspect` to provide user-friendly output.

## 🛠️ Technologies Used

| Technology | Description |
| :--- | :--- |
| **Python** | Core logic for the command-line tool and network operations. |
| **Bash** | Used for the dependency installation script (`pre-run.sh`). |
| **iproute2** | The underlying Linux utility suite used for all network modifications. |

## 🤝 Contributing

Contributions are welcome! If you'd like to improve `vpcctl`, please follow these steps:

-   Fork the repository.
-   Create a new branch (`git checkout -b feature/AmazingFeature`).
-   Commit your changes (`git commit -m 'Add some AmazingFeature'`).
-   Push to the branch (`git push origin feature/AmazingFeature`).
-   Open a Pull Request.

## ✍️ Author

**whotterre**

-   **Twitter**: [@your_twitter_handle](https://twitter.com/your_twitter_handle)
-   **LinkedIn**: [your-linkedin-profile](https://linkedin.com/in/your-linkedin-profile)

<br>


![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

[![Readme was generated by Dokugen](https://img.shields.io/badge/Readme%20was%20generated%20by-Dokugen-brightgreen)](https://www.npmjs.com/package/dokugen)
``` # VpcCtl: Simplified VPC Management on Linux 🌐

A lightweight command-line tool built with Python for creating and managing isolated network environments on Linux. `vpcctl` simplifies the process of setting up network bridges, namespaces, and subnets, mimicking the functionality of a cloud Virtual Private Cloud (VPC) on your local machine. Built as a submission for my HNG Stage 4 Task.

## ✨ Features

- **VPC Creation**: Easily scaffold a new virtual network with a specified CIDR block.
- **Network Isolation**: Utilizes Linux network namespaces to create completely isolated environments.
- **Bridge Networking**: Automatically creates and configures a network bridge for the VPC.
- **Smart IP Assignment**: Intelligently selects and assigns an available IP address from the VPC's CIDR range to the bridge.
- **Dry Run Mode**: Preview all network changes before applying them with the `--dry-run` flag.

## 🚀 Getting Started

Follow these steps to get `vpcctl` running on your system.

### Prerequisites

This tool is designed for Debian-based Linux distributions (like Ubuntu) and requires root privileges to manage network interfaces.

- Python 3.x
- `iproute2` package
- `iptables` package
- `bridge-utils` package
- `python3-venv` package

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/whotterre/HNG13_DevOps_Task_4.git
    cd HNG13_DevOps_Task_4
    ```

2.  **Run the Setup Script**
    The `pre-run.sh` script will check for and install the required `iproute2` package.

    ```bash
    chmod +x pre-run.sh
    sudo ./pre-run.sh
    ```

## ⚙️ Usage

`vpcctl` is operated from the command line. The primary command is `create`, which sets up a new VPC environment.

### Create a VPC

To create a new VPC, you need to specify its name, a primary CIDR block, public/private subnets, and the host's main network interface.

**Command Structure:**
```bash
sudo python3 -m vpcctl.cli create --name <VPC_NAME> --cidr <CIDR_BLOCK> --public-subnet <PUBLIC_SUBNET_CIDR> --private-subnet <PRIVATE_SUBNET_CIDR> --interface <HOST_INTERFACE>
```

**Example:**

This command creates a VPC named `my-test-vpc` with a main CIDR of `10.10.0.0/16`.

```bash
sudo python3 -m vpcctl.cli create \
  --name "my-test-vpc" \
  --cidr "10.10.0.0/16" \
  --public-subnet "10.10.1.0/24" \
  --private-subnet "10.10.2.0/24" \
  --interface "eth0"
```

### Dry Run

To see what commands the tool will execute without making any changes to your system, use the `--dry-run` flag.

```bash
sudo python3 -m vpcctl.cli create \
  --name "my-test-vpc" \
  --cidr "10.10.0.0/16" \
  --public-subnet "10.10.1.0/24" \
  --private-subnet "10.10.2.0/24" \
  --interface "eth0" \
  --dry-run
```

## 🛠️ Technologies Used

| Technology | Description |
| :--- | :--- |
| **Python** | Core logic for the command-line tool and network operations. |
| **Bash** | Used for the dependency installation script (`pre-run.sh`). |
| **iproute2** | The underlying Linux utility suite used for all network modifications. |

## 🤝 Contributing

Contributions are welcome! If you'd like to improve `vpcctl`, please follow these steps:

-   Fork the repository.
-   Create a new branch (`git checkout -b feature/AmazingFeature`).
-   Commit your changes (`git commit -m 'Add some AmazingFeature'`).
-   Push to the branch (`git push origin feature/AmazingFeature`).
-   Open a Pull Request.



![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
