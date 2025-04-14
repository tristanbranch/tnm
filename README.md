# Terminal Network Manager ( WIP )

A powerful terminal-based network management tool designed to monitor and manage network connections, interfaces, and configurations directly from the command line. This tool provides various functionalities such as network scanning, traffic monitoring, and device health checks.

I am aware that they are bugs, and i'm working on them, this tool is ment for linux I have not tested it on windows.

## Features

- **Ping Hosts**: Check the reachability of hosts.
- **Port Scanning**: Scan common ports on specified hosts.
- **Network Information**: Retrieve detailed information about network interfaces, routing tables, and DNS configurations.
- **Firewall Management**: Open and close ports using iptables.
- **Network Topology Mapping**: Visualize the network topology and discover active devices.
- **Traffic Monitoring**: Monitor network traffic in real-time with detailed statistics.
- **Configuration Backup**: Backup device configurations using SNMP or SSH.
- **Security Scanning**: Perform basic security scans to identify open ports and potential vulnerabilities.
- **Device Health Monitoring**: Check CPU, memory, and temperature metrics of network devices.

## Installation

To install the Terminal Network Manager, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/terminal-network-manager.git
   ```

2. Navigate to the project directory:
   ```bash
   cd terminal-network-manager
   ```

3. Install the required dependencies:
   ```bash
   pip install psutil nmap
   ```

## Usage

To start the Terminal Network Manager, run the following command:

```bash
sudo python3 terminal.py
```

### Main Menu Options

1. **Ping a host**: Check if a host is reachable.
2. **Scan ports on a host**: Identify open ports on a specified host.
3. **Show network information**: Display detailed network information.
4. **Open a port**: Open a specified port in the firewall.
5. **Close a port**: Close a specified port in the firewall.
6. **Map network topology**: Visualize the network and discover devices.
7. **Monitor network traffic**: Analyze real-time network traffic.
8. **Backup device configuration**: Backup configurations of network devices.
9. **Security scan**: Perform a security scan on a host.
10. **Device health check**: Monitor the health of a specified device.
11. **Exit**: Exit the application.

## Requirements

- Python 3.x
- Root privileges for certain functionalities (e.g., firewall management, network scanning).
- Required Python packages: `psutil`, `nmap`.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please fork the repository and submit a pull request.

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/YourFeature
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m "Add your message here"
   ```
4. Push to the branch:
   ```bash
   git push origin feature/YourFeature
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Your Name](https://github.com/yourusername) - for creating this project.
- Any libraries or tools you used in the project.

## Contact

For any inquiries, please reach out to [your.email@example.com](mailto:your.email@example.com).
