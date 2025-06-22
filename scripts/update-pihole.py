import toml
import argparse
import re

def update_pihole_hosts(dnsmasq_file, pihole_toml_file):
    """
    Reads host entries from a dnsmasq-style hosts file and adds them to
    the [dns].hosts array in a Pi-hole TOML configuration file.

    Args:
        dnsmasq_file (str): Path to the dnsmasq hosts configuration file.
        pihole_toml_file (str): Path to the Pi-hole TOML configuration file.
    """
    try:
        # Read the dnsmasq hosts file
        with open(dnsmasq_file, 'r') as f:
            dnsmasq_content = f.readlines()

        # Parse dnsmasq entries
        new_host_entries = []
        for line in dnsmasq_content:
            line = line.strip()
            # Regex to match lines like "address=/hostname/ip_address"
            match = re.match(r'address=/(.*?)/(.*)', line)
            if match:
                hostname = match.group(1)
                ip_address = match.group(2)
                new_host_entries.append(f"{ip_address} {hostname}")
            # Also handle standard hosts file format "ip_address hostname"
            elif not line.startswith('#') and line:
                parts = line.split()
                if len(parts) >= 2:
                    ip_address = parts[0]
                    hostname = parts[1]
                    new_host_entries.append(f"{ip_address} {hostname}")

        # Read the Pi-hole TOML file
        with open(pihole_toml_file, 'r') as f:
            pihole_config = toml.load(f)

        # Ensure the [dns] section and hosts array exist
        if 'dns' not in pihole_config:
            pihole_config['dns'] = {}
        if 'hosts' not in pihole_config['dns'] or not isinstance(pihole_config['dns']['hosts'], list):
            pihole_config['dns']['hosts'] = []

        # Add new entries, avoiding duplicates
        for entry in new_host_entries:
            if entry not in pihole_config['dns']['hosts']:
                pihole_config['dns']['hosts'].append(entry)

        # Write the updated TOML back to the file
        with open(pihole_toml_file, 'w') as f:
            toml.dump(pihole_config, f)

        print(f"Successfully updated '{pihole_toml_file}' with entries from '{dnsmasq_file}'.")

    except FileNotFoundError as e:
        print(f"Error: One of the specified files was not found: {e}")
    except toml.TomlDecodeError as e:
        print(f"Error parsing TOML file '{pihole_toml_file}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update Pi-hole TOML file with Dnsmasq host entries.")
    parser.add_argument("--dnsmasq", required=True, help="Path to the dnsmasq hosts configuration file (e.g., vadai-hosts.conf).")
    parser.add_argument("--pihole", required=True, help="Path to the Pi-hole TOML configuration file (e.g., pihole.toml).")

    args = parser.parse_args()

    update_pihole_hosts(args.dnsmasq, args.pihole)

