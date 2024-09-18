# Firewall Rules Script
This project is a [4evergaming](https://4evergaming.com.ar) tool that fetches firewall rules from a database and loads them into iptables. The setup includes a Python virtual environment and a scheduled task to update the rules every 24 hours.

## Requirements

- Python 3.x
- `pip`
- MySQL database
- Access to cron (to schedule the script execution)

## Installation
```bash
# Install linux dependencies
apt install git python3-venv -y

# Clone my repository
cd /root
git clone https://github.com/stefanofabi/firewall-rules.git
cd firewall-rules

# Enter the virtual environment
python3 -m venv myenv
source myenv/bin/activate

# Install python dependencies
pip install -r requirements.txt

# Configure the MySQL connection
cp config.json.example config.json
nano config.json

# Run the script to verify that everything is ok
chmod +x run_firewall_rules.sh
./run_firewall_rules.sh
```

Then set up a cron to run every day at 4am
```bash
crontab -e

0 4 * * * cd /root/firewall-rules && /root/firewall-rules/run_firewall_rules.sh >> /root/firewall-rules/firewall-rules.log 2>&1

```
