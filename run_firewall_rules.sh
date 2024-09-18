#!/bin/bash
# Path to the current directory
DIR=$(pwd)

# Activate the virtual environment
source "$DIR/myenv/bin/activate"

# Run the Python script
python3 "$DIR/firewall-rules.py"
