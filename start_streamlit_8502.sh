#!/bin/bash
# Script to start Streamlit app in cybersecurity repo on port 8502 with nohup

cd "$(dirname "$0")"
cd ../cybersecurity

nohup streamlit run main.py --server.port 8502 > streamlit.log 2>&1 &
echo "Streamlit started on port 8502. Log: streamlit.log"
