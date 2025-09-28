#!/bin/bash

# Cybersecurity Lab Startup Script

echo "🔒 Starting Cybersecurity Lab..."
echo "================================"

# Activate virtual environment
echo "📦 Activating virtual environment..."
source ~/venv/bin/activate

# Install dependencies
cd ~/cybersecurity
echo "📥 Installing dependencies..."
pip install -r requirements.txt


# Start Streamlit app
echo "🚀 Starting Cybersecurity Lab..."
echo "📱 Open your browser and go to: http://localhost:8501"
echo "⏹️  Press Ctrl+C to stop the lab"
echo "================================"

streamlit run main.py --server.address 0.0.0.0 --server.port 8501
