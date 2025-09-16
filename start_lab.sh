#!/bin/bash

# Cybersecurity Lab Startup Script

cd "$(dirname "$0")"

echo "🔒 Starting Cybersecurity Lab..."
echo "================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Check if all packages are installed
echo "🔍 Checking dependencies..."
python -c "import streamlit, pandas, numpy, matplotlib, plotly, cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Some packages are missing. Installing..."
    pip install -r requirements.txt
fi

# Start Streamlit app
echo "🚀 Starting Cybersecurity Lab..."
echo "📱 Open your browser and go to: http://localhost:8501"
echo "⏹️  Press Ctrl+C to stop the lab"
echo "================================"

streamlit run main.py --server.address 0.0.0.0 --server.port 8501
