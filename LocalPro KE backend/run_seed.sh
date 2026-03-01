#!/bin/bash
# PetSoko Admin Seeding Script - Linux/Mac Shell Script
# Quick launcher for seed_admin.py

echo "===================================="
echo "PetSoko Admin Seeding Tool"
echo "===================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

echo "Python found. Starting seed script..."
echo ""

# Check for command line arguments
if [ $# -eq 0 ]; then
    echo "No arguments provided. Creating admin only..."
    echo ""
    python3 seed_admin.py
elif [ "$1" = "clean" ]; then
    echo "Running in CLEAN mode..."
    echo ""
    if [ "$2" = "sample" ]; then
        python3 seed_admin.py --clean --with-sample
    else
        python3 seed_admin.py --clean
    fi
elif [ "$1" = "sample" ]; then
    echo "Creating admin with sample data..."
    echo ""
    python3 seed_admin.py --with-sample
else
    echo "Unknown argument: $1"
    echo ""
    echo "Usage:"
    echo "  ./run_seed.sh              - Create admin only"
    echo "  ./run_seed.sh sample       - Create admin with sample data"
    echo "  ./run_seed.sh clean        - Clean database and create admin"
    echo "  ./run_seed.sh clean sample - Clean database and create all data"
    exit 1
fi

echo ""
echo "===================================="
