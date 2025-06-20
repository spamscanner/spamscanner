#!/bin/bash
# SpamScanner Classifier Training Example
# This script demonstrates the complete training pipeline

set -e  # Exit on any error

echo "🚀 SpamScanner Classifier Training Example"
echo "=========================================="

# Check dependencies
echo "📋 Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed"
    exit 1
fi

echo "✅ Dependencies check passed"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install datasets huggingface_hub

# Download dataset
echo "⬇️  Downloading Enron dataset..."
python3 download_dataset.py

# Check if dataset was downloaded
if [ ! -f "enron_dataset.json" ]; then
    echo "❌ Failed to download dataset"
    exit 1
fi

echo "✅ Dataset downloaded successfully"

# Train classifier
echo "🧠 Training classifier..."
echo "This may take 5-10 minutes depending on your system..."

node simple_trainer.js enron_dataset.json classifier.json

# Check if classifier was created
if [ ! -f "classifier.json" ]; then
    echo "❌ Failed to create classifier"
    exit 1
fi

echo "✅ Classifier trained successfully"

# Test classifier
echo "🧪 Testing classifier..."
node test_classifier.js

# Copy to main project
echo "📁 Installing classifier..."
cp classifier.json ../
cp classifier_metadata.json ../

echo ""
echo "🎉 Training completed successfully!"
echo ""
echo "📊 Results:"
echo "   - Dataset: $(wc -l < enron_dataset.json) emails processed"
echo "   - Classifier size: $(du -h classifier.json | cut -f1)"
echo "   - Metadata: classifier_metadata.json"
echo ""
echo "🚀 Your SpamScanner is now ready with a trained classifier!"
echo "   Run 'npm test' in the main directory to verify everything works."

