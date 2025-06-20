#!/usr/bin/env python3
"""
Optimized Enron Dataset Classifier Training Script
Converts JSON dataset to format suitable for SpamScanner training
"""

import json
import os
import tempfile
import shutil
from pathlib import Path

def prepare_training_data(dataset_path, output_dir):
    """
    Convert Enron JSON dataset to directory structure expected by classifier
    
    Args:
        dataset_path: Path to enron_dataset.json
        output_dir: Directory to create ham/spam subdirectories
    """
    print(f"Loading dataset from {dataset_path}...")
    
    with open(dataset_path, 'r', encoding='utf-8') as f:
        emails = json.load(f)
    
    print(f"Loaded {len(emails)} emails")
    
    # Create output directories
    ham_dir = Path(output_dir) / 'ham'
    spam_dir = Path(output_dir) / 'spam'
    
    ham_dir.mkdir(parents=True, exist_ok=True)
    spam_dir.mkdir(parents=True, exist_ok=True)
    
    ham_count = 0
    spam_count = 0
    
    for email in emails:
        # Combine subject and message for full email content
        subject = email.get('subject', '').strip()
        message = email.get('message', '').strip()
        
        # Create email content in mbox-like format
        email_content = f"Subject: {subject}\n\n{message}"
        
        # Determine output directory and filename
        if email['label'] == 0:  # Ham
            output_file = ham_dir / f"ham_{email['id']}.txt"
            ham_count += 1
        else:  # Spam
            output_file = spam_dir / f"spam_{email['id']}.txt"
            spam_count += 1
        
        # Write email to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(email_content)
    
    print(f"Created {ham_count} ham files in {ham_dir}")
    print(f"Created {spam_count} spam files in {spam_dir}")
    
    return ham_dir, spam_dir, ham_count, spam_count

if __name__ == "__main__":
    dataset_path = "enron_dataset.json"
    output_dir = "training_data"
    
    if not os.path.exists(dataset_path):
        print(f"Error: {dataset_path} not found. Run download_dataset.py first.")
        exit(1)
    
    ham_dir, spam_dir, ham_count, spam_count = prepare_training_data(dataset_path, output_dir)
    
    print(f"\nTraining data prepared:")
    print(f"Ham directory: {ham_dir} ({ham_count} files)")
    print(f"Spam directory: {spam_dir} ({spam_count} files)")
    print(f"\nNext steps:")
    print(f"1. Train ham: SPAM_CATEGORY=ham SCAN_DIRECTORY={ham_dir} node ../spamscanner-fresh/classifier.js")
    print(f"2. Train spam: SPAM_CATEGORY=spam SCAN_DIRECTORY={spam_dir} node ../spamscanner-fresh/classifier.js")

