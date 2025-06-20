#!/usr/bin/env python3
"""
Download Enron Spam/Ham Dataset from Hugging Face
"""

from datasets import load_dataset
import json
import os

def download_enron_dataset():
    """Download and save the Enron spam/ham dataset"""
    print("Downloading Enron spam/ham dataset from Hugging Face...")
    
    # Load the dataset
    dataset = load_dataset("SetFit/enron_spam")
    
    # Get the training split
    train_data = dataset['train']
    
    print(f"Dataset loaded: {len(train_data)} emails")
    print(f"Features: {train_data.features}")
    
    # Convert to list for easier processing
    emails = []
    spam_count = 0
    ham_count = 0
    
    for item in train_data:
        email = {
            'id': item['message_id'],
            'subject': item['subject'] or '',
            'message': item['message'] or '',
            'text': item['text'] or '',
            'label': item['label'],  # 0=ham, 1=spam
            'label_text': item['label_text'],
            'date': str(item['date']) if item['date'] else ''
        }
        emails.append(email)
        
        if item['label'] == 1:
            spam_count += 1
        else:
            ham_count += 1
    
    print(f"Ham emails: {ham_count}")
    print(f"Spam emails: {spam_count}")
    print(f"Total emails: {len(emails)}")
    
    # Save to JSON file
    with open('enron_dataset.json', 'w', encoding='utf-8') as f:
        json.dump(emails, f, indent=2, ensure_ascii=False)
    
    print("Dataset saved to enron_dataset.json")
    
    # Create sample files for inspection
    ham_samples = [email for email in emails if email['label'] == 0][:10]
    spam_samples = [email for email in emails if email['label'] == 1][:10]
    
    with open('ham_samples.json', 'w', encoding='utf-8') as f:
        json.dump(ham_samples, f, indent=2, ensure_ascii=False)
    
    with open('spam_samples.json', 'w', encoding='utf-8') as f:
        json.dump(spam_samples, f, indent=2, ensure_ascii=False)
    
    print("Sample files created: ham_samples.json, spam_samples.json")
    
    return emails

if __name__ == "__main__":
    emails = download_enron_dataset()
    print(f"Download complete: {len(emails)} emails ready for training")

