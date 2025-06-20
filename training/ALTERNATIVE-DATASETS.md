# Alternative Dataset Sources

This document provides information on using alternative datasets for training the SpamScanner classifier.


## 📚 Available Datasets

### 1. SpamAssassin Public Corpus

**Description**: The original SpamAssassin public corpus, widely used for spam research.\
**Size**: \~6,000 emails\
**Quality**: High-quality, manually curated\
**License**: Apache License 2.0

#### Download and Setup

```bash
# Download the corpus
wget https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
wget https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2

# Extract files
tar -xjf 20030228_easy_ham.tar.bz2
tar -xjf 20030228_spam.tar.bz2

# Train using original classifier script
SPAM_CATEGORY=ham SCAN_DIRECTORY=easy_ham node ../classifier.js
SPAM_CATEGORY=spam SCAN_DIRECTORY=spam node ../classifier.js
```

### 2. Ling-Spam Corpus

**Description**: Academic corpus from Linguist mailing list\
**Size**: \~2,893 emails\
**Quality**: Real-world academic emails\
**License**: Research use

#### Download and Setup

```bash
# Download from official source
wget http://www.aueb.gr/users/ion/data/lingspam_public.tar.gz
tar -xzf lingspam_public.tar.gz

# Convert to JSON format
python3 convert_lingspam.py lingspam_public/ lingspam_dataset.json

# Train classifier
node simple_trainer.js lingspam_dataset.json classifier.json
```

### 3. Trec 2007 Spam Track

**Description**: NIST Text REtrieval Conference spam corpus\
**Size**: \~75,000 emails\
**Quality**: Research-grade dataset\
**License**: Research use with registration

#### Setup

```bash
# Register and download from NIST
# https://trec.nist.gov/data/spam.html

# Convert to JSON format
python3 convert_trec.py trec2007/ trec_dataset.json

# Train classifier
node simple_trainer.js trec_dataset.json classifier.json
```

### 4. Custom Corporate Dataset

**Description**: Your own email data\
**Size**: Variable\
**Quality**: Domain-specific\
**License**: Your own data

#### Format Requirements

```json
[
  {
    "id": "unique_identifier",
    "subject": "Email subject line",
    "message": "Full email body content",
    "label": 0,  // 0 for ham, 1 for spam
    "label_text": "ham"  // "ham" or "spam"
  }
]
```

#### Privacy Considerations

```javascript
// Anonymize sensitive data before training
const anonymizeEmail = (email) => ({
  ...email,
  message: email.message
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]')
    .replace(/\b\d{3}-\d{3}-\d{4}\b/g, '[PHONE]')
    .replace(/\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b/g, '[CARD]')
});
```


## 🔧 Dataset Conversion Scripts

### SpamAssassin to JSON

```python
#!/usr/bin/env python3
import os
import json
import email
from pathlib import Path

def convert_spamassassin(ham_dir, spam_dir, output_file):
    emails = []
    
    # Process ham emails
    for file_path in Path(ham_dir).glob('*'):
        if file_path.is_file():
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                msg = email.message_from_string(content)
                
                emails.append({
                    'id': f"ham_{file_path.name}",
                    'subject': msg.get('Subject', ''),
                    'message': content,
                    'label': 0,
                    'label_text': 'ham'
                })
    
    # Process spam emails
    for file_path in Path(spam_dir).glob('*'):
        if file_path.is_file():
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                msg = email.message_from_string(content)
                
                emails.append({
                    'id': f"spam_{file_path.name}",
                    'subject': msg.get('Subject', ''),
                    'message': content,
                    'label': 1,
                    'label_text': 'spam'
                })
    
    # Save to JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(emails, f, indent=2, ensure_ascii=False)
    
    print(f"Converted {len(emails)} emails to {output_file}")

if __name__ == '__main__':
    convert_spamassassin('easy_ham', 'spam', 'spamassassin_dataset.json')
```

### Maildir to JSON

```python
#!/usr/bin/env python3
import os
import json
import email
from pathlib import Path

def convert_maildir(maildir_path, label, output_file):
    emails = []
    
    # Process all emails in maildir
    for root, dirs, files in os.walk(maildir_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    msg = email.message_from_string(content)
                    
                    emails.append({
                        'id': f"{label}_{file}",
                        'subject': msg.get('Subject', ''),
                        'message': content,
                        'label': 1 if label == 'spam' else 0,
                        'label_text': label
                    })
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                continue
    
    # Save to JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(emails, f, indent=2, ensure_ascii=False)
    
    print(f"Converted {len(emails)} emails to {output_file}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 4:
        print("Usage: python3 convert_maildir.py <maildir_path> <label> <output_file>")
        sys.exit(1)
    
    convert_maildir(sys.argv[1], sys.argv[2], sys.argv[3])
```


## 📊 Dataset Quality Guidelines

### Minimum Requirements

* **Size**: At least 1,000 emails (500 ham, 500 spam)
* **Balance**: Roughly equal ham/spam ratio (40-60% either way)
* **Quality**: Real-world emails, not synthetic
* **Diversity**: Multiple sources, time periods, languages

### Recommended Practices

```javascript
// Validate dataset before training
const validateDataset = (emails) => {
  const hamCount = emails.filter(e => e.label === 0).length;
  const spamCount = emails.filter(e => e.label === 1).length;
  const total = emails.length;
  
  console.log(`Dataset validation:`);
  console.log(`  Total emails: ${total}`);
  console.log(`  Ham emails: ${hamCount} (${(hamCount/total*100).toFixed(1)}%)`);
  console.log(`  Spam emails: ${spamCount} (${(spamCount/total*100).toFixed(1)}%)`);
  
  // Check balance
  const ratio = Math.min(hamCount, spamCount) / Math.max(hamCount, spamCount);
  if (ratio < 0.3) {
    console.warn(`⚠️  Dataset is imbalanced (ratio: ${ratio.toFixed(2)})`);
  }
  
  // Check size
  if (total < 1000) {
    console.warn(`⚠️  Dataset is small (${total} emails). Consider adding more data.`);
  }
  
  return { hamCount, spamCount, total, ratio };
};
```


## 🔄 Combining Datasets

### Merge Multiple Sources

```javascript
#!/usr/bin/env node
const fs = require('fs');

async function mergeDatasets(inputFiles, outputFile) {
  let allEmails = [];
  let idCounter = 1;
  
  for (const file of inputFiles) {
    console.log(`Loading ${file}...`);
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    
    // Normalize IDs to prevent conflicts
    const normalizedData = data.map(email => ({
      ...email,
      id: `merged_${idCounter++}`,
      source: file
    }));
    
    allEmails = allEmails.concat(normalizedData);
  }
  
  // Shuffle for better training
  for (let i = allEmails.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [allEmails[i], allEmails[j]] = [allEmails[j], allEmails[i]];
  }
  
  fs.writeFileSync(outputFile, JSON.stringify(allEmails, null, 2));
  console.log(`Merged ${allEmails.length} emails to ${outputFile}`);
}

// Usage: node merge_datasets.js dataset1.json dataset2.json merged.json
if (require.main === module) {
  const inputFiles = process.argv.slice(2, -1);
  const outputFile = process.argv[process.argv.length - 1];
  
  mergeDatasets(inputFiles, outputFile);
}
```


## 🎯 Domain-Specific Training

### Corporate Email Training

```javascript
// Configure for corporate environment
const corporateConfig = {
  vocabularyLimit: 15000,  // Smaller vocabulary for focused domain
  hamBias: 3.0,           // Higher bias for business emails
  customStopWords: [
    'confidential', 'internal', 'company', 'meeting'
  ],
  enableDomainFeatures: true  // Use sender domain as feature
};
```

### Multi-Language Training

```javascript
// Configure for international emails
const multiLangConfig = {
  vocabularyLimit: 30000,  // Larger vocabulary for multiple languages
  enableLanguageDetection: true,
  languageSpecificTokens: true,
  supportedLanguages: ['en', 'es', 'fr', 'de', 'zh', 'ja']
};
```


## 📈 Performance Optimization

### Large Dataset Handling

```javascript
// Stream processing for large datasets
const processLargeDataset = async (inputFile, outputFile) => {
  const readline = require('readline');
  const fs = require('fs');
  
  const fileStream = fs.createReadStream(inputFile);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });
  
  const trainer = new OptimizedTrainer({
    streamMode: true,
    batchSize: 50  // Smaller batches for memory efficiency
  });
  
  for await (const line of rl) {
    const email = JSON.parse(line);
    await trainer.processEmail(email);
  }
  
  await trainer.finalize(outputFile);
};
```


## 🔍 Quality Assurance

### Dataset Validation

```bash
# Validate dataset format
python3 validate_dataset.py dataset.json

# Check for duplicates
python3 check_duplicates.py dataset.json

# Analyze content distribution
node analyze_dataset.js dataset.json
```

### Training Validation

```bash
# Cross-validation
node cross_validate.js dataset.json 5  # 5-fold cross-validation

# Performance benchmarking
node benchmark_training.js dataset.json
```

This comprehensive guide ensures you can successfully train SpamScanner with any dataset while maintaining high quality and performance standards.
