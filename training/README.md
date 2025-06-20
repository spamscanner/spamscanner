# Classifier Training Guide

This directory contains scripts and documentation for training the SpamScanner classifier with your own datasets.


## 🎯 Quick Start

### Using the Enron Dataset (Recommended)

```bash
# 1. Install Python dependencies
pip3 install datasets huggingface_hub

# 2. Download the Enron dataset
python3 download_dataset.py

# 3. Train the classifier
node simple_trainer.js enron_dataset.json classifier.json

# 4. Test the trained classifier
node test_classifier.js

# 5. Copy classifier to main project
cp classifier.json ../
cp classifier_metadata.json ../
```


## 📁 Training Scripts

### Core Scripts

* **`download_dataset.py`** - Downloads Enron spam/ham dataset from Hugging Face
* **`simple_trainer.js`** - Memory-efficient training script (recommended)
* **`optimized_trainer.js`** - Advanced training with worker threads
* **`test_classifier.js`** - Validates trained classifier performance
* **`prepare_training_data.py`** - Converts JSON to file-based format

### Legacy Scripts

* **`../classifier.js`** - Original training script (requires file-based input)
* **`../classifier-with-workers.js`** - Multi-threaded version of original script


## 🗃️ Dataset Options

### 1. Enron Dataset (Default)

**Source**: Hugging Face SetFit/enron\_spam\
**Size**: 31,716 emails (15,553 ham, 16,163 spam)\
**Quality**: High-quality, real-world email data\
**License**: Public domain

```python
# Download automatically
python3 download_dataset.py
```

### 2. SpamAssassin Public Corpus

**Source**: Apache SpamAssassin\
**Size**: \~6,000 emails\
**Quality**: Well-curated, widely used\
**License**: Apache License

```bash
# Download manually
wget https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
wget https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2

# Extract and convert
tar -xjf 20030228_easy_ham.tar.bz2
tar -xjf 20030228_spam.tar.bz2

# Train with original script
SPAM_CATEGORY=ham SCAN_DIRECTORY=easy_ham node ../classifier.js
SPAM_CATEGORY=spam SCAN_DIRECTORY=spam node ../classifier.js
```

### 3. Custom Dataset

Create your own dataset in JSON format:

```json
[
  {
    "id": 1,
    "subject": "Meeting tomorrow",
    "message": "Hi John, can we reschedule...",
    "label": 0,
    "label_text": "ham"
  },
  {
    "id": 2,
    "subject": "You won $1,000,000!!!",
    "message": "Congratulations! Click here...",
    "label": 1,
    "label_text": "spam"
  }
]
```

**Required fields:**

* `id`: Unique identifier
* `subject`: Email subject line
* `message`: Email body content
* `label`: 0 for ham, 1 for spam
* `label_text`: "ham" or "spam"


## ⚙️ Training Configuration

### Simple Trainer (Recommended)

```javascript
const trainer = new OptimizedTrainer({
  vocabularyLimit: 20000,    // Max unique tokens
  batchSize: 100,           // Emails per batch
  hashTokens: true,         // Enable privacy hashing
  verbose: true             // Show progress
});
```

### Advanced Options

```javascript
// Custom tokenization
tokenizer: (tokens) => {
  return tokens
    .map(token => token.toLowerCase())
    .filter(token => token.length > 2)
    .map(token => hashTokens ? hash(token) : token);
}

// Ham bias (reduces false positives)
hamBias: 2.0,  // 2x weight for ham tokens

// Memory management
maxMemoryUsage: '512MB',
enableGarbageCollection: true
```


## 🔒 Privacy & Security

### Token Hashing

All training scripts use SHA-256 hashing by default:

```javascript
// Tokens are hashed before storage
const hashedToken = createHash('sha256')
  .update(token)
  .digest('hex')
  .slice(0, 16);
```

**Benefits:**

* Training data cannot be reverse-engineered
* Protects user privacy
* Maintains classification accuracy
* Reduces storage requirements

### Disable Hashing (Development Only)

```javascript
const trainer = new OptimizedTrainer({
  hashTokens: false  // Only for debugging
});
```


## 📊 Performance Optimization

### Memory Management

```javascript
// Batch processing
const BATCH_SIZE = 100;  // Adjust based on available RAM

// Garbage collection
if (global.gc && processedEmails % 1000 === 0) {
  global.gc();
}
```

### Vocabulary Limiting

```javascript
// Prevent overfitting
const VOCABULARY_LIMIT = 20000;  // Optimal for most datasets

// Dynamic adjustment
const vocabularySize = Math.min(
  uniqueTokens.length,
  Math.floor(totalEmails * 0.1)
);
```

### Concurrent Processing

```javascript
// Worker threads (advanced)
const workers = os.cpus().length;
const concurrency = Math.min(workers, 4);

await pMap(emails, processEmail, { concurrency });
```


## 🧪 Testing & Validation

### Basic Testing

```bash
# Test with sample emails
node test_classifier.js

# Expected output:
# ✅ Ham - Business Email (95.2% confidence)
# ✅ Spam - Phishing (87.3% confidence)
# 📊 Accuracy: 80.0% (4/5)
```

### Cross-Validation

```javascript
// Split dataset for validation
const trainSize = Math.floor(emails.length * 0.8);
const trainData = emails.slice(0, trainSize);
const testData = emails.slice(trainSize);

// Train and validate
await trainer.train(trainData);
const accuracy = await trainer.validate(testData);
```

### Performance Benchmarks

```bash
# Run performance tests
npm run test:performance

# Memory usage monitoring
node --max-old-space-size=4096 simple_trainer.js
```


## 🔧 Troubleshooting

### Common Issues

**Out of Memory Error**

```bash
# Reduce batch size
const BATCH_SIZE = 50;  // Instead of 100

# Increase Node.js memory
node --max-old-space-size=8192 simple_trainer.js
```

**Slow Training**

```bash
# Use optimized trainer
node optimized_trainer.js

# Enable worker threads
const USE_WORKERS = true;
```

**Low Accuracy**

```bash
# Increase vocabulary limit
const VOCABULARY_LIMIT = 30000;

# Adjust ham bias
const HAM_BIAS = 1.5;  # Reduce from 2.0

# Add more training data
python3 download_additional_datasets.py
```

### Debug Mode

```javascript
// Enable detailed logging
const trainer = new OptimizedTrainer({
  verbose: true,
  debug: true
});

// Monitor memory usage
process.on('exit', () => {
  console.log('Peak memory:', process.memoryUsage());
});
```


## 📈 Advanced Techniques

### Ensemble Learning

```javascript
// Train multiple classifiers
const classifiers = await Promise.all([
  trainNaiveBayes(dataset),
  trainSVM(dataset),
  trainRandomForest(dataset)
]);

// Combine predictions
const prediction = combineVotes(classifiers, email);
```

### Feature Engineering

```javascript
// Custom features
const features = {
  ...getTokenFeatures(email),
  urlCount: extractUrls(email).length,
  hasAttachments: email.attachments.length > 0,
  subjectLength: email.subject.length,
  hasNumbers: /\d/.test(email.text)
};
```

### Online Learning

```javascript
// Incremental training
const classifier = await loadExistingClassifier();
await classifier.learnIncremental(newEmails);
await classifier.save();
```


## 📚 Additional Resources

* [Naive Bayes Algorithm](https://en.wikipedia.org/wiki/Naive_Bayes_classifier)
* [Email Spam Filtering](https://en.wikipedia.org/wiki/Email_filtering)
* [Text Classification Best Practices](https://developers.google.com/machine-learning/guides/text-classification)
* [SpamAssassin Documentation](https://spamassassin.apache.org/doc/)


## 🤝 Contributing

Found an issue or want to improve the training process?

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request


## 📄 License

Training scripts are released under the same license as SpamScanner.
