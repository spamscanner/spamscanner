/**
 * Open models recommended for the language model check, with their Ollama
 * tags and Hugging Face repositories. All are under open licenses.
 */
export const RECOMMENDED_MODELS = [
	{
		tier: 'tiny', ollama: 'qwen3.5:0.8b', huggingface: 'Qwen/Qwen3.5-0.8B', license: 'Apache-2.0', size: '1.3 GB', languages: '201', notes: 'Runs on any CPU. Got 4 of 6 test messages right in our runs: catches obvious spam, misses subtle cases.',
	},
	{
		tier: 'tiny', ollama: 'granite4:350m', huggingface: 'ibm-granite/granite-4.0-350m', license: 'Apache-2.0', size: '0.7 GB', languages: '12', notes: 'Smallest and fastest (about 3 seconds a message on two CPU cores), but weak alone: 3 of 6 in our runs.',
	},
	{
		tier: 'small', ollama: 'gemma4:e2b', huggingface: 'google/gemma-4-E2B-it', license: 'Apache-2.0', size: '4.6 GB', languages: '140+ trained, 35+ supported', notes: '6 of 6 test messages right in our runs, including German, Chinese and Russian, about 20 seconds a message on two CPU cores.',
	},
	{
		tier: 'small', ollama: 'qwen3.5:4b', huggingface: 'Qwen/Qwen3.5-4B', license: 'Apache-2.0', size: '3.3 GB', languages: '201', notes: 'The default. 6 of 6 test messages right in our runs, including German, Chinese, Russian and a prompt injection, about 30 seconds a message on two CPU cores.',
	},
	{
		tier: 'small', ollama: 'granite4.1:3b', huggingface: 'ibm-granite/granite-4.1-3b', license: 'Apache-2.0', size: '2.1 GB', languages: '12', notes: 'IBM\'s small enterprise model.',
	},
	{
		tier: 'small', ollama: 'ministral-3:3b', huggingface: 'mistralai/Ministral-3-3B-Instruct-2512', license: 'Apache-2.0', size: '3.0 GB', languages: 'dozens', notes: 'Mistral\'s smallest edge model.',
	},
	{
		tier: 'small', ollama: 'phi4-mini:3.8b', huggingface: 'microsoft/Phi-4-mini-instruct', license: 'MIT', size: '2.5 GB', languages: 'English first', notes: 'Microsoft\'s small model; its card notes weaker results outside English.',
	},
	{
		tier: 'medium', ollama: 'qwen3.5:9b', huggingface: 'Qwen/Qwen3.5-9B', license: 'Apache-2.0', size: '6.6 GB', languages: '201', notes: 'The larger sibling of the default, for a GPU with 8 GB or more.',
	},
	{
		tier: 'medium', ollama: 'gemma4:12b', huggingface: 'google/gemma-4-12B-it', license: 'Apache-2.0', size: '7.7 GB', languages: '140+ trained, 35+ supported', notes: 'The larger Gemma 4, for a GPU with 10 GB or more.',
	},
	{
		tier: 'policy', ollama: 'gpt-oss-safeguard:20b', huggingface: 'openai/gpt-oss-safeguard-20b', license: 'Apache-2.0', size: '14 GB', languages: 'many', notes: 'A safety model that applies your own written policy; pair it with --llm-policy.',
	},
];

/**
 * Text classification models for the "tei" and "huggingface-classifier"
 * providers. They answer in milliseconds but read English only.
 */
export const CLASSIFIER_MODELS = [
	{
		huggingface: 'cybersectony/phishing-email-detection-distilbert_v2.4.1', license: 'Apache-2.0', languages: 'English', notes: 'Phishing and spam email, DistilBERT.',
	},
	{
		huggingface: 'mshenoda/roberta-spam', license: 'MIT', languages: 'English', notes: 'Spam, RoBERTa.',
	},
	{
		huggingface: 'mrm8488/bert-tiny-finetuned-enron-spam-detection', license: 'Apache-2.0', languages: 'English', notes: 'Tiny BERT trained on Enron spam; runs anywhere.',
	},
];
