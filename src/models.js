/**
 * Open models recommended for the language model check, with their Ollama
 * tags and Hugging Face repositories. All are under open licenses.
 */
export const RECOMMENDED_MODELS = [
	{
		tier: 'tiny', ollama: 'qwen3.5:0.8b', huggingface: 'Qwen/Qwen3.5-0.8B', license: 'Apache-2.0', size: '1.3 GB', languages: '201', notes: 'Runs on any CPU: about 2 seconds a message with the decision method on two cores of an Intel Xeon at 2.10 GHz without a GPU. 54 of 72 test messages right; catches obvious spam, misses subtle cases.',
	},
	{
		tier: 'tiny', ollama: 'granite4:350m', huggingface: 'ibm-granite/granite-4.0-350m', license: 'Apache-2.0', size: '0.7 GB', languages: '12', notes: 'Smallest and fastest, about 1 second a message on two cores of an Intel Xeon at 2.10 GHz without a GPU, but calls nearly everything spam: 40 of 72 test messages right.',
	},
	{
		tier: 'small', ollama: 'gemma4:e2b', huggingface: 'google/gemma-4-E2B-it', license: 'Apache-2.0', size: '4.6 GB', languages: '140+ trained, 35+ supported', notes: '63 of 72 test messages right with the decision method, in about 5 seconds a message on two cores of an Intel Xeon at 2.10 GHz without a GPU; catches almost all spam, but is more often confidently wrong about ham than the default.',
	},
	{
		tier: 'small', ollama: 'qwen3.5:4b', huggingface: 'Qwen/Qwen3.5-4B', license: 'Apache-2.0', size: '3.3 GB', languages: '201', notes: 'The default. 65 of 72 test messages right and rarely confidently wrong about ham, in about 11 seconds a message with the decision method on two cores of an Intel Xeon at 2.10 GHz without a GPU (31 seconds writing its verdict).',
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
		tier: 'policy', ollama: 'gpt-oss-safeguard:20b', huggingface: 'openai/gpt-oss-safeguard-20b', license: 'Apache-2.0', size: '14 GB', languages: 'many', notes: 'A safety model that applies your own written policy; pair it with --llm-policy and --llm-method generate.',
	},
];

/**
 * Hosted decision models: they return a probability for each verdict from one
 * forward pass and write no text. All three take the same request format.
 */
export const DECISION_MODELS = [
	{
		provider: 'clef-flash', name: 'Cloudflare Clef Flash', license: 'Apache-2.0', weights: 'Cloudflare/clef-flash', notes: 'Qwen3.5 9B with a decision head, on Workers AI. Cloudflare reports 39 ms median latency and $0.09 per million input tokens, with a free daily allowance.',
	},
	{
		provider: 'clef', name: 'Cloudflare Clef', license: 'Apache-2.0', weights: 'Cloudflare/clef', notes: 'The 27B model, on Workers AI. Cloudflare reports the best phishing result of the three: 79.6% on PhishNChips, against 75.1% for Clef Flash and 62.6% for Jev.',
	},
	{
		provider: 'jev', name: 'TypeSafe Jev', license: 'proprietary', weights: null, notes: 'Closed weights; also on OpenRouter (--llm openrouter-jev). The cheapest, at $0.042 per million input tokens. TypeSafe has paused new sign-ups; existing accounts keep working.',
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
