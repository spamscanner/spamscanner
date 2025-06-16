import process from 'node:process';

const VOCABULARY_LIMIT = process.env.VOCABULARY_LIMIT !== undefined
	&& Number.isFinite(Number.parseInt(process.env.VOCABULARY_LIMIT, 10))
	? Number.parseInt(process.env.VOCABULARY_LIMIT, 10)
	: 20_000;

export default VOCABULARY_LIMIT;
