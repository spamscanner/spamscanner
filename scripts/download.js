// Downloads of dataset files pinned to a revision and a SHA-256, for
// scripts/train-model.js and scripts/llm-benchmark.js.
//
// A file already there is reused only when its SHA-256 is the pinned one, and
// every file is written under a .part name and renamed when complete, so an
// interrupted run leaves no truncated file behind to be reused.
import {createHash} from 'node:crypto';
import {
	createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync,
} from 'node:fs';
import path from 'node:path';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';

// Write a file under a temporary name with write(part), then rename it into
// place, so a failure part way leaves nothing at target.
export async function writeAtomically(target, write) {
	const part = `${target}.part`;
	try {
		await write(part);
		renameSync(part, target);
	} catch (error) {
		rmSync(part, {force: true});
		throw error;
	}
}

// The SHA-256 of a file, as hex.
export async function sha256Of(file) {
	const hash = createHash('sha256');
	for await (const chunk of createReadStream(file)) {
		hash.update(chunk);
	}

	return hash.digest('hex');
}

// Download {url, sha256, file} into directory, unless the pinned file is
// already there; resolves with its path. With offline, a missing or different
// file is an error. derived lists files made from it, removed with it when it
// is downloaded again.
export async function download({url, sha256, file}, directory, {offline = false, derived = []} = {}) {
	const target = path.join(directory, file);
	if (existsSync(target)) {
		const actual = await sha256Of(target);
		if (actual === sha256) {
			return target;
		}

		if (offline) {
			throw new Error(`${target}: SHA-256 ${actual}, expected ${sha256}`);
		}

		console.error(`${target}: SHA-256 ${actual}, expected ${sha256}; downloading it again`);
		for (const stale of new Set([target, ...derived])) {
			rmSync(stale, {force: true});
		}
	}

	if (offline) {
		throw new Error(`${target} is missing`);
	}

	console.error(`Downloading ${url}`);
	const response = await fetch(url);
	if (!response.ok) {
		throw new Error(`${url}: HTTP ${response.status}`);
	}

	mkdirSync(directory, {recursive: true});
	await writeAtomically(target, async part => {
		const hash = createHash('sha256');
		await pipeline(Readable.fromWeb(response.body), async function * (chunks) {
			for await (const chunk of chunks) {
				hash.update(chunk);
				yield chunk;
			}
		}, createWriteStream(part));
		const actual = hash.digest('hex');
		if (actual !== sha256) {
			throw new Error(`${url}: SHA-256 ${actual}, expected ${sha256}`);
		}
	});
	return target;
}
