// The installer, scripts/install.sh, run against a fake release in a local directory.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFile, execFileSync} from 'node:child_process';
import {
	existsSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {after, describe, it} from 'node:test';
import {fileURLToPath} from 'node:url';
import {temporaryDirectory} from './helpers/index.js';

const script = fileURLToPath(new URL('../scripts/install.sh', import.meta.url));
const platform = {linux: 'linux', darwin: 'darwin'}[process.platform];
const arch = {x64: 'x64', arm64: 'arm64'}[process.arch];
const artifact = `spamscanner-${platform}-${arch}`;

function has(command) {
	try {
		execFileSync('sh', ['-c', `command -v ${command}`], {stdio: 'ignore'});
		return true;
	} catch {
		return false;
	}
}

const skip = !platform || !arch || !has('bash') || !has('curl') ? 'needs bash, curl, and Linux or macOS on x64 or arm64' : false;
const sha256 = data => createHash('sha256').update(data).digest('hex');

// A release directory with the binary (a shell script here) and SHA256SUMS.
function release(dir, {binary = '#!/bin/sh\necho "spamscanner 1.2.3"\n', sums} = {}) {
	mkdirSync(dir, {recursive: true});
	writeFileSync(path.join(dir, artifact), binary);
	if (sums !== null) {
		writeFileSync(path.join(dir, 'SHA256SUMS'), sums ?? `${sha256(binary)}  ${artifact}\n`);
	}

	return dir;
}

// Run the installer, as `bash install.sh` or with the script on standard input.
function install(releases, binDir, {source = readFileSync(script, 'utf8'), env = {}} = {}) {
	return new Promise(resolve => {
		const child = execFile('bash', [], {
			env: {
				...process.env, SPAMSCANNER_RELEASES_URL: `file://${releases}`, SPAMSCANNER_BIN_DIR: binDir, ...env,
			},
		}, (error, stdout, stderr) => {
			resolve({code: error ? error.code : 0, output: stdout + stderr});
		});
		child.stdin.end(source);
	});
}

describe('install.sh', {skip}, () => {
	const dir = temporaryDirectory();
	after(() => rmSync(dir, {recursive: true, force: true}));

	it('installs a binary that matches SHA256SUMS and runs', async () => {
		const bin = path.join(dir, 'ok-bin');
		mkdirSync(bin);
		const {code, output} = await install(release(path.join(dir, 'ok')), bin);
		assert.equal(code, 0, output);
		assert.match(output, /Successfully installed spamscanner 1\.2\.3/);
		assert.ok(existsSync(path.join(bin, 'spamscanner')));
	});

	it('creates the directory when it does not exist', async () => {
		const bin = path.join(dir, 'new-bin', 'nested');
		const {code, output} = await install(release(path.join(dir, 'new')), bin);
		assert.equal(code, 0, output);
		assert.match(output, /Successfully installed spamscanner 1\.2\.3/);
		assert.ok(existsSync(path.join(bin, 'spamscanner')));
	});

	it('creates the directory with sudo when it cannot create it itself', async () => {
		// A mkdir that fails unless run by this sudo, which logs its command and runs it.
		const stubs = path.join(dir, 'sudo-stubs');
		mkdirSync(stubs);
		const log = path.join(dir, 'sudo.log');
		writeFileSync(path.join(stubs, 'sudo'), `#!/bin/sh\necho "$1" >> "${log}"\nSUDO_STUB=1 exec "$@"\n`, {mode: 0o755});
		writeFileSync(path.join(stubs, 'mkdir'), '#!/bin/sh\n[ -n "$SUDO_STUB" ] || exit 1\nexec /bin/mkdir "$@"\n', {mode: 0o755});
		const bin = path.join(dir, 'sudo-bin', 'nested');
		const {code, output} = await install(release(path.join(dir, 'sudo')), bin, {env: {PATH: `${stubs}:${process.env.PATH}`}});
		assert.equal(code, 0, output);
		assert.match(output, /Requesting sudo access/);
		assert.equal(readFileSync(log, 'utf8'), 'mkdir\nmv\n');
		assert.ok(existsSync(path.join(bin, 'spamscanner')));
	});

	it('installs nothing when the checksum does not match, is missing, or SHA256SUMS is absent', async () => {
		const cases = [
			[{sums: `${sha256('other')}  ${artifact}\n`}, /Checksum mismatch/],
			[{sums: `${sha256('other')}  spamscanner-other\n`}, /SHA256SUMS has no checksum for/],
			[{sums: null}, /Could not download SHA256SUMS/],
		];
		for (const [index, [options, expected]] of cases.entries()) {
			const bin = path.join(dir, `bad-bin-${index}`);
			mkdirSync(bin);

			const {code, output} = await install(release(path.join(dir, `bad-${index}`), options), bin);
			assert.equal(code, 1, output);
			assert.match(output, expected);
			assert.ok(!existsSync(path.join(bin, 'spamscanner')));
		}
	});

	it('says so when the binary is missing from the release', async () => {
		const empty = path.join(dir, 'empty');
		mkdirSync(empty);
		const {code, output} = await install(empty, dir);
		assert.equal(code, 1);
		assert.match(output, new RegExp(`Could not download ${artifact}`));
	});

	it('fails when the installed binary does not run', async () => {
		const bin = path.join(dir, 'broken-bin');
		mkdirSync(bin);
		const {code, output} = await install(release(path.join(dir, 'broken'), {binary: '#!/bin/sh\nexit 3\n'}), bin);
		assert.equal(code, 1);
		assert.match(output, /was installed but does not run/);
	});

	it('runs nothing when the script is cut short', async () => {
		const bin = path.join(dir, 'cut-bin');
		mkdirSync(bin);
		const source = readFileSync(script, 'utf8');
		const {code, output} = await install(release(path.join(dir, 'cut')), bin, {source: source.slice(0, source.lastIndexOf('main "$@"'))});
		assert.equal(code, 0, output);
		assert.equal(output, '');
		assert.ok(!existsSync(path.join(bin, 'spamscanner')));
	});

	it('stops on musl libc', {skip: platform === 'linux' ? false : 'Linux only'}, async () => {
		const stubs = path.join(dir, 'stubs');
		mkdirSync(stubs);
		writeFileSync(path.join(stubs, 'ldd'), '#!/bin/sh\necho "musl libc (x86_64)" >&2\nexit 1\n', {mode: 0o755});
		const bin = path.join(dir, 'musl-bin');
		mkdirSync(bin);
		const {code, output} = await install(release(path.join(dir, 'musl')), bin, {env: {PATH: `${stubs}:${process.env.PATH}`}});
		assert.equal(code, 1);
		assert.match(output, /musl libc/);
		assert.ok(!existsSync(path.join(bin, 'spamscanner')));
	});
});
