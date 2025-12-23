#!/usr/bin/env node
/**
 * Build CLI distribution with native modules
 * Creates a tarball containing the standalone CLI and all required native modules
 */
import {execSync} from 'node:child_process';
import {
	copyFileSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
const {version} = packageJson;

// Detect platform
const {platform} = process; // 'darwin', 'linux', 'win32'
const {arch} = process; // 'x64', 'arm64'

// Map to release naming
const platformMap = {
	darwin: 'darwin',
	linux: 'linux',
	win32: 'win',
};

const archMap = {
	x64: 'x64',
	arm64: 'arm64',
};

const targetPlatform = platformMap[platform] || platform;
const targetArch = archMap[arch] || arch;
const distName = `spamscanner-${targetPlatform}-${targetArch}`;

console.log(`Building CLI distribution for ${distName}...`);

// Create dist directory
const distDir = `dist/cli-dist/${distName}`;
rmSync(distDir, {recursive: true, force: true});
mkdirSync(distDir, {recursive: true});
mkdirSync(`${distDir}/native`, {recursive: true});

// Copy the standalone CLI
console.log('Copying standalone CLI...');
copyFileSync('dist/standalone/cli.cjs', `${distDir}/cli.cjs`);

// Find and copy native modules
console.log('Finding native modules...');

const nativeModules = [
	'node-snowball',
	're2',
	'@tensorflow/tfjs-node',
	'iconv',
];

/**
 * Find .node files for a given module
 */
function findNativeFiles(moduleName) {
	const nodeModulesPath = 'node_modules';
	const files = [];

	function searchDir(dir) {
		try {
			const entries = readdirSync(dir, {withFileTypes: true});
			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);
				if (entry.isDirectory()) {
					searchDir(fullPath);
				} else if (entry.name.endsWith('.node')) {
					files.push(fullPath);
				}
			}
		} catch {
			// Ignore errors
		}
	}

	// Search in node_modules and .pnpm
	const searchPaths = [
		path.join(nodeModulesPath, moduleName),
		path.join(nodeModulesPath, '.pnpm'),
	];

	for (const searchPath of searchPaths) {
		searchDir(searchPath);
	}

	// Filter to only include files related to this module
	return files.filter(f => f.includes(moduleName.replace('@', '').replace('/', '+')));
}

// Copy native modules
for (const moduleName of nativeModules) {
	const nativeFiles = findNativeFiles(moduleName);
	console.log(`  ${moduleName}: found ${nativeFiles.length} native files`);

	for (const file of nativeFiles) {
		const destName = path.basename(file);
		const destPath = `${distDir}/native/${destName}`;
		try {
			copyFileSync(file, destPath);
			console.log(`    Copied: ${destName}`);
		} catch (error) {
			console.warn(`    Warning: Could not copy ${file}: ${error.message}`);
		}
	}
}

// Create a wrapper script that sets up module resolution
const wrapperScript = `#!/usr/bin/env node
/**
 * SpamScanner CLI wrapper
 * Sets up native module paths before running the main CLI
 */
const path = require('node:path');
const Module = require('node:module');

// Get the directory where this script is located
const scriptDir = __dirname;
const nativeDir = path.join(scriptDir, 'native');

// Patch require to look for native modules in our native directory
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
  // Check if this is a native module request
  const nativeModules = ['node-snowball', 're2', '@tensorflow/tfjs-node', 'iconv'];

  for (const mod of nativeModules) {
    if (request === mod || request.startsWith(mod + '/')) {
      // Try to find the .node file in our native directory
      const nativeFile = path.join(nativeDir, request.replace(/[/@]/g, '_') + '.node');
      try {
        require('node:fs').accessSync(nativeFile);
        return nativeFile;
      } catch {
        // Fall through to original resolution
      }
    }
  }

  return originalResolveFilename.call(this, request, parent, isMain, options);
};

// Run the main CLI
require('./cli.cjs');
`;

writeFileSync(`${distDir}/spamscanner.cjs`, wrapperScript);

// Create shell wrapper for Unix
const shellWrapper = `#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec node "\${SCRIPT_DIR}/spamscanner.cjs" "$@"
`;
writeFileSync(`${distDir}/spamscanner`, shellWrapper);
execSync(`chmod +x ${distDir}/spamscanner`);

// Create batch wrapper for Windows
const batchWrapper = `@echo off
set SCRIPT_DIR=%~dp0
node "%SCRIPT_DIR%spamscanner.cjs" %*
`;
writeFileSync(`${distDir}/spamscanner.cmd`, batchWrapper);

// Create version file
writeFileSync(`${distDir}/VERSION`, version);

// Create tarball
console.log('Creating tarball...');
const tarballPath = `dist/cli-dist/${distName}.tar.gz`;

execSync(`tar -czf ${tarballPath} -C dist/cli-dist ${distName}`);

console.log(`\nDistribution created: ${tarballPath}`);
console.log('\nTo install:');
console.log(`  tar -xzf ${distName}.tar.gz -C /usr/local/lib/`);
console.log(`  ln -sf /usr/local/lib/${distName}/spamscanner /usr/local/bin/spamscanner`);
