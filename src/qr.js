import {Buffer} from 'node:buffer';
import {decodeImage, grayOf, pdfImages} from './image.js';

// QR codes (ISO/IEC 18004): finding one in an image and reading its text,
// for the links of QR codes in a message, which a person scans with a phone
// out of reach of the link checks of the mail it came in.

// Of each version (1 to 40) and level of error correction (L, M, Q and H),
// the blocks the codewords are split into, and their error correction
// codewords in all; and the codewords of each version.
const BLOCKS = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 1, 2, 2, 4, 1, 2, 4, 4, 2, 4, 4, 4, 2, 4, 6, 5, 2, 4, 6, 6, 2, 5, 8, 8, 4, 5, 8, 8, 4, 5, 8, 11, 4, 8, 10, 11, 4, 9, 12, 16, 4, 9, 16, 16, 6, 10, 12, 18, 6, 10, 17, 16, 6, 11, 16, 19, 6, 13, 18, 21, 7, 14, 21, 25, 8, 16, 20, 25, 8, 17, 23, 25, 9, 17, 23, 34, 9, 18, 25, 30, 10, 20, 27, 32, 12, 21, 29, 35, 12, 23, 34, 37, 12, 25, 34, 40, 13, 26, 35, 42, 14, 28, 38, 45, 15, 29, 40, 48, 16, 31, 43, 51, 17, 33, 45, 54, 18, 35, 48, 57, 19, 37, 51, 60, 19, 38, 53, 63, 20, 40, 56, 66, 21, 43, 59, 70, 22, 45, 62, 74, 24, 47, 65, 77, 25, 49, 68, 81];
const EC_CODEWORDS = [7, 10, 13, 17, 10, 16, 22, 28, 15, 26, 36, 44, 20, 36, 52, 64, 26, 48, 72, 88, 36, 64, 96, 112, 40, 72, 108, 130, 48, 88, 132, 156, 60, 110, 160, 192, 72, 130, 192, 224, 80, 150, 224, 264, 96, 176, 260, 308, 104, 198, 288, 352, 120, 216, 320, 384, 132, 240, 360, 432, 144, 280, 408, 480, 168, 308, 448, 532, 180, 338, 504, 588, 196, 364, 546, 650, 224, 416, 600, 700, 224, 442, 644, 750, 252, 476, 690, 816, 270, 504, 750, 900, 300, 560, 810, 960, 312, 588, 870, 1050, 336, 644, 952, 1110, 360, 700, 1020, 1200, 390, 728, 1050, 1260, 420, 784, 1140, 1350, 450, 812, 1200, 1440, 480, 868, 1290, 1530, 510, 924, 1350, 1620, 540, 980, 1440, 1710, 570, 1036, 1530, 1800, 570, 1064, 1590, 1890, 600, 1120, 1680, 1980, 630, 1204, 1770, 2100, 660, 1260, 1860, 2220, 720, 1316, 1950, 2310, 750, 1372, 2040, 2430];
const CODEWORDS = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815, 901, 991, 1085, 1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185, 2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706];
// (the level of error correction by the two bits of the format, as the
// tables index them: 01 is L, 00 M, 11 Q and 10 H)
const LEVEL = [1, 0, 3, 2];

// Arithmetic in GF(256), modulo x^8 + x^4 + x^3 + x^2 + 1
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
	EXP[i] = x;
	LOG[x] = i;
	x <<= 1;
	if (x & 0x1_00) {
		x ^= 0x1_1D;
	}
}

for (let i = 255; i < 512; i++) {
	EXP[i] = EXP[i - 255];
}

const multiply = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
// (of a value other than 0)
const inverse = a => EXP[255 - LOG[a]];
// (a polynomial of coefficients from the lowest power up, at x)
const evaluate = (poly, x) => poly.reduceRight((sum, coefficient) => multiply(sum, x) ^ coefficient, 0);

/**
 * Correct a block of codewords (data, then error correction codewords) in
 * place with its Reed-Solomon code, as QR codes make it (roots from 1):
 * whether it holds no errors, or as many as it can correct.
 * @param {number[]} block
 * @param {number} ecCount - its error correction codewords
 * @returns {boolean}
 */
export function correctBlock(block, ecCount) {
	const syndromes = Array.from({length: ecCount}, (_, i) => block.reduce((sum, codeword) => multiply(sum, EXP[i]) ^ codeword, 0));
	if (syndromes.every(syndrome => syndrome === 0)) {
		return true;
	}

	// (the error locator, by Berlekamp and Massey)
	let locator = [1];
	let previous = [1];
	let errors = 0;
	let shift = 1;
	let last = 1;
	for (let k = 0; k < ecCount; k++) {
		let discrepancy = syndromes[k];
		for (let i = 1; i <= errors; i++) {
			discrepancy ^= multiply(locator[i] ?? 0, syndromes[k - i]);
		}

		if (discrepancy === 0) {
			shift++;
			continue;
		}

		const scale = multiply(discrepancy, inverse(last));
		const next = [...locator];
		for (const [i, coefficient] of previous.entries()) {
			next[i + shift] = (next[i + shift] ?? 0) ^ multiply(scale, coefficient);
		}

		if (2 * errors <= k) {
			previous = locator;
			errors = k + 1 - errors;
			last = discrepancy;
			shift = 1;
		} else {
			shift++;
		}

		locator = next;
	}

	locator = locator.slice(0, locator.findLastIndex(coefficient => coefficient !== 0) + 1);

	// (where they are, by Chien's search, and how much, by Forney's)
	const n = block.length;
	const positions = [];
	for (let k = 0; k < n && positions.length < locator.length; k++) {
		if (evaluate(locator, EXP[(255 - ((n - 1 - k) % 255)) % 255]) === 0) {
			positions.push(k);
		}
	}

	if (positions.length !== locator.length - 1 || 2 * positions.length > ecCount) {
		return false;
	}

	const evaluator = Array.from({length: ecCount}, () => 0);
	for (let i = 0; i < ecCount; i++) {
		for (let j = 0; j < locator.length && i + j < ecCount; j++) {
			evaluator[i + j] ^= multiply(syndromes[i], locator[j]);
		}
	}

	// (a derivative of 0 is no error found: the block is checked again after)
	for (const k of positions) {
		const power = (n - 1 - k) % 255;
		const at = EXP[(255 - power) % 255];
		let derivative = 0;
		for (let i = 1; i < locator.length; i += 2) {
			derivative ^= multiply(locator[i], EXP[(LOG[at] * (i - 1)) % 255]);
		}

		block[k] ^= multiply(EXP[power], multiply(evaluate(evaluator, at), inverse(derivative)));
	}

	return Array.from({length: ecCount}, (_, i) => block.reduce((sum, codeword) => multiply(sum, EXP[i]) ^ codeword, 0)).every(syndrome => syndrome === 0);
}

// The 32 formats (two bits of the level of error correction and three of
// the mask) as written: a BCH code of them, masked
const FORMATS = Array.from({length: 32}, (_, data) => {
	let remainder = data << 10;
	for (let i = 14; i >= 10; i--) {
		if (remainder & (1 << i)) {
			remainder ^= 0x5_37 << (i - 10);
		}
	}

	return ((data << 10) | remainder) ^ 0x54_12;
});

const bitCount = value => {
	let count = 0;
	for (let v = value; v; v &= v - 1) {
		count++;
	}

	return count;
};

// The format nearest the bits read, within three bits, or -1
function formatOf(...readings) {
	let best = -1;
	let distance = 4;
	for (const [data, format] of FORMATS.entries()) {
		for (const reading of readings) {
			const d = bitCount(format ^ reading);
			if (d < distance) {
				distance = d;
				best = data;
			}
		}
	}

	return best;
}

const MASKS = [
	(i, j) => (i + j) % 2 === 0,
	i => i % 2 === 0,
	(i, j) => j % 3 === 0,
	(i, j) => (i + j) % 3 === 0,
	(i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
	(i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
	(i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
	(i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
];

// The rows (and columns) of the centers of a version's alignment patterns
function alignmentCenters(version) {
	if (version === 1) {
		return [];
	}

	const count = Math.floor(version / 7) + 2;
	const size = (version * 4) + 17;
	const interval = size === 145 ? 26 : Math.ceil((size - 13) / ((2 * count) - 2)) * 2;
	const centers = [size - 7];
	for (let i = 1; i < count - 1; i++) {
		centers.push(centers.at(-1) - interval);
	}

	centers.push(6);
	return centers.reverse();
}

// Which modules of a version are not data: finder patterns and their
// separators, format and version information, timing and alignment patterns
function functionModules(version) {
	const size = (version * 4) + 17;
	const reserved = new Uint8Array(size * size);
	const mark = (row, column) => {
		if (row >= 0 && row < size && column >= 0 && column < size) {
			reserved[(row * size) + column] = 1;
		}
	};

	// (each finder pattern and its separator, 8 modules square, and the
	//  format beside them: 9 at the top left)
	for (let i = 0; i < 9; i++) {
		for (let j = 0; j < 9; j++) {
			mark(i, j);
			if (j < 8) {
				mark(i, size - 1 - j);
				mark(size - 1 - j, i);
			}
		}
	}

	for (let i = 0; i < size; i++) {
		mark(6, i);
		mark(i, 6);
	}

	const centers = alignmentCenters(version);
	for (const row of centers) {
		for (const column of centers) {
			// (not where a finder pattern is)
			if ((row === 6 && (column === 6 || column === size - 7)) || (row === size - 7 && column === 6)) {
				continue;
			}

			for (let i = -2; i <= 2; i++) {
				for (let j = -2; j <= 2; j++) {
					mark(row + i, column + j);
				}
			}
		}
	}

	if (version >= 7) {
		for (let i = 0; i < 6; i++) {
			for (let j = size - 11; j < size - 8; j++) {
				mark(i, j);
				mark(j, i);
			}
		}
	}

	return reserved;
}

// The bits of a QR code's data, one at a time
class Bits {
	constructor(bytes) {
		this.bytes = bytes;
		this.offset = 0;
	}

	get left() {
		return (this.bytes.length * 8) - this.offset;
	}

	read(count) {
		let value = 0;
		for (let i = 0; i < count; i++) {
			const byte = this.bytes[this.offset >> 3];
			value = (value * 2) + ((byte >> (7 - (this.offset & 7))) & 1);
			this.offset++;
		}

		return value;
	}
}

const ALPHANUMERIC = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const shiftJis = new TextDecoder('shift_jis');

// The text of a QR code's data: its segments of digits, letters, bytes
// (read as UTF-8) and kanji, or null where they break off
function textOf(bytes, version) {
	const bits = new Bits(bytes);
	const sizes = version <= 9 ? [10, 9, 8, 8] : (version <= 26 ? [12, 11, 16, 10] : [14, 13, 16, 12]);
	const parts = [];
	while (bits.left >= 4) {
		const mode = bits.read(4);
		if (mode === 0) {
			break;
		}

		if (mode === 0b0111) {
			// (an ECI designator, of one to three bytes: read as UTF-8 all the same)
			const first = bits.read(8);
			bits.read((first & 0x80) === 0 ? 0 : ((first & 0xC0) === 0x80 ? 8 : 16));
			continue;
		}

		if (mode === 0b0011) {
			bits.read(16);
			continue;
		}

		if (mode === 0b0101 || mode === 0b1001) {
			bits.read(mode === 0b1001 ? 8 : 0);
			continue;
		}

		const index = [0b0001, 0b0010, 0b0100, 0b1000].indexOf(mode);
		if (index === -1 || bits.left < sizes[index]) {
			return null;
		}

		let count = bits.read(sizes[index]);
		switch (mode) {
			case 0b0001: {
				for (; count >= 3; count -= 3) {
					parts.push(String(bits.read(10)).padStart(3, '0'));
				}

				if (count > 0) {
					parts.push(String(bits.read(count === 2 ? 7 : 4)).padStart(count, '0'));
				}

				break;
			}

			case 0b0010: {
				for (; count >= 2; count -= 2) {
					const value = bits.read(11);
					parts.push(ALPHANUMERIC[Math.floor(value / 45)] + ALPHANUMERIC[value % 45]);
				}

				if (count === 1) {
					parts.push(ALPHANUMERIC[bits.read(6)]);
				}

				break;
			}

			case 0b0100: {
				if (bits.left < count * 8) {
					return null;
				}

				parts.push(Buffer.from(Array.from({length: count}, () => bits.read(8))).toString('utf8'));
				break;
			}

			default: {
				if (bits.left < count * 13) {
					return null;
				}

				const kanji = [];
				for (let i = 0; i < count; i++) {
					const value = bits.read(13);
					const assembled = (Math.floor(value / 0xC0) << 8) | (value % 0xC0);
					const code = assembled + (assembled < 0x1F_00 ? 0x81_40 : 0xC1_40);
					kanji.push(code >> 8, code & 0xFF);
				}

				parts.push(shiftJis.decode(Uint8Array.from(kanji)));
			}
		}
	}

	return parts.join('');
}

/**
 * How a version and level of error correction (0 to 3 for L, M, Q and H)
 * split a QR code's codewords: its codewords in all, the error correction
 * codewords of each block, and the data codewords of each block (the shorter
 * blocks first).
 * @param {number} version
 * @param {number} level
 * @returns {{total: number, ecPerBlock: number, blocks: number[]}}
 */
export function blockLayout(version, level) {
	const index = ((version - 1) * 4) + level;
	const total = CODEWORDS[version - 1];
	const blockCount = BLOCKS[index];
	const dataCount = total - EC_CODEWORDS[index];
	const short = Math.floor(dataCount / blockCount);
	const long = dataCount % blockCount;
	return {total, ecPerBlock: EC_CODEWORDS[index] / blockCount, blocks: Array.from({length: blockCount}, (_, b) => short + (b >= blockCount - long ? 1 : 0))};
}

/**
 * The text of a QR code, read from its modules (a square matrix of rows,
 * true for a dark module): its format, the data under its mask, each block
 * of codewords corrected, and the segments of its data. Null when it is
 * none, or holds more errors than its error correction corrects.
 * @param {boolean[][]|Uint8Array[]} grid
 * @returns {string|null}
 */
export function readMatrix(grid) {
	const size = grid.length;
	const version = (size - 17) / 4;
	if (!Number.isInteger(version) || version < 1 || version > 40) {
		return null;
	}

	const at = (row, column) => (grid[row][column] ? 1 : 0);
	// (the format, of either of its two copies)
	let first = 0;
	for (const [row, column] of [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]]) {
		first = (first << 1) | at(row, column);
	}

	let second = 0;
	for (let row = size - 1; row >= size - 7; row--) {
		second = (second << 1) | at(row, 8);
	}

	for (let column = size - 8; column < size; column++) {
		second = (second << 1) | at(8, column);
	}

	const format = formatOf(first, second);
	if (format === -1) {
		return null;
	}

	const level = LEVEL[format >> 3];
	const mask = MASKS[format & 7];
	const reserved = functionModules(version);
	// (the codewords, two columns at a time from the right, up and down in turn)
	const total = CODEWORDS[version - 1];
	const codewords = new Uint8Array(total);
	let bit = 0;
	let upward = true;
	for (let column = size - 1; column > 0; column -= 2) {
		if (column === 6) {
			column--;
		}

		for (let k = 0; k < size; k++) {
			const row = upward ? size - 1 - k : k;
			for (const j of [column, column - 1]) {
				if (reserved[(row * size) + j] || bit >= total * 8) {
					continue;
				}

				if (at(row, j) ^ (mask(row, j) ? 1 : 0)) {
					codewords[bit >> 3] |= 0x80 >> (bit & 7);
				}

				bit++;
			}
		}

		upward = !upward;
	}

	// (the blocks, interleaved: their data codewords in turn, then their error
	//  correction codewords)
	const {ecPerBlock, blocks: layout} = blockLayout(version, level);
	const blocks = layout.map(data => ({data, codewords: []}));
	const short = layout[0];
	let read = 0;
	for (let i = 0; i <= short; i++) {
		for (const block of blocks) {
			if (i < block.data) {
				block.codewords.push(codewords[read++]);
			}
		}
	}

	for (let i = 0; i < ecPerBlock; i++) {
		for (const block of blocks) {
			block.codewords.push(codewords[read++]);
		}
	}

	const data = [];
	for (const block of blocks) {
		if (!correctBlock(block.codewords, ecPerBlock)) {
			return null;
		}

		data.push(...block.codewords.slice(0, block.data));
	}

	return textOf(data, version);
}

// Whether five runs read as a finder pattern's, 1:1:3:1:1
function finderRatio(runs) {
	const total = runs.reduce((sum, run) => sum + run, 0);
	if (total < 7) {
		return false;
	}

	const module = total / 7;
	const variance = module / 1.5;
	return Math.abs(module - runs[0]) < variance && Math.abs(module - runs[1]) < variance && Math.abs((3 * module) - runs[2]) < 3 * variance && Math.abs(module - runs[3]) < variance && Math.abs(module - runs[4]) < variance;
}

// The center, along a column or a row through a point, of a finder pattern
// there, and its size in modules, or null
function crossCheck({dark, width, height}, x, y, vertical) {
	const get = offset => (vertical ? dark[((y + offset) * width) + x] : dark[(y * width) + x + offset]);
	const limit = vertical ? height : width;
	const position = vertical ? y : x;
	// (from a light pixel, no dark run in the middle: no finder pattern)
	const runs = [0, 0, 0, 0, 0];
	let i = 0;
	while (position + i >= 0 && get(i)) {
		runs[2]++;
		i--;
	}

	while (position + i >= 0 && !get(i)) {
		runs[1]++;
		i--;
	}

	while (position + i >= 0 && get(i)) {
		runs[0]++;
		i--;
	}

	i = 1;
	while (position + i < limit && get(i)) {
		runs[2]++;
		i++;
	}

	while (position + i < limit && !get(i)) {
		runs[3]++;
		i++;
	}

	while (position + i < limit && get(i)) {
		runs[4]++;
		i++;
	}

	if (!finderRatio(runs)) {
		return null;
	}

	const end = position + i - runs[4] - runs[3];
	return {center: end - (runs[2] / 2), module: runs.reduce((sum, run) => sum + run, 0) / 7};
}

// The finder patterns of an image of dark pixels: by the rows each is found
// in (`count`), its center and the size of a module
function findersOf(dark, width, height) {
	const found = [];
	for (let y = 0; y < height; y++) {
		const runs = [];
		let start = 0;
		for (let x = 1; x <= width; x++) {
			if (x === width || dark[(y * width) + x] !== dark[(y * width) + start]) {
				runs.push({dark: dark[(y * width) + start], start, length: x - start});
				start = x;
			}
		}

		for (let r = 0; r + 4 < runs.length; r++) {
			if (!runs[r].dark || !finderRatio(runs.slice(r, r + 5).map(run => run.length))) {
				continue;
			}

			const x = Math.floor(runs[r + 2].start + (runs[r + 2].length / 2));
			const vertical = crossCheck({dark, width, height}, x, y, true);
			if (!vertical) {
				continue;
			}

			const horizontal = crossCheck({dark, width, height}, x, Math.floor(vertical.center), false);
			if (!horizontal) {
				continue;
			}

			const center = {x: horizontal.center, y: vertical.center, module: (vertical.module + horizontal.module) / 2};
			const same = found.find(finder => Math.abs(finder.x - center.x) < finder.module * 2 && Math.abs(finder.y - center.y) < finder.module * 2);
			if (same) {
				same.x = ((same.x * same.count) + center.x) / (same.count + 1);
				same.y = ((same.y * same.count) + center.y) / (same.count + 1);
				same.module = ((same.module * same.count) + center.module) / (same.count + 1);
				same.count++;
			} else if (found.length < 64) {
				found.push({...center, count: 1});
			}
		}
	}

	return found;
}

// Whether a finder pattern found is one, module by module: a dark ring 7
// modules square, a light one in it, a dark square of 3 in the middle, and
// light around it (its separator, or the margin), as data seldom is
function isFinder({dark, width, height}, {x, y, module}) {
	let matches = 0;
	for (let dy = -4; dy <= 4; dy++) {
		for (let dx = -4; dx <= 4; dx++) {
			const ring = Math.max(Math.abs(dx), Math.abs(dy));
			const px = Math.floor(x + (dx * module));
			const py = Math.floor(y + (dy * module));
			const value = px >= 0 && py >= 0 && px < width && py < height ? dark[(py * width) + px] : 0;
			if (value === (ring === 4 || ring === 2 ? 0 : 1)) {
				matches++;
			}
		}
	}

	return matches >= 75;
}

const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

// Three finder patterns placed as a QR code's are, top left, top right and
// bottom left, or null
function cornersOf(finders) {
	// (Node 18 has no toSorted)
	const candidates = [...finders].sort((a, b) => b.count - a.count).slice(0, 10);
	let best = null;
	let bestError = Infinity;
	for (let i = 0; i < candidates.length; i++) {
		for (let j = i + 1; j < candidates.length; j++) {
			for (let k = j + 1; k < candidates.length; k++) {
				const three = [candidates[i], candidates[j], candidates[k]];
				const modules = three.map(finder => finder.module);
				if (Math.max(...modules) > Math.min(...modules) * 1.5) {
					continue;
				}

				// (the corner is the one opposite the longest side)
				const sides = [[1, 2], [0, 2], [0, 1]].map(([a, b]) => distance(three[a], three[b]));
				const corner = sides.indexOf(Math.max(...sides));
				const [a, b] = [0, 1, 2].filter(index => index !== corner).map(index => three[index]);
				const topLeft = three[corner];
				const legA = distance(topLeft, a);
				const legB = distance(topLeft, b);
				const error = (Math.abs(legA - legB) / Math.max(legA, legB)) + Math.abs((Math.hypot(legA, legB) / sides[corner]) - 1);
				// (the finders found in the most rows, as a QR code's are, at least
				//  14 modules apart, as they are in the smallest)
				const score = error - three.reduce((sum, finder) => sum + finder.count, 0);
				if (error < 0.2 && Math.min(legA, legB) >= 13 * Math.max(...modules) && score < bestError) {
					// (top right to the right of top left, as seen from it, and
					//  bottom left below)
					const cross = ((a.x - topLeft.x) * (b.y - topLeft.y)) - ((a.y - topLeft.y) * (b.x - topLeft.x));
					best = cross > 0 ? {topLeft, topRight: a, bottomLeft: b} : {topLeft, topRight: b, bottomLeft: a};
					bestError = score;
				}
			}
		}
	}

	return best;
}

// The modules of a QR code of a size at the corners found, sampled at the
// center of each in the image
function sample({dark, width, height}, {topLeft, topRight, bottomLeft}, size) {
	const right = {x: (topRight.x - topLeft.x) / (size - 7), y: (topRight.y - topLeft.y) / (size - 7)};
	const down = {x: (bottomLeft.x - topLeft.x) / (size - 7), y: (bottomLeft.y - topLeft.y) / (size - 7)};
	return Array.from({length: size}, (_, row) => {
		const line = new Uint8Array(size);
		for (let column = 0; column < size; column++) {
			const u = column - 3;
			const v = row - 3;
			// (the nearest pixel at the edge, past it)
			const x = Math.min(width - 1, Math.max(0, Math.floor(topLeft.x + (u * right.x) + (v * down.x))));
			const y = Math.min(height - 1, Math.max(0, Math.floor(topLeft.y + (u * right.y) + (v * down.y))));
			line[column] = dark[(y * width) + x];
		}

		return line;
	});
}

// The threshold between dark and light of a grayscale image, by Otsu's
// method
function thresholdOf(gray) {
	const histogram = new Float64Array(256);
	for (const value of gray) {
		histogram[value]++;
	}

	let sum = 0;
	for (let i = 0; i < 256; i++) {
		sum += i * histogram[i];
	}

	let background = 0;
	let backgroundSum = 0;
	let best = 0;
	let threshold = 128;
	for (let i = 0; i < 256; i++) {
		background += histogram[i];
		if (background === 0) {
			continue;
		}

		const foreground = gray.length - background;
		if (foreground === 0) {
			break;
		}

		backgroundSum += i * histogram[i];
		const between = background * foreground * (((backgroundSum / background) - ((sum - backgroundSum) / foreground)) ** 2);
		if (between > best) {
			best = between;
			threshold = i;
		}
	}

	return threshold;
}

/**
 * The text of a QR code in a grayscale image (a byte a pixel, 0 for black),
 * dark on light or light on dark, upright or turned, or null: its three
 * finder patterns, the size they make, and the modules sampled between them
 * (an image taken square on, as a QR code in a message is drawn).
 * @param {{width: number, height: number, gray: Uint8Array}} image
 * @returns {string|null}
 */
export function decodeQr({width, height, gray}) {
	if (!Number.isInteger(width) || !Number.isInteger(height) || width < 21 || height < 21 || !gray || gray.length < width * height) {
		return null;
	}

	const threshold = thresholdOf(gray.subarray(0, width * height));
	for (const inverted of [false, true]) {
		const dark = new Uint8Array(width * height);
		for (let i = 0; i < dark.length; i++) {
			dark[i] = (gray[i] <= threshold) === !inverted ? 1 : 0;
		}

		const corners = cornersOf(findersOf(dark, width, height).filter(finder => isFinder({dark, width, height}, finder)));
		if (!corners) {
			continue;
		}

		const module = (corners.topLeft.module + corners.topRight.module + corners.bottomLeft.module) / 3;
		const across = ((distance(corners.topLeft, corners.topRight) + distance(corners.topLeft, corners.bottomLeft)) / 2 / module) + 7;
		// (the size nearest, of the form 4n + 17, and those beside it)
		const estimate = (Math.round((across - 17) / 4) * 4) + 17;
		for (const size of [estimate, estimate + 4, estimate - 4]) {
			const grid = sample({dark, width, height}, corners, size);
			// (and its mirror image)
			const text = readMatrix(grid) ?? readMatrix(grid.map((line, row) => line.map((_, column) => grid[column][row])));
			if (text !== null) {
				return text;
			}
		}
	}

	return null;
}

// A cell of a grid drawn in HTML: a table cell, <div> or <span> with a
// background color and a width or height of a few pixels, as a QR code drawn
// without an image is ("<td width="4" height="4" bgcolor="#000000">")
const CELL_START = /<(?:td|th|div|span)\b/gi;
const CELL_COLOR = /\bbgcolor\s*=|background(?:-color)?\s*:/i;
const CELL_SIZE = /\b(?:width|height)\s*[:=][\s"']*(\d{1,3})(?:\.\d+)?(?:px)?\b/i;
// (a QR code has at least 21 by 21 modules)
const QR_CELLS = 21 * 21;
// A line of a QR code drawn with block characters ("█▀▄"), and spaces
const BLOCK_LINE = /^[\u2580-\u259F\u25A0\u25A1 \u00A0\u3000]{21,}$/;
const BLOCK = /[\u2580-\u259F\u25A0]/g;

/**
 * Whether a message draws a QR code without an image, as phishing does to
 * hide its link from scanners that read images: a grid of at least 21 by 21
 * cells of HTML with background colors and at most 12 pixels wide or high,
 * or ten lines of text or more, one after another, of 21 block characters
 * ("█", "▀", "▄") and spaces or more, a third of them blocks. Reads at most
 * `maxLength` characters of each text, and twice as many of the HTML.
 * @param {string} html
 * @param {string|string[]} texts - the text, and the text the HTML shows
 * @param {object} [options]
 * @param {number} [options.maxLength]
 * @returns {boolean}
 */
export function drawnQrCode(html, texts, {maxLength = 1_000_000} = {}) {
	if (typeof html === 'string' && html.length >= QR_CELLS * 10) {
		const read = html.slice(0, maxLength * 2);
		let cells = 0;
		// (each tag read once, up to its ">", of 400 characters at most)
		CELL_START.lastIndex = 0;
		let start;
		while ((start = CELL_START.exec(read)) !== null) {
			const end = read.indexOf('>', start.index);
			if (end === -1) {
				break;
			}

			CELL_START.lastIndex = end + 1;
			const tag = read.slice(start.index, Math.min(end, start.index + 400));
			const size = CELL_SIZE.exec(tag);
			if (size && Number(size[1]) <= 12 && CELL_COLOR.test(tag) && ++cells >= QR_CELLS) {
				return true;
			}
		}
	}

	return [texts].flat().some(text => typeof text === 'string' && blockLines(text.slice(0, maxLength)) >= 10);
}

// The most lines one after another of a QR code drawn with block characters
// (see BLOCK_LINE), up to ten
function blockLines(text) {
	let lines = 0;
	for (const line of text.split('\n')) {
		const trimmed = line.trim();
		lines = BLOCK_LINE.test(trimmed) && (trimmed.match(BLOCK)?.length ?? 0) * 3 >= trimmed.length ? lines + 1 : 0;
		if (lines >= 10) {
			break;
		}
	}

	return lines;
}

// Whether a cell's background color is dark ("#000", "black", "rgb(0,0,0)")
function darkColor(tag) {
	const value = /\bbgcolor\s*=[\s"']*([#\w]{1,20})|background(?:-color)?\s*:\s*([#\w]{1,20}(?:\([\d\s,.%]{1,40}\))?)/i.exec(tag);
	const color = (value?.[1] ?? value?.[2] ?? '').toLowerCase();
	if (color === 'black') {
		return true;
	}

	const hex = /^#([\da-f]{3}|[\da-f]{6})$/.exec(color)?.[1];
	const rgb = hex ? (hex.length === 3 ? [...hex].map(digit => Number.parseInt(digit + digit, 16)) : [0, 2, 4].map(i => Number.parseInt(hex.slice(i, i + 2), 16))) : /^rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(color.replaceAll(' ', ''))?.slice(1).map(Number);
	return Boolean(rgb) && (rgb[0] * 0.299) + (rgb[1] * 0.587) + (rgb[2] * 0.114) < 128;
}

// A grayscale image of rows of modules (true for dark), four pixels a module
// with a margin of four modules, as qr.js reads one
function moduleImage(rows, width, height = 1) {
	const columns = Math.max(...rows.map(row => row.length)) * width;
	const scale = 4;
	const imageWidth = (columns + 8) * scale;
	const imageHeight = ((rows.length * height) + 8) * scale;
	const gray = new Uint8Array(imageWidth * imageHeight).fill(255);
	for (const [r, row] of rows.entries()) {
		for (const [c, dark] of row.entries()) {
			if (!dark) {
				continue;
			}

			for (let y = ((r * height) + 4) * scale; y < (((r + 1) * height) + 4) * scale; y++) {
				gray.fill(0, (y * imageWidth) + (((c * width) + 4) * scale), (y * imageWidth) + ((((c + 1) * width) + 4) * scale));
			}
		}
	}

	return {width: imageWidth, height: imageHeight, gray};
}

/**
 * The QR codes a message draws without an image (see drawnQrCode), as
 * images to read: the rows of a table of at least 21 colored cells, each
 * cell a module, and the lines of block characters, each a module wide and
 * two high ("▀" the top one, "▄" the bottom one), or two modules wide.
 * @param {string} html
 * @param {string[]} texts
 * @param {object} [options]
 * @param {number} [options.maxLength]
 * @returns {Array<{width: number, height: number, gray: Uint8Array}>}
 */
export function drawnQrImages(html, texts, {maxLength = 1_000_000} = {}) {
	const images = [];
	if (typeof html === 'string' && html.length >= QR_CELLS * 10) {
		const read = html.slice(0, maxLength * 2);
		const rows = [];
		const tag = /<(tr|td|th)\b/gi;
		let start;
		while ((start = tag.exec(read)) !== null && rows.length < 400) {
			const end = read.indexOf('>', start.index);
			if (end === -1) {
				break;
			}

			tag.lastIndex = end + 1;
			if (start[1].toLowerCase() === 'tr') {
				rows.push([]);
			} else if (rows.length > 0 && rows.at(-1).length < 400) {
				rows.at(-1).push(darkColor(read.slice(start.index, Math.min(end, start.index + 400))));
			}
		}

		// (the rows of the grid: 21 cells or more, as many in each)
		let grid = [];
		for (const row of rows) {
			if (row.length >= 21 && (grid.length === 0 || row.length === grid[0].length)) {
				grid.push(row);
			} else if (grid.length < 21) {
				grid = row.length >= 21 ? [row] : [];
			} else {
				break;
			}
		}

		if (grid.length >= 21) {
			images.push(moduleImage(grid, 1));
		}
	}

	for (const text of [texts].flat()) {
		if (typeof text !== 'string' || blockLines(text.slice(0, maxLength)) < 10) {
			continue;
		}

		// (of the lines of blocks, without the indentation they share)
		const lines = text.slice(0, maxLength).split('\n').map(line => line.trimEnd()).filter(line => BLOCK_LINE.test(line.trim()));
		const indent = Math.min(...lines.map(line => line.length - line.trimStart().length));
		const halves = [];
		for (const line of lines.map(line => line.slice(indent))) {
			halves.push([...line].map(char => char !== ' ' && char !== '\u00A0' && char !== '\u3000' && char !== '\u2584'), [...line].map(char => char !== ' ' && char !== '\u00A0' && char !== '\u3000' && char !== '\u2580'));
		}

		images.push(moduleImage(halves, 1), moduleImage(halves, 2));
		if (images.length >= 4) {
			break;
		}
	}

	return images;
}

// Images read for QR codes in a message at most, pixels in all, and bytes of
// each image and PDF file
const MAX_IMAGES = 10;
const MAX_TOTAL_PIXELS = 6_000_000;
const MAX_IMAGE_BYTES = 10_000_000;
const MAX_PDF_BYTES = 20_000_000;

// Whether a buffer is an image (PNG, GIF, JPEG or WebP) or a PDF file, by
// its first bytes
const isImage = buffer => buffer.length > 12 && (buffer.readUInt32BE(0) === 0x89_50_4E_47 || buffer.toString('latin1', 0, 4) === 'GIF8' || (buffer[0] === 0xFF && buffer[1] === 0xD8) || (buffer.toString('latin1', 0, 4) === 'RIFF' && buffer.toString('latin1', 8, 12) === 'WEBP'));
// (a character of base64, or a space or line break inside it)
const isBase64 = code => (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 47 && code <= 57) || code === 43 || code === 61 || code === 32 || (code >= 9 && code <= 13);
const isPdf = buffer => buffer.length > 8 && buffer.toString('latin1', 0, 1024).includes('%PDF-');

/**
 * The images and PDF files of a message to read QR codes from: its
 * attachments (inline ones too, and those of attached messages, as
 * given) by their content, and the images its HTML holds in data: URLs,
 * at most MAX_IMAGES of each, each no bigger than MAX_IMAGE_BYTES (a PDF
 * file MAX_PDF_BYTES).
 * @param {Array<{content?: Buffer}>} attachments
 * @param {string} html
 * @returns {{images: Buffer[], pdfs: Buffer[]}}
 */
export function qrSources(attachments, html) {
	const images = [];
	const pdfs = [];
	for (const {content} of Array.isArray(attachments) ? attachments : []) {
		if (!Buffer.isBuffer(content)) {
			continue;
		}

		if (images.length < MAX_IMAGES && content.length <= MAX_IMAGE_BYTES && isImage(content)) {
			images.push(content);
		} else if (pdfs.length < MAX_IMAGES && content.length <= MAX_PDF_BYTES && isPdf(content)) {
			pdfs.push(content);
		}
	}

	if (typeof html !== 'string') {
		return {images, pdfs};
	}

	// (of data: URLs, by their base64 up to the first character that is none)
	let offset = 0;
	while (images.length < MAX_IMAGES) {
		const start = html.indexOf('data:image/', offset);
		if (start === -1) {
			break;
		}

		const comma = html.indexOf(',', start);
		offset = start + 11;
		if (comma === -1 || comma - start > 60 || !/;base64$/i.test(html.slice(start, comma))) {
			continue;
		}

		let end = comma + 1;
		while (end < html.length && end - comma <= (MAX_IMAGE_BYTES / 3) * 4 && isBase64(html.codePointAt(end))) {
			end++;
		}

		offset = end;
		const content = Buffer.from(html.slice(comma + 1, end).replaceAll(/\s+/g, ''), 'base64');
		if (isImage(content)) {
			images.push(content);
		}
	}

	return {images, pdfs};
}

// The image an image decoder outside reads (see the decodeImage option), by
// the time left, or null
async function decodeOutside(decode, buffer, deadline) {
	let timer;
	const decoded = await Promise.race([
		(async () => {
			try {
				return await decode(buffer);
			} catch {
				return null;
			}
		})(),
		new Promise(resolve => {
			timer = setTimeout(resolve, Math.max(0, deadline - Date.now()), null);
		}),
	]);
	clearTimeout(timer);
	return decoded ? grayOf(decoded) : null;
}

/**
 * The texts of the QR codes of a message, at most ten, one a QR code:
 * of the images drawn without one (see drawnQrImages), of its images and
 * PDF files (see qrSources), each read with decodeImage (image.js), or else
 * with `decode` (an image decoder outside, for WebP and progressive JPEG)
 * where one is given; up to MAX_IMAGES images and MAX_TOTAL_PIXELS pixels in
 * all, and no image started after `deadline` (a time as Date.now() gives).
 * @param {{images?: Buffer[], pdfs?: Buffer[], drawn?: object[]}} sources
 * @param {object} [options]
 * @param {Function|null} [options.decode]
 * @param {number} [options.deadline]
 * @returns {Promise<string[]>}
 */
export async function qrCodesOf({images = [], pdfs = [], drawn = []} = {}, {decode = null, deadline = Infinity} = {}) {
	const texts = new Set();
	let pixels = 0;
	let read = 0;
	const take = image => {
		if (!image || pixels + (image.width * image.height) > MAX_TOTAL_PIXELS) {
			return;
		}

		pixels += image.width * image.height;
		read++;
		const text = decodeQr(image);
		if (text) {
			texts.add(text);
		}
	};

	const open = () => read < MAX_IMAGES && Date.now() < deadline;
	for (const image of drawn) {
		if (open()) {
			take(image);
		}
	}

	for (const buffer of images) {
		if (!open()) {
			break;
		}

		// eslint-disable-next-line no-await-in-loop
		take(decodeImage(buffer) ?? (typeof decode === 'function' ? await decodeOutside(decode, buffer, deadline) : null));
	}

	for (const buffer of pdfs) {
		for (const image of open() ? pdfImages(buffer, {maxImages: MAX_IMAGES - read}) : []) {
			if (open()) {
				take(image);
			}
		}
	}

	return [...texts].slice(0, 10);
}
