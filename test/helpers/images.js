import {Buffer} from 'node:buffer';
import {deflateSync} from 'node:zlib';
import {blockLayout} from '../../src/qr.js';

// QR codes and images made for tests: a QR code encoder (any version, level
// and mask, of byte segments or of bits given), and writers of PNG, GIF and
// PDF files, as mail carries them.

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

// The error correction codewords of a block, as a QR code computes them
function errorCorrection(data, count) {
	let generator = [1];
	for (let i = 0; i < count; i++) {
		const next = Array.from({length: generator.length + 1}, () => 0);
		for (const [j, coefficient] of generator.entries()) {
			next[j] ^= coefficient;
			next[j + 1] ^= multiply(coefficient, EXP[i]);
		}

		generator = next;
	}

	const remainder = [...data, ...Array.from({length: count}, () => 0)];
	for (let i = 0; i < data.length; i++) {
		const factor = remainder[i];
		if (factor) {
			for (let j = 1; j < generator.length; j++) {
				remainder[i + j] ^= multiply(generator[j], factor);
			}
		}
	}

	return remainder.slice(data.length);
}

const LEVELS = {
	L: [0, 0b01], M: [1, 0b00], Q: [2, 0b11], H: [3, 0b10],
};
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

function bch(value, generator, degree) {
	let remainder = value << degree;
	const top = Math.floor(Math.log2(generator));
	for (let i = degree + 14; i >= top; i--) {
		if (remainder & (1 << i)) {
			remainder ^= generator << (i - top);
		}
	}

	return (value << degree) | remainder;
}

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

/**
 * The bits of a byte segment of text (UTF-8) for a version.
 * @param {string} text
 * @param {number} version
 * @returns {Array<[number, number]>} values and their lengths in bits
 */
export function byteSegment(text, version) {
	const bytes = Buffer.from(text);
	return [[0b0100, 4], [bytes.length, version < 10 ? 8 : 16], ...[...bytes].map(byte => [byte, 8])];
}

/**
 * A QR code's modules (rows of 0 and 1): of a text in one byte segment, or
 * of `bits` given (values and their lengths), ended, padded and with error
 * correction as a QR code is.
 * @param {string|null} text
 * @param {object} options
 * @param {number} options.version
 * @param {'L'|'M'|'Q'|'H'} [options.level]
 * @param {number} [options.mask]
 * @param {Array<[number, number]>} [options.bits]
 * @returns {number[][]}
 */
export function encodeQr(text, {
	version, level = 'M', mask = 0, bits,
}) {
	const [levelIndex, levelBits] = LEVELS[level];
	const {total, ecPerBlock, blocks} = blockLayout(version, levelIndex);
	const capacity = blocks.reduce((sum, length) => sum + length, 0);
	const stream = [];
	for (const [value, length] of bits ?? byteSegment(text, version)) {
		for (let i = length - 1; i >= 0; i--) {
			stream.push(Math.floor(value / (2 ** i)) % 2);
		}
	}

	for (let i = 0; i < 4 && stream.length < capacity * 8; i++) {
		stream.push(0);
	}

	while (stream.length % 8) {
		stream.push(0);
	}

	const data = [];
	for (let i = 0; i < stream.length && data.length < capacity; i += 8) {
		data.push(Number.parseInt(stream.slice(i, i + 8).join(''), 2));
	}

	for (let pad = 0; data.length < capacity; pad++) {
		data.push(pad % 2 ? 0x11 : 0xEC);
	}

	let offset = 0;
	const split = blocks.map(length => {
		const block = data.slice(offset, offset + length);
		offset += length;
		return {data: block, ec: errorCorrection(block, ecPerBlock)};
	});
	const codewords = [];
	for (let i = 0; i < Math.max(...blocks); i++) {
		for (const block of split) {
			if (i < block.data.length) {
				codewords.push(block.data[i]);
			}
		}
	}

	for (let i = 0; i < ecPerBlock; i++) {
		for (const block of split) {
			codewords.push(block.ec[i]);
		}
	}

	const size = (version * 4) + 17;
	const grid = Array.from({length: size}, () => Array.from({length: size}, () => 0));
	const reserved = Array.from({length: size}, () => Array.from({length: size}, () => false));
	const set = (row, column, dark) => {
		if (row >= 0 && column >= 0 && row < size && column < size) {
			grid[row][column] = dark ? 1 : 0;
			reserved[row][column] = true;
		}
	};

	for (const [top, left] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
		for (let i = -1; i <= 7; i++) {
			for (let j = -1; j <= 7; j++) {
				const ring = Math.max(Math.abs(i - 3), Math.abs(j - 3));
				set(top + i, left + j, ring !== 2 && ring !== 4);
			}
		}
	}

	for (let i = 8; i < size - 8; i++) {
		set(6, i, i % 2 === 0);
		set(i, 6, i % 2 === 0);
	}

	const centers = alignmentCenters(version);
	for (const row of centers) {
		for (const column of centers) {
			if ((row === 6 && (column === 6 || column === size - 7)) || (row === size - 7 && column === 6)) {
				continue;
			}

			for (let i = -2; i <= 2; i++) {
				for (let j = -2; j <= 2; j++) {
					set(row + i, column + j, Math.max(Math.abs(i), Math.abs(j)) !== 1);
				}
			}
		}
	}

	const format = bch((levelBits << 3) | mask, 0x5_37, 10) ^ 0x54_12;
	const first = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
	for (const [i, [row, column]] of first.entries()) {
		set(row, column, (format >> (14 - i)) & 1);
	}

	for (let i = 0; i < 7; i++) {
		set(size - 1 - i, 8, (format >> (14 - i)) & 1);
	}

	for (let i = 0; i < 8; i++) {
		set(8, size - 8 + i, (format >> (7 - i)) & 1);
	}

	set(size - 8, 8, true);
	if (version >= 7) {
		const info = bch(version, 0x1F_25, 12);
		for (let i = 0; i < 18; i++) {
			const bit = (info >> i) & 1;
			set(Math.floor(i / 3), size - 11 + (i % 3), bit);
			set(size - 11 + (i % 3), Math.floor(i / 3), bit);
		}
	}

	let bit = 0;
	let upward = true;
	for (let column = size - 1; column > 0; column -= 2) {
		if (column === 6) {
			column--;
		}

		for (let k = 0; k < size; k++) {
			const row = upward ? size - 1 - k : k;
			for (const j of [column, column - 1]) {
				if (reserved[row][j]) {
					continue;
				}

				const value = bit < total * 8 ? (codewords[bit >> 3] >> (7 - (bit & 7))) & 1 : 0;
				bit++;
				grid[row][j] = value ^ (MASKS[mask](row, j) ? 1 : 0);
			}
		}

		upward = !upward;
	}

	return grid;
}

/**
 * A grayscale image of a QR code's modules.
 * @param {number[][]} grid
 * @param {object} [options]
 * @param {number} [options.scale] - pixels a module
 * @param {number} [options.margin] - modules of margin
 * @param {number} [options.turns] - quarter turns clockwise
 * @param {boolean} [options.invert] - light on dark
 * @param {boolean} [options.mirror]
 * @returns {{width: number, height: number, gray: Uint8Array}}
 */
export function render(grid, {
	scale = 4, margin = 4, turns = 0, invert = false, mirror = false,
} = {}) {
	let modules = grid;
	for (let t = 0; t < turns; t++) {
		modules = modules[0].map((_, column) => modules.map(row => row[column]).reverse());
	}

	if (mirror) {
		modules = modules.map(row => [...row].reverse());
	}

	const width = (modules.length + (margin * 2)) * scale;
	const gray = new Uint8Array(width * width).fill(invert ? 0 : 255);
	for (const [r, row] of modules.entries()) {
		for (const [c, dark] of row.entries()) {
			if (dark) {
				for (let y = 0; y < scale; y++) {
					gray.fill(invert ? 255 : 0, ((((r + margin) * scale) + y) * width) + ((c + margin) * scale), ((((r + margin) * scale) + y) * width) + ((c + margin + 1) * scale));
				}
			}
		}
	}

	return {width, height: width, gray};
}

const CRC_TABLE = Array.from({length: 256}, (_, n) => {
	let c = n;
	for (let k = 0; k < 8; k++) {
		c = c & 1 ? 0xED_B8_83_20 ^ (c >>> 1) : c >>> 1;
	}

	return c >>> 0;
});

function chunk(type, data) {
	const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
	let crc = 0xFF_FF_FF_FF;
	for (const byte of body) {
		crc = CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
	}

	const length = Buffer.alloc(4);
	length.writeUInt32BE(data.length);
	const sum = Buffer.alloc(4);
	sum.writeUInt32BE((crc ^ 0xFF_FF_FF_FF) >>> 0);
	return Buffer.concat([length, body, sum]);
}

const PASSES = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];

/**
 * A PNG file of a grayscale image, in any color type and bit depth PNG has,
 * with each of its filters in turn, interlaced or not.
 * @param {{width: number, height: number, gray: Uint8Array}} image
 * @param {object} [options]
 * @param {0|2|3|4|6} [options.color]
 * @param {1|2|4|8|16} [options.depth]
 * @param {boolean} [options.interlaced]
 * @param {boolean} [options.transparent] - light pixels transparent (in alpha, or by tRNS of the palette)
 * @param {Buffer|null} [options.palette] - of color type 3 (black and white; null for none)
 * @returns {Buffer}
 */
export function encodePng({width, height, gray}, {
	color = 0, depth = 8, interlaced = false, transparent = false, palette = Buffer.from([0, 0, 0, 255, 255, 255]),
} = {}) {
	const channels = {
		0: 1, 2: 3, 3: 1, 4: 2, 6: 4,
	}[color];
	const max = (2 ** depth) - 1;
	const samplesOf = value => {
		const dark = value < 128;
		const alpha = transparent && !dark ? 0 : max;
		const level = color === 3 ? (dark ? 0 : 1) : Math.round((value / 255) * max);
		return {
			0: [level], 2: [level, level, level], 3: [level], 4: [level, alpha], 6: [level, level, level, alpha],
		}[color];
	};

	const rows = [];
	let filter = 0;
	for (const [x0, y0, dx, dy] of interlaced ? PASSES : [[0, 0, 1, 1]]) {
		const passWidth = Math.ceil((width - x0) / dx);
		const passHeight = Math.ceil((height - y0) / dy);
		if (passWidth <= 0 || passHeight <= 0) {
			continue;
		}

		const rowBytes = Math.ceil((passWidth * channels * depth) / 8);
		const bpp = Math.max(1, (channels * depth) >> 3);
		let previous = Buffer.alloc(rowBytes);
		for (let r = 0; r < passHeight; r++) {
			const row = Buffer.alloc(rowBytes);
			let bit = 0;
			for (let c = 0; c < passWidth; c++) {
				for (const sample of samplesOf(gray[((y0 + (r * dy)) * width) + x0 + (c * dx)])) {
					if (depth === 16) {
						row.writeUInt16BE(sample, bit >> 3);
					} else {
						row[bit >> 3] |= sample << (8 - depth - (bit & 7));
					}

					bit += depth;
				}
			}

			const filtered = Buffer.alloc(rowBytes);
			for (let i = 0; i < rowBytes; i++) {
				const left = i >= bpp ? row[i - bpp] : 0;
				const up = previous[i];
				const upLeft = i >= bpp ? previous[i - bpp] : 0;
				const p = left + up - upLeft;
				const predictor = [0, left, up, (left + up) >> 1, Math.abs(p - left) <= Math.abs(p - up) && Math.abs(p - left) <= Math.abs(p - upLeft) ? left : (Math.abs(p - up) <= Math.abs(p - upLeft) ? up : upLeft)][filter];
				filtered[i] = (row[i] - predictor) & 0xFF;
			}

			rows.push(Buffer.from([filter]), filtered);
			filter = (filter + 1) % 5;
			previous = row;
		}
	}

	const header = Buffer.alloc(13);
	header.writeUInt32BE(width, 0);
	header.writeUInt32BE(height, 4);
	header[8] = depth;
	header[9] = color;
	header[12] = interlaced ? 1 : 0;
	return Buffer.concat([
		Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
		chunk('IHDR', header),
		...(color === 3 && palette ? [chunk('PLTE', palette)] : []),
		...(color === 3 && transparent ? [chunk('tRNS', Buffer.from([255, 0]))] : []),
		chunk('tEXt', Buffer.from('Comment\0test')),
		chunk('IDAT', deflateSync(Buffer.concat(rows))),
		chunk('IEND', Buffer.alloc(0)),
	]);
}

/**
 * A GIF file of a grayscale image (black and white), its codes all
 * literals, interlaced or not, with its colors in a global or local table.
 * @param {{width: number, height: number, gray: Uint8Array}} image
 * @param {object} [options]
 * @param {boolean} [options.interlaced]
 * @param {boolean} [options.local] - the colors in the image's own table
 * @param {boolean} [options.transparent] - white transparent
 * @returns {Buffer}
 */
export function encodeGif({width, height, gray}, {interlaced = false, local = false, transparent = false} = {}) {
	const table = Buffer.from([0, 0, 0, 255, 255, 255, 128, 128, 128, 64, 64, 64]);
	const order = interlaced ? [[0, 8], [4, 8], [2, 4], [1, 2]].flatMap(([start, step]) => Array.from({length: Math.ceil(Math.max(0, height - start) / step)}, (_, i) => start + (i * step))) : Array.from({length: height}, (_, i) => i);
	const indices = order.flatMap(y => Array.from({length: width}, (_, x) => (gray[(y * width) + x] < 128 ? 0 : 1)));
	const minimum = 2;
	const clear = 1 << minimum;
	const codes = [];
	let size = minimum + 1;
	let next = clear + 2;
	let first = true;
	const emit = code => {
		codes.push([code, size]);
	};

	emit(clear);
	for (const index of indices) {
		emit(index);
		if (first) {
			first = false;
		} else {
			next++;
			if (next === 1 << size && size < 12) {
				size++;
			}
		}

		if (next >= 4095) {
			emit(clear);
			size = minimum + 1;
			next = clear + 2;
			first = true;
		}
	}

	emit(clear + 1);
	const bytes = [];
	let value = 0;
	let bits = 0;
	for (const [code, length] of codes) {
		value |= code << bits;
		bits += length;
		while (bits >= 8) {
			bytes.push(value & 0xFF);
			value >>>= 8;
			bits -= 8;
		}
	}

	if (bits > 0) {
		bytes.push(value & 0xFF);
	}

	const blocks = [];
	for (let i = 0; i < bytes.length; i += 255) {
		const part = bytes.slice(i, i + 255);
		blocks.push(part.length, ...part);
	}

	const screen = Buffer.alloc(7);
	screen.writeUInt16LE(width, 0);
	screen.writeUInt16LE(height, 2);
	screen[4] = local ? 0 : 0x81;
	const descriptor = Buffer.alloc(10);
	descriptor[0] = 0x2C;
	descriptor.writeUInt16LE(width, 5);
	descriptor.writeUInt16LE(height, 7);
	descriptor[9] = (local ? 0x81 : 0) | (interlaced ? 0x40 : 0);
	return Buffer.concat([
		Buffer.from('GIF89a', 'latin1'),
		screen,
		...(local ? [] : [table]),
		// (a comment, and a graphic control extension)
		Buffer.from([0x21, 0xFE, 4, ...Buffer.from('test'), 0]),
		Buffer.from([0x21, 0xF9, 4, transparent ? 1 : 0, 0, 0, 1, 0]),
		descriptor,
		...(local ? [table] : []),
		Buffer.from([minimum, ...blocks, 0, 0x3B]),
	]);
}

/**
 * A PDF file of streams, each a dictionary's entries and its data (no
 * cross-reference table, as the scanner reads none).
 * @param {Array<[string, Buffer]>} streams
 * @returns {Buffer}
 */
export function pdf(streams) {
	return Buffer.concat([
		Buffer.from('%PDF-1.4\n'),
		...streams.map(([dictionary, data], i) => Buffer.concat([Buffer.from(`${i + 1} 0 obj\n<< ${dictionary} /Length ${data.length} >>\nstream\r\n`), data, Buffer.from('\nendstream\nendobj\n')])),
		Buffer.from('trailer\n<< /Root 1 0 R >>\n%%EOF\n'),
	]);
}
