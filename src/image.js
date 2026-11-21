import {Buffer} from 'node:buffer';
import {inflateSync} from 'node:zlib';

// Images read as grayscale, for the QR codes in them (see qr.js): PNG, GIF
// (its first frame) and baseline JPEG, and the images and squares drawn in
// PDF files. Each is read only up to MAX_PIXELS, and compressed data only up
// to what that many pixels take, so a small file cannot make a huge image.
export const MAX_PIXELS = 2_500_000;

const luma = (r, g, b) => Math.round((r * 0.299) + (g * 0.587) + (b * 0.114));
// (over a white background, as a mail client shows a transparent image)
const overWhite = (value, alpha) => Math.round(((value * alpha) + (255 * (255 - alpha))) / 255);

// PNG's filters, undone on a row of bytes (`bpp`: bytes a pixel, at least 1)
function unfilter(type, row, previous, bpp) {
	for (let i = 0; i < row.length; i++) {
		const left = i >= bpp ? row[i - bpp] : 0;
		const up = previous ? previous[i] : 0;
		const upLeft = previous && i >= bpp ? previous[i - bpp] : 0;
		switch (type) {
			case 1: {
				row[i] = (row[i] + left) & 0xFF;
				break;
			}

			case 2: {
				row[i] = (row[i] + up) & 0xFF;
				break;
			}

			case 3: {
				row[i] = (row[i] + ((left + up) >> 1)) & 0xFF;
				break;
			}

			case 4: {
				const p = left + up - upLeft;
				const pa = Math.abs(p - left);
				const pb = Math.abs(p - up);
				const pc = Math.abs(p - upLeft);
				row[i] = (row[i] + (pa <= pb && pa <= pc ? left : (pb <= pc ? up : upLeft))) & 0xFF;
				break;
			}

			default: {
				break;
			}
		}
	}
}

// The samples of a row of pixels, each 0 to 255
function samplesOf(row, count, depth) {
	const samples = new Uint8Array(count);
	for (let i = 0; i < count; i++) {
		if (depth === 8) {
			samples[i] = row[i];
		} else if (depth === 16) {
			samples[i] = row[i * 2];
		} else {
			const bit = i * depth;
			const value = (row[bit >> 3] >> (8 - depth - (bit & 7))) & ((1 << depth) - 1);
			samples[i] = Math.round((value * 255) / ((1 << depth) - 1));
		}
	}

	return samples;
}

const CHANNELS = {
	0: 1, 2: 3, 3: 1, 4: 2, 6: 4,
};
// (Adam7's passes: first column and row, and steps between)
const PASSES = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];

function decodePng(buffer, maxPixels) {
	let offset = 8;
	let header;
	let palette = null;
	let alphas = null;
	const data = [];
	while (offset + 12 <= buffer.length) {
		const length = buffer.readUInt32BE(offset);
		const type = buffer.toString('latin1', offset + 4, offset + 8);
		const chunk = buffer.subarray(offset + 8, offset + 8 + length);
		offset += 12 + length;
		if (type === 'IEND') {
			break;
		}

		switch (type) {
			case 'IHDR': {
				header = chunk.length >= 13 && {
					width: chunk.readUInt32BE(0), height: chunk.readUInt32BE(4), depth: chunk[8], color: chunk[9], interlaced: chunk[12] === 1,
				};
				break;
			}

			case 'PLTE': {
				palette = chunk;
				break;
			}

			case 'tRNS': {
				alphas = chunk;
				break;
			}

			case 'IDAT': {
				data.push(chunk);
				break;
			}

			default: {
				break;
			}
		}
	}

	const channels = CHANNELS[header?.color];
	if (!channels || ![1, 2, 4, 8, 16].includes(header.depth) || header.width === 0 || header.height === 0 || header.width * header.height > maxPixels) {
		return null;
	}

	const {width, height, depth, color} = header;
	const bpp = Math.max(1, (channels * depth) >> 3);
	const passes = header.interlaced ? PASSES : [[0, 0, 1, 1]];
	const sizes = passes.map(([x, y, dx, dy]) => [Math.ceil((width - x) / dx), Math.ceil((height - y) / dy)]);
	const expected = sizes.reduce((sum, [w, h]) => sum + (w > 0 && h > 0 ? h * (Math.ceil((w * channels * depth) / 8) + 1) : 0), 0);
	let raw;
	try {
		raw = inflateSync(Buffer.concat(data), {maxOutputLength: expected});
	} catch {
		return null;
	}

	const gray = new Uint8Array(width * height).fill(255);
	let read = 0;
	for (const [index, [x0, y0, dx, dy]] of passes.entries()) {
		const [w, h] = sizes[index];
		if (w <= 0 || h <= 0) {
			continue;
		}

		const rowBytes = Math.ceil((w * channels * depth) / 8);
		let previous = null;
		for (let r = 0; r < h && read + rowBytes + 1 <= raw.length; r++) {
			const type = raw[read];
			const row = Uint8Array.from(raw.subarray(read + 1, read + 1 + rowBytes));
			read += rowBytes + 1;
			unfilter(type, row, previous, bpp);
			previous = row;
			const samples = samplesOf(row, w * channels, depth);
			for (let c = 0; c < w; c++) {
				const s = c * channels;
				let value;
				switch (color) {
					case 0: {
						value = samples[s];
						break;
					}

					case 2: {
						value = luma(samples[s], samples[s + 1], samples[s + 2]);
						break;
					}

					case 3: {
						// (the palette's color, by the index, not scaled)
						const entry = depth === 8 ? row[c] : (row[(c * depth) >> 3] >> (8 - depth - ((c * depth) & 7))) & ((1 << depth) - 1);
						value = palette && (entry * 3) + 2 < palette.length ? luma(palette[entry * 3], palette[(entry * 3) + 1], palette[(entry * 3) + 2]) : 255;
						if (alphas && entry < alphas.length) {
							value = overWhite(value, alphas[entry]);
						}

						break;
					}

					case 4: {
						value = overWhite(samples[s], samples[s + 1]);
						break;
					}

					default: {
						value = overWhite(luma(samples[s], samples[s + 1], samples[s + 2]), samples[s + 3]);
					}
				}

				gray[(((y0 + (r * dy)) * width) + x0 + (c * dx))] = value;
			}
		}
	}

	return {width, height, gray};
}

// GIF's LZW, the indices of up to `count` pixels
function lzw(data, minimum, count) {
	const clear = 1 << minimum;
	const prefix = new Int16Array(4096);
	const suffix = new Uint8Array(4096);
	const first = new Uint8Array(4096);
	for (let i = 0; i < clear; i++) {
		suffix[i] = i;
		first[i] = i;
	}

	const out = new Uint8Array(count);
	const stack = new Uint8Array(4097);
	let size = minimum + 1;
	let next = clear + 2;
	let old = -1;
	let bits = 0;
	let value = 0;
	let written = 0;
	for (let i = 0; i < data.length && written < count; i++) {
		value |= data[i] << bits;
		bits += 8;
		while (bits >= size && written < count) {
			const code = value & ((1 << size) - 1);
			value >>>= size;
			bits -= size;
			if (code === clear) {
				size = minimum + 1;
				next = clear + 2;
				old = -1;
				continue;
			}

			if (code === clear + 1) {
				return out;
			}

			let current = code;
			let depth = 0;
			if (code >= next) {
				if (old === -1 || code > next) {
					return out;
				}

				stack[depth++] = first[old];
				current = old;
			}

			while (current >= clear && depth < 4096) {
				stack[depth++] = suffix[current];
				current = prefix[current];
			}

			stack[depth++] = current;
			const head = current;
			while (depth > 0 && written < count) {
				out[written++] = stack[--depth];
			}

			if (old !== -1 && next < 4096) {
				prefix[next] = old;
				suffix[next] = head;
				first[next] = first[old];
				next++;
				if (next === 1 << size && size < 12) {
					size++;
				}
			}

			old = code;
		}
	}

	return out;
}

function decodeGif(buffer, maxPixels) {
	const width = buffer.readUInt16LE(6);
	const height = buffer.readUInt16LE(8);
	if (width === 0 || height === 0 || width * height > maxPixels) {
		return null;
	}

	const flags = buffer[10];
	let offset = 13;
	let table = null;
	if (flags & 0x80) {
		table = buffer.subarray(offset, offset + (3 * (2 << (flags & 7))));
		offset += table.length;
	}

	let transparent = -1;
	while (offset < buffer.length) {
		const block = buffer[offset++];
		if (block === 0x21) {
			const label = buffer[offset++];
			if (label === 0xF9 && buffer[offset] >= 4 && (buffer[offset + 1] & 1)) {
				transparent = buffer[offset + 4];
			}

			while (offset < buffer.length && buffer[offset] !== 0) {
				offset += buffer[offset] + 1;
			}

			offset++;
		} else if (block === 0x2C) {
			const left = buffer.readUInt16LE(offset);
			const top = buffer.readUInt16LE(offset + 2);
			const w = buffer.readUInt16LE(offset + 4);
			const h = buffer.readUInt16LE(offset + 6);
			const local = buffer[offset + 8];
			offset += 9;
			if (local & 0x80) {
				table = buffer.subarray(offset, offset + (3 * (2 << (local & 7))));
				offset += table.length;
			}

			const minimum = buffer[offset++];
			const parts = [];
			while (offset < buffer.length && buffer[offset] !== 0) {
				parts.push(buffer.subarray(offset + 1, offset + 1 + buffer[offset]));
				offset += buffer[offset] + 1;
			}

			if (!table || minimum < 2 || minimum > 11 || w * h > maxPixels) {
				return null;
			}

			const indices = lzw(Buffer.concat(parts), minimum, w * h);
			// (interlaced: rows 0, 8, 16, then 4, 12, then 2, 6, then the odd ones)
			const rows = local & 0x40 ? [[0, 8], [4, 8], [2, 4], [1, 2]].flatMap(([start, step]) => Array.from({length: Math.ceil(Math.max(0, h - start) / step)}, (_, i) => start + (i * step))) : Array.from({length: h}, (_, i) => i);
			const gray = new Uint8Array(width * height).fill(255);
			for (const [r, y] of rows.entries()) {
				for (let x = 0; x < w; x++) {
					const index = indices[(r * w) + x];
					const px = left + x;
					const py = top + y;
					if (index !== transparent && px < width && py < height && (index * 3) + 2 < table.length) {
						gray[(py * width) + px] = luma(table[index * 3], table[(index * 3) + 1], table[(index * 3) + 2]);
					}
				}
			}

			return {width, height, gray};
		} else {
			return null;
		}
	}

	return null;
}

const ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63];
// (cos((2x + 1) u π / 16), with C(0) = 1/√2, for the inverse DCT)
const COSINES = Float64Array.from({length: 64}, (_, i) => {
	const x = i >> 3;
	const u = i & 7;
	return (u === 0 ? Math.SQRT1_2 : 1) * Math.cos((((2 * x) + 1) * u * Math.PI) / 16);
});

// A Huffman table of JPEG: the symbols by the codes of each length
function huffman(counts, symbols) {
	const table = {maxCode: new Int32Array(18).fill(-1), offset: new Int32Array(18), symbols};
	let code = 0;
	let index = 0;
	for (let length = 1; length <= 16; length++) {
		table.offset[length] = index - code;
		code += counts[length - 1];
		index += counts[length - 1];
		table.maxCode[length] = counts[length - 1] ? code - 1 : -1;
		code <<= 1;
	}

	return table;
}

// The entropy-coded bits of a JPEG scan, without stuffed bytes and up to a
// marker
class Reader {
	constructor(buffer, offset) {
		this.buffer = buffer;
		this.offset = offset;
		this.value = 0;
		this.bits = 0;
		this.marker = false;
	}

	bit() {
		if (this.bits === 0) {
			let byte = 0;
			if (!this.marker && this.offset < this.buffer.length) {
				byte = this.buffer[this.offset];
				if (byte === 0xFF) {
					const next = this.buffer[this.offset + 1];
					if (next === 0) {
						this.offset += 2;
					} else {
						this.marker = true;
						byte = 0;
					}
				} else {
					this.offset++;
				}
			}

			this.value = byte;
			this.bits = 8;
		}

		this.bits--;
		return (this.value >> this.bits) & 1;
	}

	receive(count) {
		let value = 0;
		for (let i = 0; i < count; i++) {
			value = (value << 1) | this.bit();
		}

		return value;
	}

	decode(table) {
		let code = 0;
		for (let length = 1; length <= 16; length++) {
			code = (code << 1) | this.bit();
			if (code <= table.maxCode[length]) {
				return table.symbols[table.offset[length] + code];
			}
		}

		return 0;
	}

	// (past a restart marker, the next bytes after the bits read, where it is)
	restart() {
		this.bits = 0;
		this.marker = false;
		if (this.buffer[this.offset] === 0xFF && this.buffer[this.offset + 1] >= 0xD0 && this.buffer[this.offset + 1] <= 0xD7) {
			this.offset += 2;
		}
	}
}

const extend = (value, size) => (size && value < (1 << (size - 1)) ? value - (1 << size) + 1 : value);

// A JPEG's quantization tables (DQT), by their numbers
function readQuantization(segment, quantization) {
	for (let i = 0; i + 1 < segment.length;) {
		const sixteen = segment[i] >> 4;
		const table = new Int32Array(64);
		for (let k = 0; k < 64; k++) {
			table[ZIGZAG[k]] = sixteen ? segment.readUInt16BE(i + 1 + (k * 2)) : segment[i + 1 + k];
		}

		quantization[segment[i] & 3] = table;
		i += 1 + (sixteen ? 128 : 64);
	}
}

// A JPEG's Huffman tables (DHT), of DC and AC coefficients by their numbers
function readHuffman(segment, dc, ac) {
	for (let i = 0; i + 17 <= segment.length;) {
		const counts = segment.subarray(i + 1, i + 17);
		const total = counts.reduce((sum, count) => sum + count, 0);
		(segment[i] >> 4 ? ac : dc)[segment[i] & 3] = huffman(counts, segment.subarray(i + 17, i + 17 + total));
		i += 17 + total;
	}
}

// A baseline JPEG's frame (SOF0, SOF1): its size and components, or null for
// one of 12 bits, too big, of four components, or sampled as no JPEG is
function frameOf(segment, maxPixels) {
	const components = Array.from({length: segment[5]}, (_, i) => ({
		id: segment[6 + (i * 3)], h: segment[7 + (i * 3)] >> 4, v: segment[7 + (i * 3)] & 15, q: segment[8 + (i * 3)] & 3, predictor: 0,
	}));
	const frame = {height: segment.readUInt16BE(1), width: segment.readUInt16BE(3), components};
	// (and of one or three components: not CMYK, whose first is no luminance)
	return segment[0] === 8 && frame.width > 0 && frame.height > 0 && frame.width * frame.height <= maxPixels && (components.length === 1 || components.length === 3) && components.every(c => c.h >= 1 && c.h <= 4 && c.v >= 1 && c.v <= 4) ? frame : null;
}

// A baseline JPEG's luminance (its first component), or null for any other
// kind (progressive, arithmetic coding, 12 bits)
function decodeJpeg(buffer, maxPixels) {
	const quantization = [];
	const dc = [];
	const ac = [];
	let frame = null;
	let restart = 0;
	let offset = 2;
	while (offset + 4 <= buffer.length) {
		if (buffer[offset] !== 0xFF) {
			offset++;
			continue;
		}

		const marker = buffer[offset + 1];
		if (marker === 0xD8 || marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7) || marker === 0xFF) {
			offset += marker === 0xFF ? 1 : 2;
			continue;
		}

		const length = buffer.readUInt16BE(offset + 2);
		const segment = buffer.subarray(offset + 4, offset + 2 + length);
		offset += 2 + length;
		// (progressive, lossless, hierarchical and arithmetic coded frames)
		if (marker >= 0xC2 && marker <= 0xCF && marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC) {
			return null;
		}

		switch (marker) {
			case 0xDB: {
				readQuantization(segment, quantization);
				break;
			}

			case 0xC0:
			case 0xC1: {
				frame = frameOf(segment, maxPixels);
				if (!frame) {
					return null;
				}

				break;
			}

			case 0xC4: {
				readHuffman(segment, dc, ac);
				break;
			}

			case 0xDD: {
				restart = segment.readUInt16BE(0);
				break;
			}

			case 0xDA: {
				return frame
					? scanJpeg(buffer, offset, segment, {
						frame, quantization, dc, ac, restart,
					})
					: null;
			}

			case 0xD9: {
				return null;
			}

			default: {
				break;
			}
		}
	}

	return null;
}

// The coefficients of a block of a JPEG's component, dequantized
function decodeBlock(reader, component, {dc, ac, quantization}, coefficients) {
	coefficients.fill(0);
	const size = reader.decode(dc);
	component.predictor += extend(reader.receive(size), size);
	coefficients[0] = component.predictor * quantization[0];
	for (let k = 1; k < 64;) {
		const symbol = reader.decode(ac);
		const run = symbol >> 4;
		const bits = symbol & 15;
		if (bits === 0) {
			if (run !== 15) {
				break;
			}

			k += 16;
			continue;
		}

		k += run;
		if (k > 63) {
			break;
		}

		coefficients[ZIGZAG[k]] = extend(reader.receive(bits), bits) * quantization[ZIGZAG[k]];
		k++;
	}
}

// The pixels of a block, by the inverse DCT of its coefficients (rows, then
// columns), into a plane of a component
function inverseDct(coefficients, block, {plane, planeWidth, x: blockX, y: blockY}) {
	for (let y = 0; y < 8; y++) {
		for (let x = 0; x < 8; x++) {
			let sum = 0;
			for (let u = 0; u < 8; u++) {
				sum += COSINES[(x * 8) + u] * coefficients[(y * 8) + u];
			}

			block[(y * 8) + x] = sum / 2;
		}
	}

	for (let x = 0; x < 8; x++) {
		for (let y = 0; y < 8; y++) {
			let sum = 0;
			for (let u = 0; u < 8; u++) {
				sum += COSINES[(y * 8) + u] * block[(u * 8) + x];
			}

			const px = (blockX * 8) + x;
			const py = (blockY * 8) + y;
			if (px < planeWidth && (py * planeWidth) + px < plane.length) {
				plane[(py * planeWidth) + px] = Math.max(0, Math.min(255, Math.round((sum / 2) + 128)));
			}
		}
	}
}

function scanJpeg(buffer, offset, segment, {frame, quantization, dc, ac, restart}) {
	const {width, height, components} = frame;
	const scanned = Array.from({length: segment[0]}, (_, i) => {
		const component = components.find(c => c.id === segment[1 + (i * 2)]);
		return component && {component, dc: dc[segment[2 + (i * 2)] >> 4], ac: ac[segment[2 + (i * 2)] & 15]};
	});
	if (scanned.some(s => !s?.dc || !s.ac || !quantization[s.component.q])) {
		return null;
	}

	const hMax = Math.max(...components.map(c => c.h));
	const vMax = Math.max(...components.map(c => c.v));
	const mcuColumns = Math.ceil(width / (8 * hMax));
	const mcuRows = Math.ceil(height / (8 * vMax));
	const luminance = components[0];
	const planeWidth = mcuColumns * luminance.h * 8;
	const plane = new Uint8Array(planeWidth * mcuRows * luminance.v * 8);
	const reader = new Reader(buffer, offset);
	const coefficients = new Float64Array(64);
	const block = new Float64Array(64);
	// (a scan of one component has a block an MCU, of its own size)
	const single = scanned.length === 1;
	const blocksWide = Math.ceil(Math.ceil((width * scanned[0].component.h) / hMax) / 8);
	const blocksHigh = Math.ceil(Math.ceil((height * scanned[0].component.v) / vMax) / 8);
	for (let mcu = 0; mcu < (single ? blocksWide * blocksHigh : mcuColumns * mcuRows); mcu++) {
		if (restart && mcu > 0 && mcu % restart === 0) {
			reader.restart();
			for (const c of components) {
				c.predictor = 0;
			}
		}

		const mcuX = mcu % mcuColumns;
		const mcuY = Math.floor(mcu / mcuColumns);
		for (const {component, dc: dcTable, ac: acTable} of scanned) {
			for (let v = 0; v < (single ? 1 : component.v); v++) {
				for (let h = 0; h < (single ? 1 : component.h); h++) {
					decodeBlock(reader, component, {dc: dcTable, ac: acTable, quantization: quantization[component.q]}, coefficients);
					if (component === luminance) {
						inverseDct(coefficients, block, {
							plane, planeWidth, x: single ? mcu % blocksWide : (mcuX * component.h) + h, y: single ? Math.floor(mcu / blocksWide) : (mcuY * component.v) + v,
						});
					}
				}
			}
		}
	}

	// (the luminance at the size of the image, where it is sampled less)
	const gray = new Uint8Array(width * height);
	const scaleX = luminance.h / hMax;
	const scaleY = luminance.v / vMax;
	for (let y = 0; y < height; y++) {
		for (let x = 0; x < width; x++) {
			gray[(y * width) + x] = plane[(Math.floor(y * scaleY) * planeWidth) + Math.floor(x * scaleX)];
		}
	}

	return {width, height, gray};
}

/**
 * A PNG, GIF or baseline JPEG image as grayscale (a byte a pixel), or null
 * for another kind, a damaged one, or one of more than `maxPixels` pixels.
 * @param {Buffer} buffer
 * @param {object} [options]
 * @param {number} [options.maxPixels]
 * @returns {{width: number, height: number, gray: Uint8Array}|null}
 */
export function decodeImage(buffer, {maxPixels = MAX_PIXELS} = {}) {
	if (!Buffer.isBuffer(buffer) || buffer.length < 16) {
		return null;
	}

	try {
		if (buffer.readUInt32BE(0) === 0x89_50_4E_47) {
			return decodePng(buffer, maxPixels);
		}

		if (buffer.toString('latin1', 0, 4) === 'GIF8') {
			return decodeGif(buffer, maxPixels);
		}

		if (buffer[0] === 0xFF && buffer[1] === 0xD8) {
			return decodeJpeg(buffer, maxPixels);
		}
	} catch {
		// (a damaged image is none)
	}

	return null;
}

/**
 * Grayscale pixels from any channels a pixel (1 gray, 2 gray and alpha, 3
 * RGB, 4 RGBA), as an image decoder outside gives them
 * @param {{width: number, height: number, data: Uint8Array, channels: number}} image
 * @returns {{width: number, height: number, gray: Uint8Array}|null}
 */
export function grayOf({
	width, height, data, channels,
} = {}) {
	if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0 || width * height > MAX_PIXELS || ![1, 2, 3, 4].includes(channels) || !data || data.length < width * height * channels) {
		return null;
	}

	const gray = new Uint8Array(width * height);
	for (let i = 0; i < gray.length; i++) {
		const s = i * channels;
		const value = channels < 3 ? data[s] : luma(data[s], data[s + 1], data[s + 2]);
		gray[i] = channels === 2 || channels === 4 ? overWhite(value, data[s + channels - 1]) : value;
	}

	return {width, height, gray};
}

// (of a PDF dictionary, the number after a name, or the name)
const pdfNumber = (dictionary, name) => {
	const match = new RegExp(`/${name}\\s+(\\d{1,7})(?![\\d.]|\\s+\\d+\\s+R)`).exec(dictionary);
	return match ? Number(match[1]) : null;
};

// The pixels of a PDF image, by its dictionary and its data as stored
function pdfImage(dictionary, data, maxPixels) {
	const width = pdfNumber(dictionary, 'Width');
	const height = pdfNumber(dictionary, 'Height');
	if (!width || !height || width * height > maxPixels || /\/(?:CCITTFax|JBIG2|JPX|LZW|RunLength|ASCII85|ASCIIHex)Decode|\/Indexed|\/Crypt/.test(dictionary)) {
		return null;
	}

	if (/\/DCTDecode/.test(dictionary)) {
		return /\/FlateDecode/.test(dictionary) ? null : decodeImage(data, {maxPixels});
	}

	const mask = /\/ImageMask\s+true/.test(dictionary);
	const depth = mask ? 1 : (pdfNumber(dictionary, 'BitsPerComponent') ?? 8);
	let channels = 1;
	if (!mask && /\/DeviceCMYK/.test(dictionary)) {
		channels = 4;
	} else if (!mask && /\/DeviceRGB|\/CalRGB|\/N\s+3\b/.test(dictionary)) {
		channels = 3;
	}

	if (![1, 2, 4, 8].includes(depth)) {
		return null;
	}

	const rowBytes = Math.ceil((width * channels * depth) / 8);
	const predictor = pdfNumber(dictionary, 'Predictor') ?? 1;
	let raw = data;
	if (/\/FlateDecode/.test(dictionary)) {
		try {
			raw = inflateSync(data, {maxOutputLength: (rowBytes + 1) * height});
		} catch {
			return null;
		}
	}

	const gray = new Uint8Array(width * height);
	const stride = predictor >= 10 ? rowBytes + 1 : rowBytes;
	let previous = null;
	// (an image mask paints its 0 bits, or its 1 bits with Decode [1 0])
	const inverted = mask && /\/Decode\s*\[\s*1\s+0\s*]/.test(dictionary);
	for (let y = 0; y < height && (y + 1) * stride <= raw.length; y++) {
		const row = Uint8Array.from(raw.subarray((y * stride) + (predictor >= 10 ? 1 : 0), (y + 1) * stride));
		if (predictor >= 10) {
			unfilter(raw[y * stride], row, previous, Math.max(1, (channels * depth) >> 3));
			previous = row;
		}

		const samples = samplesOf(row, width * channels, depth);
		for (let x = 0; x < width; x++) {
			const s = x * channels;
			let value;
			if (channels === 1) {
				value = mask ? (((samples[s] === 0) === !inverted) ? 0 : 255) : samples[s];
			} else if (channels === 3) {
				value = luma(samples[s], samples[s + 1], samples[s + 2]);
			} else {
				value = 255 - Math.min(255, samples[s + 3] + Math.round((samples[s] + samples[s + 1] + samples[s + 2]) / 3));
			}

			gray[(y * width) + x] = value;
		}
	}

	return {width, height, gray};
}

// The squares a PDF page's content fills dark ("x y w h re", then "f"), as a
// QR code drawn in a PDF is, drawn again as an image: a pixel a module, with
// a margin of four
function pdfSquares(content) {
	const squares = [];
	let path = [];
	let fill = 0;
	const numbers = [];
	for (const token of content.split(/[\s[\]()<>]+/)) {
		if (token === 're' && numbers.length >= 4) {
			path.push(numbers.slice(-4));
		} else if (token === 'g' && numbers.length > 0) {
			fill = numbers.at(-1);
		} else if (token === 'rg' && numbers.length >= 3) {
			fill = (numbers.at(-3) * 0.299) + (numbers.at(-2) * 0.587) + (numbers.at(-1) * 0.114);
		} else if (token === 'k' && numbers.length >= 4) {
			fill = 1 - Math.min(1, numbers.at(-1) + ((numbers.at(-4) + numbers.at(-3) + numbers.at(-2)) / 3));
		} else if (['f', 'F', 'f*', 'B', 'B*', 'b', 'b*'].includes(token)) {
			if (fill < 0.5) {
				squares.push(...path);
			}

			path = [];
		} else if (['S', 's', 'n'].includes(token)) {
			path = [];
		}

		if (/^-?(?:\d+\.?\d*|\.\d+)$/.test(token)) {
			numbers.push(Number(token));
			if (numbers.length > 8) {
				numbers.shift();
			}
		} else {
			numbers.length = 0;
		}

		if (squares.length > 40_000) {
			break;
		}
	}

	if (squares.length < 30) {
		return null;
	}

	const module = Math.min(...squares.map(square => Math.min(Math.abs(square[2]), Math.abs(square[3]))).filter(size => size > 0));
	const left = Math.min(...squares.map(([x, , w]) => Math.min(x, x + w)));
	const bottom = Math.min(...squares.map(([, y, , h]) => Math.min(y, y + h)));
	const right = Math.max(...squares.map(([x, , w]) => Math.max(x, x + w)));
	const top = Math.max(...squares.map(([, y, , h]) => Math.max(y, y + h)));
	const columns = Math.round((right - left) / module);
	const rows = Math.round((top - bottom) / module);
	if (!Number.isFinite(module) || columns < 21 || rows < 21 || columns > 300 || rows > 300) {
		return null;
	}

	const scale = 4;
	const width = (columns + 8) * scale;
	const height = (rows + 8) * scale;
	const gray = new Uint8Array(width * height).fill(255);
	for (const [x, y, w, h] of squares) {
		const x0 = Math.round((Math.min(x, x + w) - left) / module);
		const x1 = Math.round((Math.max(x, x + w) - left) / module);
		// (PDF's y grows upward)
		const y0 = Math.round((top - Math.max(y, y + h)) / module);
		const y1 = Math.round((top - Math.min(y, y + h)) / module);
		for (let py = (y0 + 4) * scale; py < (y1 + 4) * scale; py++) {
			gray.fill(0, (py * width) + ((x0 + 4) * scale), (py * width) + ((x1 + 4) * scale));
		}
	}

	return {width, height, gray};
}

/**
 * The images of a PDF file, and the squares its pages draw, as grayscale
 * (see decodeImage): of at most `maxImages` streams, each read up to what
 * its pixels take. Not of an encrypted file.
 * @param {Buffer} buffer
 * @param {object} [options]
 * @param {number} [options.maxImages]
 * @param {number} [options.maxPixels]
 * @returns {Array<{width: number, height: number, gray: Uint8Array}>}
 */
export function pdfImages(buffer, {maxImages = 10, maxPixels = MAX_PIXELS} = {}) {
	const images = [];
	if (!Buffer.isBuffer(buffer) || buffer.includes('/Encrypt')) {
		return images;
	}

	let offset = 0;
	let streams = 0;
	while (images.length < maxImages && streams < 200) {
		const start = buffer.indexOf('stream', offset, 'latin1');
		if (start === -1) {
			break;
		}

		offset = start + 6;
		// ("endstream" is none, and the data starts after the end of the line)
		if (buffer.toString('latin1', start - 3, start) === 'end') {
			continue;
		}

		streams++;
		const head = buffer.toString('latin1', Math.max(0, start - 2048), start);
		const dictionary = head.slice(head.lastIndexOf('obj') + 3);
		let dataStart = start + 6;
		if (buffer[dataStart] === 0x0D) {
			dataStart++;
		}

		if (buffer[dataStart] === 0x0A) {
			dataStart++;
		}

		const end = buffer.indexOf('endstream', dataStart, 'latin1');
		if (end === -1) {
			break;
		}

		offset = end + 9;
		const data = buffer.subarray(dataStart, end);
		let image = null;
		try {
			if (/\/Subtype\s*\/Image/.test(dictionary)) {
				image = pdfImage(dictionary, data, maxPixels);
			} else if (!/\/Type\s*\/(?:XRef|ObjStm|Metadata|EmbeddedFile)|\/Subtype\s*\/(?:Type1C|CIDFontType0C|OpenType|XML)|\/Length1/.test(dictionary)) {
				const content = /\/FlateDecode/.test(dictionary) ? inflateSync(data, {maxOutputLength: 4_000_000}) : data;
				image = pdfSquares(content.toString('latin1'));
			}
		} catch {
			// (a stream that does not read is none)
		}

		if (image) {
			images.push(image);
		}
	}

	return images;
}
