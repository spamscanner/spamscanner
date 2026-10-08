import {Buffer} from 'node:buffer';
import {characterClass} from './tokenizer.js';

/**
 * File extensions that run code when opened, on Windows, macOS, Linux and
 * Android: programs, installers, scripts, shortcuts, and disk images that
 * mail filters are bypassed with. Based on the attachment types Outlook blocks
 * by default, plus the scripting and container formats used in malware
 * campaigns.
 */
export const EXECUTABLE_EXTENSIONS = new Set([
	'ade', 'adp', 'apk', 'app', 'appimage', 'application', 'appref-ms', 'appx', 'appxbundle', 'asp', 'aspx', 'asx', 'bas', 'bat', 'bgi', 'cab', 'cer', 'chm', 'cmd', 'cnt', 'com', 'command', 'cpl', 'csh', 'der', 'diagcab', 'dll', 'dmg', 'docm', 'dotm', 'elf', 'exe', 'fxp', 'gadget', 'grp', 'hlp', 'hpj', 'hta', 'htc', 'img', 'inf', 'ins', 'ipa', 'iso', 'isp', 'its', 'jar', 'jnlp', 'js', 'jse', 'ksh', 'lnk', 'mad', 'maf', 'mag', 'mam', 'maq', 'mar', 'mas', 'mat', 'mau', 'mav', 'maw', 'mcf', 'mda', 'mde', 'mdt', 'mdw', 'mdz', 'msc', 'msh', 'msh1', 'msh1xml', 'msh2', 'msh2xml', 'mshxml', 'msi', 'msix', 'msixbundle', 'msp', 'mst', 'msu', 'nsh', 'ops', 'osd', 'pcd', 'pif', 'pkg', 'pl', 'plg', 'potm', 'ppam', 'ppsm', 'pptm', 'prf', 'prg', 'ps1', 'ps1xml', 'ps2', 'ps2xml', 'psc1', 'psc2', 'pst', 'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw', 'reg', 'scf', 'scpt', 'scr', 'sct', 'settingcontent-ms', 'sh', 'shb', 'shs', 'slk', 'sys', 'theme', 'tmp', 'url', 'vb', 'vbe', 'vbp', 'vbs', 'vhd', 'vhdx', 'vsmacros', 'vsw', 'webpnp', 'website', 'ws', 'wsb', 'wsc', 'wsf', 'wsh', 'xbap', 'xlam', 'xll', 'xlsm', 'xltm', 'xnk',
]);

// Office formats whose file name says they may contain macros.
const MACRO_EXTENSIONS = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppsm', 'ppam', 'sldm']);

// Formats people send every day; one of these before an executable extension
// ("invoice.pdf.exe") is a disguise.
const DOCUMENT_EXTENSIONS = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'csv', 'odt', 'ods', 'html', 'htm', 'mp3', 'mp4', 'mov', 'wav', 'eml', 'msg', 'xml', 'json']);

const BIDI_CONTROLS = characterClass([[0x20_2A, 0x20_2E], [0x20_66, 0x20_69]], 'u');

const ARCHIVE_TYPES = new Set(['zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'cab', 'iso', 'tar', 'zst', 'lzh', 'ace', 'arj']);

/**
 * Identify a file from its first bytes. Returns null when unknown.
 *
 * Recognises programs (Windows PE, ELF, Mach-O), Windows shortcuts, OLE
 * compound files (old Office formats, MSI), ZIP-based formats (Office, Java,
 * Android), other archives, disk images, PDF, RTF, HTML, SVG and common images.
 *
 * @param {Buffer} buffer
 * @returns {{type: string, executable: boolean, archive: boolean}|null}
 */
export function sniff(buffer) {
	if (!Buffer.isBuffer(buffer) || buffer.length < 4) {
		return null;
	}

	const at = (offset, bytes) => buffer.length >= offset + bytes.length && bytes.every((byte, i) => buffer[offset + i] === byte);
	const ascii = (offset, text) => at(offset, [...Buffer.from(text, 'latin1')]);
	const result = (type, executable = false) => ({type, executable, archive: ARCHIVE_TYPES.has(type)});

	if (ascii(0, 'MZ')) {
		return result('exe', true);
	}

	if (at(0, [0x7F, 0x45, 0x4C, 0x46])) {
		return result('elf', true);
	}

	const magic = buffer.readUInt32BE(0);
	if ([0xFE_ED_FA_CE, 0xFE_ED_FA_CF, 0xCE_FA_ED_FE, 0xCF_FA_ED_FE].includes(magic)) {
		return result('macho', true);
	}

	// 0xCAFEBABE is both a Mach-O universal binary and a Java class file;
	// both run code.
	if (magic === 0xCA_FE_BA_BE) {
		return result('macho', true);
	}

	if (at(0, [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) {
		return result('lnk', true);
	}

	if (at(0, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) {
		return result('ole');
	}

	if (at(0, [0x50, 0x4B, 0x03, 0x04]) || at(0, [0x50, 0x4B, 0x05, 0x06])) {
		const names = zipEntries(buffer).map(entry => entry.name);
		if (names.includes('AndroidManifest.xml') || names.includes('classes.dex')) {
			return result('apk', true);
		}

		if (names.includes('META-INF/MANIFEST.MF') && names.some(name => name.endsWith('.class'))) {
			return result('jar', true);
		}

		if (names.some(name => name.startsWith('word/'))) {
			return result('docx');
		}

		if (names.some(name => name.startsWith('xl/'))) {
			return result('xlsx');
		}

		if (names.some(name => name.startsWith('ppt/'))) {
			return result('pptx');
		}

		return result('zip');
	}

	if (ascii(0, 'Rar!')) {
		return result('rar');
	}

	if (at(0, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) {
		return result('7z');
	}

	if (at(0, [0x1F, 0x8B])) {
		return result('gz');
	}

	if (ascii(0, 'MSCF')) {
		return result('cab');
	}

	if (ascii(0x80_01, 'CD001') || ascii(0x88_01, 'CD001') || ascii(0x90_01, 'CD001')) {
		return result('iso');
	}

	if (ascii(0, 'conectix') || ascii(0, 'vhdxfile')) {
		return result('vhd', true);
	}

	if (ascii(0, '%PDF')) {
		return result('pdf');
	}

	if (ascii(0, String.raw`{\rt`)) {
		return result('rtf');
	}

	if (at(0, [0x89, 0x50, 0x4E, 0x47])) {
		return result('png');
	}

	if (at(0, [0xFF, 0xD8, 0xFF])) {
		return result('jpg');
	}

	if (ascii(0, 'GIF8')) {
		return result('gif');
	}

	if (ascii(0, 'RIFF') && ascii(8, 'WEBP')) {
		return result('webp');
	}

	if (ascii(0, '#!')) {
		return result('script', true);
	}

	const head = buffer.subarray(0, 1024).toString('utf8').replace(/^\uFEFF/u, '').trimStart().toLowerCase();
	if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) {
		return result('svg');
	}

	if (head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<head') || head.startsWith('<script')) {
		return result('html');
	}

	return null;
}

/**
 * The entries of a ZIP file, read from its central directory without
 * decompressing anything: name, sizes, and whether the entry is encrypted.
 * @param {Buffer} buffer
 * @param {number} [limit] - most entries to read
 * @returns {Array<{name: string, encrypted: boolean, size: number}>}
 */
export function zipEntries(buffer, limit = 2000) {
	const entries = [];
	// End of central directory: within the last 64 KiB plus 22 bytes.
	const start = Math.max(0, buffer.length - 65_557);
	let eocd = -1;
	for (let i = buffer.length - 22; i >= start; i--) {
		if (buffer.readUInt32LE(i) === 0x06_05_4B_50) {
			eocd = i;
			break;
		}
	}

	if (eocd === -1) {
		return entries;
	}

	const count = buffer.readUInt16LE(eocd + 10);
	let offset = buffer.readUInt32LE(eocd + 16);
	for (let n = 0; n < Math.min(count, limit); n++) {
		if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02_01_4B_50) {
			break;
		}

		const flags = buffer.readUInt16LE(offset + 8);
		const size = buffer.readUInt32LE(offset + 24);
		const nameLength = buffer.readUInt16LE(offset + 28);
		const extraLength = buffer.readUInt16LE(offset + 30);
		const commentLength = buffer.readUInt16LE(offset + 32);
		const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString(flags & 0x8_00 ? 'utf8' : 'latin1');
		entries.push({name, encrypted: (flags & 1) === 1, size});
		offset += 46 + nameLength + extraLength + commentLength;
	}

	return entries;
}

function extensionOf(name) {
	const base = String(name).toLowerCase().split(/[/\\]/).pop();
	const dot = base.lastIndexOf('.');
	return dot === -1 ? '' : base.slice(dot + 1).trim();
}

function oleHasMacros(buffer) {
	// VBA projects live in storages named "VBA" and "_VBA_PROJECT", stored as
	// UTF-16LE names in the compound file's directory.
	const names = ['_VBA_PROJECT', 'VBA', 'Macros'].map(name => Buffer.from(name, 'utf16le'));
	return names.some(name => buffer.includes(name));
}

const PDF_ACTIVE = /\/(?:JavaScript|JS|Launch|EmbeddedFile|OpenAction\s*<<[^>]*\/(?:JS|JavaScript))\b/;

/**
 * Inspect a message's attachments.
 *
 * Reports each finding as { type, filename, message, score }:
 * - executable: a program, script, installer or shortcut (by extension or content)
 * - disguised_executable: content is a program but the name says otherwise
 * - double_extension: "invoice.pdf.exe"
 * - rtl_override: a right-to-left override hides the real extension (a file named "invoice", U+202E, "fdp.exe" shows as "invoiceexe.pdf")
 * - executable_in_archive: a ZIP holds a program, read without unpacking
 * - encrypted_archive: a password-protected ZIP, which virus scanners cannot open
 * - macro: an Office document with a VBA project
 * - pdf_active: a PDF with JavaScript, launch actions or embedded files
 * - rtf_object: an RTF document with an embedded OLE object
 * - html_attachment: an HTML or SVG file, the usual carrier of fake login pages
 *
 * @param {Array<{filename?: string, contentType?: string, content?: Buffer}>} attachments
 * @returns {Array<{type: string, filename: string, message: string, extension?: string}>}
 */
export function inspectAttachments(attachments = []) {
	const findings = [];
	for (const attachment of attachments) {
		const filename = typeof attachment.filename === 'string' ? attachment.filename : '';
		const name = filename || 'unnamed attachment';
		const content = Buffer.isBuffer(attachment.content) ? attachment.content : null;
		const extension = extensionOf(filename);
		const detected = content ? sniff(content) : null;
		const add = (type, message, extra = {}) => findings.push({
			type, filename: name, message, ...extra,
		});

		if (BIDI_CONTROLS.test(filename)) {
			add('rtl_override', `Attachment "${name}" uses a right-to-left override to hide its real extension`);
		}

		const parts = filename.toLowerCase().split('.');
		if (parts.length >= 3 && EXECUTABLE_EXTENSIONS.has(extension) && DOCUMENT_EXTENSIONS.has(parts.at(-2))) {
			add('double_extension', `Attachment "${name}" has a document extension followed by a program extension`, {extension});
		}

		if (EXECUTABLE_EXTENSIONS.has(extension) && !MACRO_EXTENSIONS.has(extension)) {
			add('executable', `Attachment "${name}" is a file type that runs code (.${extension})`, {extension});
		} else if (detected?.executable) {
			add(extension && !EXECUTABLE_EXTENSIONS.has(extension) ? 'disguised_executable' : 'executable', `Attachment "${name}" contains a program (${detected.type})${extension ? ` but is named .${extension}` : ''}`, {extension: detected.type});
		}

		if (!content) {
			if (MACRO_EXTENSIONS.has(extension)) {
				add('macro', `Attachment "${name}" is an Office document type that holds macros (.${extension})`, {extension});
			}

			continue;
		}

		if (detected?.type === 'zip' || detected?.type === 'docx' || detected?.type === 'xlsx' || detected?.type === 'pptx') {
			const entries = zipEntries(content);
			if (entries.some(entry => /(?:^|\/)vbaproject\.bin$/i.test(entry.name))) {
				add('macro', `Attachment "${name}" is an Office document with a VBA macro project`, {extension});
			} else if (MACRO_EXTENSIONS.has(extension)) {
				add('macro', `Attachment "${name}" is an Office document type that holds macros (.${extension})`, {extension});
			}

			if (detected.type === 'zip') {
				const inner = entries.filter(entry => EXECUTABLE_EXTENSIONS.has(extensionOf(entry.name)));
				if (inner.length > 0) {
					add('executable_in_archive', `Archive "${name}" contains ${inner.length === 1 ? 'a program' : `${inner.length} programs`} (${inner.slice(0, 3).map(entry => entry.name.split('/').pop()).join(', ')})`, {extension: extensionOf(inner[0].name)});
				}

				if (entries.some(entry => entry.encrypted)) {
					add('encrypted_archive', `Archive "${name}" is password protected, so its contents cannot be scanned`, {extension});
				}
			}
		} else if (detected?.type === 'ole') {
			if (oleHasMacros(content)) {
				add('macro', `Attachment "${name}" is an Office document with a VBA macro project`, {extension});
			}
		} else if (detected?.type === 'pdf' || extension === 'pdf') {
			if (PDF_ACTIVE.test(content.toString('latin1'))) {
				add('pdf_active', `PDF "${name}" contains JavaScript, a launch action or an embedded file`, {extension: 'pdf'});
			}
		} else if (detected?.type === 'rtf' && /\\object\b|\\objdata\b|\\objupdate\b/.test(content.toString('latin1'))) {
			add('rtf_object', `RTF document "${name}" embeds an OLE object`, {extension: 'rtf'});
		}

		if (detected?.type === 'html' || detected?.type === 'svg' || ['htm', 'html', 'shtml', 'xhtml', 'svg'].includes(extension)) {
			const text = content.subarray(0, 200_000).toString('utf8');
			const active = /<script\b|<form\b|\bon(?:load|error|click)\s*=|javascript:|window\.location|document\.location|atob\(/i.test(text);
			add('html_attachment', `Attachment "${name}" is ${detected?.type === 'svg' || extension === 'svg' ? 'an SVG image' : 'a web page'}${active ? ' with scripts or forms' : ''}`, {extension: extension || detected?.type, active});
		}
	}

	return findings;
}
