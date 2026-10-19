import {Buffer} from 'node:buffer';
import {linear, trimEndOf} from './linear.js';
import {characterClass} from './tokenizer.js';

/**
 * File extensions that run code when opened, on Windows, macOS, Linux and
 * Android: programs, installers, scripts, shortcuts, and disk images that
 * mail filters are bypassed with. Based on the attachment types Outlook blocks
 * by default, plus the scripting and container formats used in malware
 * campaigns.
 */
export const EXECUTABLE_EXTENSIONS = new Set([
	'ade', 'adp', 'apk', 'app', 'appimage', 'application', 'appref-ms', 'appx', 'appxbundle', 'asp', 'aspx', 'asx', 'bas', 'bat', 'bgi', 'cab', 'chm', 'cmd', 'cnt', 'com', 'command', 'cpl', 'csh', 'diagcab', 'dll', 'dmg', 'docm', 'dotm', 'elf', 'exe', 'fxp', 'gadget', 'grp', 'hlp', 'hpj', 'hta', 'htc', 'img', 'inf', 'ins', 'ipa', 'iso', 'isp', 'its', 'jar', 'jnlp', 'js', 'jse', 'ksh', 'lnk', 'mad', 'maf', 'mag', 'mam', 'maq', 'mar', 'mas', 'mau', 'mav', 'maw', 'mcf', 'mda', 'mde', 'mdt', 'mdw', 'mdz', 'msc', 'msh', 'msh1', 'msh1xml', 'msh2', 'msh2xml', 'mshxml', 'msi', 'msix', 'msixbundle', 'msp', 'mst', 'msu', 'nsh', 'ops', 'osd', 'pcd', 'pif', 'pkg', 'pl', 'plg', 'potm', 'ppam', 'ppsm', 'pptm', 'prf', 'prg', 'ps1', 'ps1xml', 'ps2', 'ps2xml', 'psc1', 'psc2', 'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw', 'reg', 'scf', 'scpt', 'scr', 'sct', 'settingcontent-ms', 'sh', 'shb', 'shs', 'slk', 'sys', 'vb', 'vbe', 'vbp', 'vbs', 'vhd', 'vhdx', 'vsmacros', 'vsw', 'webpnp', 'website', 'ws', 'wsb', 'wsc', 'wsf', 'wsh', 'xbap', 'xlam', 'xll', 'xlsm', 'xltm', 'xnk',
]);

/**
 * File extensions Outlook blocks that are risky by name rather than programs:
 * certificates (installing one trusts whoever holds its key), Internet
 * shortcuts, Windows themes, and data files people send every day (MATLAB
 * data, Outlook data, temporary files). Reported as risky_attachment, with
 * few points.
 */
export const RISKY_EXTENSIONS = new Set(['cer', 'der', 'mat', 'pst', 'theme', 'tmp', 'url']);

// Scripts that developers and students share (a zipped website or homework):
// in an archive they count for fewer points than native programs.
const SCRIPT_EXTENSIONS = new Set(['asp', 'aspx', 'csh', 'js', 'ksh', 'pl', 'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw', 'sh']);

// Office formats whose file name says they may contain macros.
const MACRO_EXTENSIONS = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppsm', 'ppam', 'sldm']);

// Formats people send every day; one of these before an executable extension
// ("invoice.pdf.exe") is a disguise.
const DOCUMENT_EXTENSIONS = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'csv', 'odt', 'ods', 'html', 'htm', 'mp3', 'mp4', 'mov', 'wav', 'eml', 'msg', 'xml', 'json']);

// Suffixes Office and editors add to a document's name for a temporary copy
// ("report.xlsx.tmp"): not a disguise.
const TEMPORARY_EXTENSIONS = new Set(['tmp']);

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

	// A Windows program: "MZ", and "PE\0\0" where its header says (text can
	// start with "MZ" too, such as a list of country codes).
	if (ascii(0, 'MZ') && buffer.length >= 64 && at(buffer.readUInt32LE(0x3C), [0x50, 0x45, 0x00, 0x00])) {
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
		const names = entriesOf(buffer).map(entry => entry.name);
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

const ZIP_FAMILY = new Set(['zip', 'docx', 'xlsx', 'pptx']);
const OFFICE_TYPES = new Set(['docx', 'xlsx', 'pptx']);
// What Office embeds in a document: other documents (with macros too, which
// are reported as macros).
const OFFICE_EMBEDDED = MACRO_EXTENSIONS;

// The entries of each ZIP attachment, read once (by sniff and by
// inspectAttachments).
const ENTRIES = new WeakMap();
function entriesOf(buffer) {
	let entries = ENTRIES.get(buffer);
	if (!entries) {
		entries = zipEntries(buffer);
		ENTRIES.set(buffer, entries);
	}

	return entries;
}

/**
 * The entries of a ZIP file, read from its central directory without
 * decompressing anything: name, sizes, and whether the entry is encrypted.
 *
 * Every end record that ends the file (its comment running to the last byte)
 * is read, as well as the last one found: archive programs differ in which
 * they use, so a directory hidden behind another record is read too.  ZIP64
 * archives, and archives after other data (self-extracting archives), are
 * read as well.
 * @param {Buffer} buffer
 * @param {number} [limit] - most entries to read
 * @returns {Array<{name: string, encrypted: boolean, size: number}>}
 */
export function zipEntries(buffer, limit = 2000) {
	// End of central directory: within the last 64 KiB plus 22 bytes.
	const start = Math.max(0, buffer.length - 65_557);
	const records = [];
	for (let i = buffer.length - 22; i >= start; i--) {
		if (buffer.readUInt32LE(i) === 0x06_05_4B_50 && (records.length === 0 || i + 22 + buffer.readUInt16LE(i + 20) === buffer.length)) {
			records.push(i);
		}
	}

	// (each directory once, and at most `limit` entries in all)
	const entries = [];
	const read = new Set();
	for (const eocd of records) {
		const offset = directoryOf(buffer, eocd);
		if (offset !== -1 && !read.has(offset)) {
			read.add(offset);
			readDirectory(buffer, offset, limit - entries.length, entries);
		}
	}

	return entries;
}

const DIRECTORY = 0x02_01_4B_50;
const isDirectory = (buffer, offset) => offset >= 0 && offset + 46 <= buffer.length && buffer.readUInt32LE(offset) === DIRECTORY;

// Where the central directory of an end record starts, or -1.
function directoryOf(buffer, eocd) {
	let offset = buffer.readUInt32LE(eocd + 16);
	let size = buffer.readUInt32LE(eocd + 12);
	// ZIP64: the offset and size are in the ZIP64 end record, which a locator
	// right before this record points to.
	const locator = eocd - 20;
	if ((offset === 0xFF_FF_FF_FF || size === 0xFF_FF_FF_FF) && locator >= 0 && buffer.readUInt32LE(locator) === 0x07_06_4B_50) {
		// (or, after other data, right before the locator)
		const stated = Number(buffer.readBigUInt64LE(locator + 8));
		const isRecord = at => at >= 0 && at + 56 <= locator && buffer.readUInt32LE(at) === 0x06_06_4B_50;
		const record = isRecord(stated) ? stated : locator - 56;
		if (isRecord(record)) {
			size = Number(buffer.readBigUInt64LE(record + 40));
			offset = Number(buffer.readBigUInt64LE(record + 48));
		}
	}

	if (isDirectory(buffer, offset)) {
		return offset;
	}

	// (after other data, as in a self-extracting archive, the directory is
	// right before its end records, whatever offset they give)
	for (const end of [eocd, locator - 56]) {
		const directory = end - size;
		if (directory < end && isDirectory(buffer, directory)) {
			return directory;
		}
	}

	return -1;
}

// Read up to `count` directory entries from `offset` into `entries`.
function readDirectory(buffer, offset, count, entries) {
	for (let n = 0; n < count && isDirectory(buffer, offset); n++) {
		const flags = buffer.readUInt16LE(offset + 8);
		const size = buffer.readUInt32LE(offset + 24);
		const nameLength = buffer.readUInt16LE(offset + 28);
		const extraLength = buffer.readUInt16LE(offset + 30);
		const commentLength = buffer.readUInt16LE(offset + 32);
		const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString(flags & 0x8_00 ? 'utf8' : 'latin1');
		entries.push({name, encrypted: (flags & 1) === 1, size});
		offset += 46 + nameLength + extraLength + commentLength;
	}
}

// (Windows drops dots and spaces at the end of a file name: "run.js." runs)
function extensionOf(name) {
	const base = trimEndOf(String(name).toLowerCase().split(/[/\\]/).pop(), '. ');
	const dot = base.lastIndexOf('.');
	return dot === -1 ? '' : base.slice(dot + 1).trim();
}

// The names of the storages and streams of a VBA project (case does not
// matter in a compound file).
const VBA_NAMES = new Set(['vba', '_vba_project', '_vba_project_cur', 'macros']);

function oleHasMacros(buffer) {
	// VBA projects live in storages named "VBA", "_VBA_PROJECT_CUR" (Excel)
	// or "Macros" (Word), with a "_VBA_PROJECT" stream. These are entries of
	// the compound file's directory: 128 bytes each, at 128-byte boundaries
	// after the header, with a UTF-16LE name, its length in bytes (with the
	// final null) at 64 and its type at 66 (1 storage, 2 stream). Text that
	// mentions these names, as an Outlook message may, is not an entry.
	for (let offset = 512; offset + 128 <= buffer.length; offset += 128) {
		const length = buffer.readUInt16LE(offset + 64);
		const type = buffer[offset + 66];
		if ((type === 1 || type === 2) && length >= 4 && length <= 64 && length % 2 === 0 && VBA_NAMES.has(buffer.subarray(offset, offset + length - 2).toString('utf16le').toLowerCase())) {
			return true;
		}
	}

	return false;
}

// Actions a PDF runs: script and launch actions. (An /OpenAction that runs
// script names /JS or /JavaScript, which this matches wherever it is, so the
// action itself is not looked for: "<<[^>]*" would read the rest of the file
// again from every /OpenAction.) Embedded files are not active content: every
// ZUGFeRD or Factur-X e-invoice carries one.
const PDF_ACTIVE = linear(String.raw`\/(?:JavaScript|JS|Launch)\b`);

// A PDF name with a character written as #xx ("/J#61vaScript" is
// "/JavaScript"), decoded before it is matched.
const PDF_ESCAPED_NAME = /\/[^\s/<>[\]()%{}]*#[\dA-Fa-f]{2}[^\s/<>[\]()%{}]*/g;
const decodePdfNames = text => text.replaceAll(PDF_ESCAPED_NAME, name => name.replaceAll(/#([\dA-Fa-f]{2})/g, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16))));

/**
 * Inspect a message's attachments.
 *
 * Reports each finding as { type, filename, message, score }:
 * - executable: a program, script, installer or shortcut (by extension or content)
 * - disguised_executable: content is a program but the name says otherwise
 * - double_extension: "invoice.pdf.exe"
 * - rtl_override: a right-to-left override hides the real extension (a file named "invoice", U+202E, "fdp.exe" shows as "invoiceexe.pdf")
 * - risky_attachment: a type that is risky by name but not a program
 *   (a certificate, an Internet shortcut, a theme; see RISKY_EXTENSIONS)
 * - executable_in_archive: a ZIP holds a program, read without unpacking
 *   (extension: the first program's, extensions: every program's)
 * - script_in_archive: a ZIP holds scripts (JavaScript, Python, shell, Perl)
 *   but no other programs
 * - encrypted_archive: a password-protected ZIP, which virus scanners cannot open
 * - macro: an Office document with a VBA project
 * - pdf_active: a PDF with JavaScript or launch actions
 * - rtf_object: an RTF document with an embedded OLE object
 * - html_attachment: an HTML or SVG file, the usual carrier of fake login pages
 *
 * @param {Array<{filename?: string, contentType?: string, content?: Buffer}>} attachments
 * @returns {Array<{type: string, filename: string, message: string, extension?: string, extensions?: string[]}>}
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

		// (also "invoice.pdf .exe", a space before the last dot)
		const parts = trimEndOf(filename.toLowerCase(), '. ').split('.');
		if (parts.length >= 3 && (EXECUTABLE_EXTENSIONS.has(extension) || RISKY_EXTENSIONS.has(extension)) && !TEMPORARY_EXTENSIONS.has(extension) && DOCUMENT_EXTENSIONS.has(parts.at(-2).trim())) {
			add('double_extension', `Attachment "${name}" has a document extension followed by a program extension`, {extension});
		}

		// A program by its content, whatever it is named (also as a script, a
		// file type that runs code too, but is often allowed); a script by its
		// name, else by its content.
		const byName = EXECUTABLE_EXTENSIONS.has(extension) && !MACRO_EXTENSIONS.has(extension);
		if (detected?.executable && (detected.type !== 'script' || !byName)) {
			add(extension && !EXECUTABLE_EXTENSIONS.has(extension) ? 'disguised_executable' : 'executable', `Attachment "${name}" contains a program (${detected.type})${extension && extension !== detected.type ? ` but is named .${extension}` : ''}`, {extension: detected.type});
		} else if (byName) {
			add('executable', `Attachment "${name}" is a file type that runs code (.${extension})`, {extension});
		} else if (RISKY_EXTENSIONS.has(extension)) {
			add('risky_attachment', `Attachment "${name}" is a risky file type (.${extension})`, {extension});
		}

		// (a document named as one that holds macros counts only with a VBA
		//  project inside)
		if (!content) {
			continue;
		}

		// (a ZIP named .zip after other data, as self-extracting archives are,
		//  opens in archive programs too)
		const zipFamily = ZIP_FAMILY.has(detected?.type) || (extension === 'zip' && !detected?.executable && entriesOf(content).length > 0);
		if (zipFamily) {
			const entries = entriesOf(content);
			const office = OFFICE_TYPES.has(detected?.type);
			if (entries.some(entry => /(?:^|\/)vbaproject\.bin$/i.test(entry.name))) {
				add('macro', `Attachment "${name}" is an Office document with a VBA macro project`, {extension});
			} else if (office && entries.some(entry => MACRO_EXTENSIONS.has(extensionOf(entry.name)))) {
				// (as Office names an embedded workbook or document with macros:
				//  "word/embeddings/Microsoft_Excel_Macro-Enabled_Worksheet.xlsm")
				add('macro', `Attachment "${name}" is an Office document holding another with macros`, {extension});
			}

			// (an Office document holding a program is an archive of programs
			// too; not the documents and certificates Office itself embeds)
			const inner = entries.filter(entry => EXECUTABLE_EXTENSIONS.has(extensionOf(entry.name)) && !(office && OFFICE_EMBEDDED.has(extensionOf(entry.name))));
			const details = {extension: extensionOf(inner[0]?.name ?? ''), extensions: [...new Set(inner.map(entry => extensionOf(entry.name)))]};
			const listed = inner.slice(0, 3).map(entry => entry.name.split('/').pop()).join(', ');
			if (inner.some(entry => !SCRIPT_EXTENSIONS.has(extensionOf(entry.name)))) {
				add('executable_in_archive', `Archive "${name}" contains ${inner.length === 1 ? 'a program' : `${inner.length} programs`} (${listed})`, details);
			} else if (inner.length > 0) {
				add('script_in_archive', `Archive "${name}" contains ${inner.length === 1 ? 'a script' : `${inner.length} scripts`} (${listed})`, details);
			}

			// (archives only: Office documents are encrypted otherwise)
			if ((detected?.type === 'zip' || !ZIP_FAMILY.has(detected?.type)) && entries.some(entry => entry.encrypted)) {
				add('encrypted_archive', `Archive "${name}" is password protected, so its contents cannot be scanned`, {extension});
			}
		} else if (detected?.type === 'ole') {
			if (oleHasMacros(content)) {
				add('macro', `Attachment "${name}" is an Office document with a VBA macro project`, {extension});
			}
		} else if (detected?.type === 'pdf' || extension === 'pdf') {
			if (PDF_ACTIVE.test(decodePdfNames(content.toString('latin1')))) {
				add('pdf_active', `PDF "${name}" contains JavaScript or a launch action`, {extension: 'pdf'});
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
