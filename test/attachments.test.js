import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {
	EXECUTABLE_EXTENSIONS, inspectAttachments, sniff, zipEntries,
} from '../src/attachments.js';
import {zip} from './helpers/index.js';

const bytes = (...values) => Buffer.from(values);
const pad = (head, size = 64) => Buffer.concat([Buffer.isBuffer(head) ? head : Buffer.from(head, 'latin1'), Buffer.alloc(size)]);
// The start of a Windows program: "MZ", and "PE\\0\\0" where its header says.
const pe = () => {
	const buffer = Buffer.alloc(0x48);
	buffer.write('MZ', 0, 'latin1');
	buffer.writeUInt32LE(0x40, 0x3C);
	buffer.write('PE\0\0', 0x40, 'latin1');
	return buffer;
};

const ole = (...names) => Buffer.concat([bytes(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1), Buffer.alloc(32), ...names.map(name => Buffer.from(name, 'utf16le'))]);
const iso = () => {
	const buffer = Buffer.alloc(0x80_10);
	buffer.write('CD001', 0x80_01, 'latin1');
	return buffer;
};

const types = attachments => inspectAttachments(attachments).map(finding => finding.type);

describe('sniff', () => {
	const cases = [
		['exe', pe(), true],
		['elf', pad(bytes(0x7F, 0x45, 0x4C, 0x46)), true],
		['macho', pad(bytes(0xFE, 0xED, 0xFA, 0xCF)), true],
		['macho', pad(bytes(0xCF, 0xFA, 0xED, 0xFE)), true],
		['macho', pad(bytes(0xCA, 0xFE, 0xBA, 0xBE)), true],
		['lnk', pad(bytes(0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00)), true],
		['ole', ole(), false],
		['docx', zip([{name: 'word/document.xml', content: '<w/>'}]), false],
		['xlsx', zip([{name: 'xl/workbook.xml', content: '<x/>'}]), false],
		['pptx', zip([{name: 'ppt/presentation.xml', content: '<p/>'}]), false],
		['jar', zip([{name: 'META-INF/MANIFEST.MF', content: 'x'}, {name: 'a/B.class', content: 'x'}]), true],
		['apk', zip([{name: 'AndroidManifest.xml', content: 'x'}]), true],
		['zip', zip([{name: 'readme.txt', content: 'hello'}]), false],
		['zip', pad(bytes(0x50, 0x4B, 0x05, 0x06), 18), false],
		['rar', pad('Rar!'), false],
		['7z', pad(bytes(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)), false],
		['gz', pad(bytes(0x1F, 0x8B, 0x08, 0x00)), false],
		['cab', pad('MSCF'), false],
		['iso', iso(), false],
		['vhd', pad('conectix'), true],
		['vhd', pad('vhdxfile'), true],
		['pdf', pad('%PDF-1.7'), false],
		['rtf', pad(String.raw`{\rtf1`), false],
		['png', pad(bytes(0x89, 0x50, 0x4E, 0x47)), false],
		['jpg', pad(bytes(0xFF, 0xD8, 0xFF, 0xE0)), false],
		['gif', pad('GIF89a'), false],
		['webp', pad('RIFF\0\0\0\0WEBP'), false],
		['script', pad('#!/bin/sh\n'), true],
		['svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'), false],
		['svg', Buffer.from('<?xml version="1.0"?>\n<svg/>'), false],
		['html', Buffer.from('\u{FEFF}<!DOCTYPE html><title>x</title>'), false],
		['html', Buffer.from('<html><body>x</body></html>'), false],
		['html', Buffer.from('<head><title>x</title></head>'), false],
		['html', Buffer.from('<script>alert(1)</script>'), false],
	];
	for (const [type, buffer, executable] of cases) {
		it(`recognises ${type}${executable ? ' as a program' : ''}`, () => {
			const result = sniff(buffer);
			assert.equal(result?.type, type);
			assert.equal(result.executable, executable);
		});
	}

	it('marks archives', () => {
		assert.equal(sniff(pad('Rar!')).archive, true);
		assert.equal(sniff(pad('%PDF')).archive, false);
	});

	it('returns null for unknown, short and non-buffer input', () => {
		assert.equal(sniff(Buffer.from('plain text file')), null);
		assert.equal(sniff(Buffer.from('MZ')), null);
		assert.equal(sniff('MZ....'), null);
		// (text that starts with "MZ" is not a program)
		assert.equal(sniff(pad('MZ')), null);
		assert.equal(sniff(Buffer.from('MZ,Mozambique\nNA,Namibia\n'.repeat(4))), null);
		const far = pe();
		far.writeUInt32LE(0x10_00, 0x3C);
		assert.equal(sniff(far), null);
	});
});

describe('zipEntries', () => {
	it('lists entries without unpacking, with encryption flags and UTF-8 names', () => {
		const file = zip([{name: 'a.txt', content: 'x'}, {name: 'secret.exe', content: 'y', encrypted: true}]);
		assert.deepEqual(zipEntries(file), [{name: 'a.txt', encrypted: false, size: 1}, {name: 'secret.exe', encrypted: true, size: 1}]);
		const utf8 = zip([{name: 'résumé.pdf', content: 'x'}]);
		utf8.writeUInt16LE(0x8_00, utf8.indexOf(Buffer.from([0x50, 0x4B, 0x01, 0x02])) + 8);
		assert.equal(zipEntries(utf8)[0].name, 'résumé.pdf');
		assert.equal(zipEntries(zip([{name: 'a', content: 'x'}, {name: 'b', content: 'y'}]), 1).length, 1);
	});

	it('copes with damaged files', () => {
		assert.deepEqual(zipEntries(Buffer.alloc(100)), []);
		const broken = zip([{name: 'a.txt', content: 'x'}]);
		// (a wrong directory offset: the directory right before the end record)
		broken.writeUInt32LE(0xFF_FF, broken.length - 6);
		assert.deepEqual(zipEntries(broken).map(entry => entry.name), ['a.txt']);
		// (and a wrong directory size too, or one larger than the file)
		broken.writeUInt32LE(1, broken.length - 10);
		assert.deepEqual(zipEntries(broken), []);
		broken.writeUInt32LE(0xFF_FF_FF, broken.length - 10);
		assert.deepEqual(zipEntries(broken), []);
	});
});

// A ZIP64 archive: the end record's offset and size in a ZIP64 end record
// that a locator points to (`shift` moves the offsets, as data in front
// does).
function zip64(entries, shift = 0) {
	const plain = zip(entries);
	const eocd = plain.length - 22;
	const size = plain.readUInt32LE(eocd + 12);
	const offset = plain.readUInt32LE(eocd + 16);
	const record = Buffer.alloc(56);
	record.writeUInt32LE(0x06_06_4B_50, 0);
	record.writeBigUInt64LE(BigInt(size), 40);
	record.writeBigUInt64LE(BigInt(offset + shift), 48);
	const locator = Buffer.alloc(20);
	locator.writeUInt32LE(0x07_06_4B_50, 0);
	locator.writeBigUInt64LE(BigInt(eocd + shift), 8);
	const end = Buffer.from(plain.subarray(eocd));
	end.writeUInt16LE(0xFF_FF, 10);
	end.writeUInt32LE(0xFF_FF_FF_FF, 12);
	end.writeUInt32LE(0xFF_FF_FF_FF, 16);
	return Buffer.concat([plain.subarray(0, eocd), record, locator, end]);
}

describe('ZIP end records', () => {
	it('reads ZIP64 archives, also after other data', () => {
		assert.deepEqual(zipEntries(zip64([{name: 'run.exe', content: 'x'}])).map(entry => entry.name), ['run.exe']);
		assert.deepEqual(zipEntries(Buffer.concat([Buffer.from('GIF89a'), zip64([{name: 'run.exe', content: 'x'}])])).map(entry => entry.name), ['run.exe']);
		// (a locator pointing elsewhere: the record right before it; and no
		//  ZIP64 record at all)
		const broken = zip64([{name: 'a.txt', content: 'x'}]);
		broken.writeBigUInt64LE(0xFF_FF_FF_FFn, broken.length - 22 - 12);
		assert.deepEqual(zipEntries(broken).map(entry => entry.name), ['a.txt']);
		const unsigned = zip64([{name: 'a.txt', content: 'x'}]);
		unsigned.writeUInt32LE(0, unsigned.length - 22 - 20 - 56);
		assert.deepEqual(zipEntries(unsigned), []);
	});

	it('reads every end record that ends the file, so a decoy in the comment hides nothing', () => {
		const decoy = zip([{name: 'readme.txt', content: 'x'}]);
		const real = zip([{name: 'run.exe', content: 'y'}]);
		// (the decoy's directory and end record in the real archive's comment,
		//  its offset pointing at its directory there)
		const directory = decoy.subarray(decoy.length - 22 - decoy.readUInt32LE(decoy.length - 22 + 12));
		const comment = Buffer.from(directory);
		comment.writeUInt32LE(real.length + (directory.length - 22) - comment.readUInt32LE(comment.length - 22 + 12), comment.length - 22 + 16);
		real.writeUInt16LE(comment.length, real.length - 2);
		const archive = Buffer.concat([real, comment]);
		assert.deepEqual(zipEntries(archive).map(entry => entry.name).sort(), ['readme.txt', 'run.exe']);
		assert.deepEqual(inspectAttachments([{filename: 'files.zip', content: archive}]).map(item => item.type), ['executable_in_archive']);
		// (two records with the same directory: read once)
		const twice = zip([{name: 'a.txt', content: 'x'}]);
		const again = Buffer.from(twice.subarray(-22));
		twice.writeUInt16LE(22, twice.length - 2);
		assert.deepEqual(zipEntries(Buffer.concat([twice, again])).map(entry => entry.name), ['a.txt']);
	});
});

describe('inspectAttachments', () => {
	it('flags programs by extension and by content', () => {
		assert.deepEqual(types([{filename: 'setup.exe', content: pe()}]), ['executable']);
		assert.deepEqual(types([{filename: 'tool.js', content: Buffer.from('x()')}]), ['executable']);
		assert.deepEqual(types([{filename: 'photo.jpg', content: pe()}]), ['disguised_executable']);
		assert.deepEqual(types([{content: pad(bytes(0x7F, 0x45, 0x4C, 0x46))}]), ['executable']);
		// (a program named as a script or another type that runs code, by its
		// content; a script by its name)
		const [program] = inspectAttachments([{filename: 'run.py', content: pe()}]);
		assert.deepEqual([program.type, program.extension], ['executable', 'exe']);
		assert.match(program.message, /contains a program \(exe\) but is named \.py/);
		const [script] = inspectAttachments([{filename: 'run.sh', content: Buffer.from('#!/bin/sh\necho hi\n')}]);
		assert.deepEqual([script.type, script.extension], ['executable', 'sh']);
		assert.deepEqual(types([{filename: 'countries.csv', content: Buffer.from('MZ,Mozambique\n'.repeat(8))}]), []);
		assert.ok(EXECUTABLE_EXTENSIONS.has('scr'));
		assert.ok(!EXECUTABLE_EXTENSIONS.has('dat'));
	});

	it('flags double extensions and right-to-left overrides', () => {
		assert.deepEqual(types([{filename: 'invoice.pdf.exe', content: pe()}]), ['double_extension', 'executable']);
		assert.deepEqual(types([{filename: 'invoice\u{202E}fdp.exe'}]), ['rtl_override', 'executable']);
		assert.deepEqual(types([{filename: 'archive.tar.gz', content: pad(bytes(0x1F, 0x8B))}]), []);
	});

	it('flags macros in modern and legacy Office files', () => {
		assert.deepEqual(types([{filename: 'report.docm'}]), ['macro']);
		assert.deepEqual(types([{filename: 'report.docm', content: zip([{name: 'word/document.xml', content: 'x'}])}]), ['macro']);
		assert.deepEqual(types([{filename: 'report.docx', content: zip([{name: 'word/document.xml', content: 'x'}, {name: 'word/vbaProject.bin', content: 'x'}])}]), ['macro']);
		assert.deepEqual(types([{filename: 'sheet.xls', content: ole('Workbook', '_VBA_PROJECT')}]), ['macro']);
		assert.deepEqual(types([{filename: 'letter.doc', content: ole('WordDocument')}]), []);
		assert.deepEqual(types([{filename: 'clean.docx', content: zip([{name: 'word/document.xml', content: 'x'}])}]), []);
	});

	it('looks inside ZIP archives without unpacking them', () => {
		assert.deepEqual(types([{filename: 'files.zip', content: zip([{name: 'docs/invoice.scr', content: 'x'}])}]), ['executable_in_archive']);
		// A name ending in dots or spaces, which Windows drops.
		assert.deepEqual(types([{filename: 'run.js.', content: Buffer.from('x')}]), ['executable']);
		assert.deepEqual(types([{filename: 'invoice.pdf.vbs. . ', content: Buffer.from('x')}]).sort(), ['double_extension', 'executable']);
		// Every program's extension, not only the first's.
		const [archive] = inspectAttachments([{filename: 'files.zip', content: zip([{name: 'run.sh', content: 'x'}, {name: 'payload.exe', content: 'x'}, {name: 'more.sh', content: 'x'}])}]);
		assert.equal(archive.extension, 'sh');
		assert.deepEqual(archive.extensions, ['sh', 'exe']);
		const many = inspectAttachments([{filename: 'files.zip', content: zip([{name: 'a.exe', content: 'x'}, {name: 'b.js', content: 'y'}])}]);
		assert.match(many[0].message, /2 programs/);
		assert.deepEqual(types([{filename: 'locked.zip', content: zip([{name: 'invoice.pdf', content: 'x', encrypted: true}])}]), ['encrypted_archive']);
		assert.deepEqual(types([{filename: 'photos.zip', content: zip([{name: 'a.jpg', content: 'x'}])}]), []);
	});

	it('reports documents with macros that Office embeds as macros, and leaves embedded certificates alone', () => {
		assert.deepEqual(types([{filename: 'report.docx', content: zip([{name: 'word/document.xml', content: 'x'}, {name: 'word/embeddings/Microsoft_Excel_Macro-Enabled_Worksheet.xlsm', content: 'x'}])}]), ['macro']);
		assert.deepEqual(types([{filename: 'deck.pptx', content: zip([{name: 'ppt/slides/slide1.xml', content: 'x'}, {name: 'ppt/embeddings/oleObject1.bin', content: 'x'}, {name: 'ppt/embeddings/signing.cer', content: 'x'}])}]), []);
		// (a program is still a program, and an archive is still an archive)
		assert.deepEqual(types([{filename: 'report.docx', content: zip([{name: 'word/document.xml', content: 'x'}, {name: 'word/embeddings/setup.exe', content: 'x'}])}]), ['executable_in_archive']);
		assert.deepEqual(types([{filename: 'files.zip', content: zip([{name: 'book.xlsm', content: 'x'}])}]), ['executable_in_archive']);
	});

	it('finds programs in Office documents and in ZIP archives after other data', () => {
		// (a ZIP with a word/ folder is read as a Word document)
		assert.deepEqual(types([{filename: 'files.zip', content: zip([{name: 'word/', content: ''}, {name: 'run.exe', content: 'x'}])}]), ['executable_in_archive']);
		// (as self-extracting archives are: the ZIP after other data)
		const prefixed = Buffer.concat([Buffer.from('GIF89a'), zip([{name: 'run.exe', content: 'x'}])]);
		assert.deepEqual(types([{filename: 'files.zip', content: prefixed}]), ['executable_in_archive']);
		assert.deepEqual(types([{filename: 'locked.zip', content: Buffer.concat([Buffer.from('GIF89a'), zip([{name: 'a.pdf', content: 'x', encrypted: true}])])}]), ['encrypted_archive']);
		// (only when named .zip, and not for other data or programs)
		assert.deepEqual(types([{filename: 'image.gif', content: prefixed}]), []);
		assert.deepEqual(types([{filename: 'image.zip', content: Buffer.from('GIF89a and no archive')}]), []);
		// (a password-protected part of an Office document is not reported)
		assert.deepEqual(types([{filename: 'report.docx', content: zip([{name: 'word/document.xml', content: 'x', encrypted: true}])}]), []);
	});

	it('flags active PDF and RTF content', () => {
		assert.deepEqual(types([{filename: 'form.pdf', content: pad('%PDF-1.7 /OpenAction << /JS (app.alert(1)) >>')}]), ['pdf_active']);
		assert.deepEqual(types([{filename: 'form.pdf', content: Buffer.from('not quite a pdf /JavaScript')}]), ['pdf_active']);
		assert.deepEqual(types([{filename: 'plain.pdf', content: pad('%PDF-1.7 just text')}]), []);
		assert.deepEqual(types([{filename: 'letter.rtf', content: pad(String.raw`{\rtf1 {\object\objemb {\objdata 0102}}}`)}]), ['rtf_object']);
		assert.deepEqual(types([{filename: 'letter.rtf', content: pad(String.raw`{\rtf1 hello}`)}]), []);
	});

	it('flags HTML and SVG attachments, noting scripts and forms', () => {
		const [page] = inspectAttachments([{filename: 'login.html', content: Buffer.from('<html><form action="https://evil.example"><input name="password"></form></html>')}]);
		assert.equal(page.type, 'html_attachment');
		assert.equal(page.active, true);
		const [svg] = inspectAttachments([{filename: 'logo.svg', content: Buffer.from('<svg><circle r="1"/></svg>')}]);
		assert.equal(svg.active, false);
		assert.match(svg.message, /SVG image/);
		const [sniffed] = inspectAttachments([{content: Buffer.from('<!DOCTYPE html><p onclick="x()">hi</p>')}]);
		assert.equal(sniffed.extension, 'html');
		assert.match(sniffed.filename, /unnamed/);
	});

	it('ignores ordinary files and attachments without content', () => {
		assert.deepEqual(types([{filename: 'photo.jpg', content: pad(bytes(0xFF, 0xD8, 0xFF))}, {filename: 'notes.txt'}, {}]), []);
		assert.deepEqual(inspectAttachments(), []);
	});
});
