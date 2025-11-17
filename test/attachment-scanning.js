import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Tests for attachment scanning functionality

const scanner = new SpamScanner({supportedLanguages: []});

// Helper to create email with attachment in MIME format
function createEmailWithAttachment(filename, content) {
	const boundary = '----=_Part_0_123456789.123456789';
	const contentBase64 = Buffer.from(content).toString('base64');

	return `From: sender@example.com
To: recipient@example.com
Subject: Document
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain; charset=utf-8

Please see the attached file.

--${boundary}
Content-Type: application/octet-stream; name="${filename}"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="${filename}"

${contentBase64}
--${boundary}--`;
}

// Test Office document macro detection

test('should detect Office document with macros (docm)', async () => {
	const email = createEmailWithAttachment('invoice.docm', 'fake docm content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect docm file');
	const macro = result.results.macros.find(m => m.subtype === 'office_document');
	assert.ok(macro, 'Should identify as office_document');
	assert.ok(macro.filename.includes('docm'), 'Should include filename');
});

test('should detect Excel with macros (xlsm)', async () => {
	const email = createEmailWithAttachment('spreadsheet.xlsm', 'fake xlsm content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect xlsm file');
	const macro = result.results.macros.find(m => m.subtype === 'office_document');
	assert.ok(macro, 'Should identify as office_document');
});

test('should detect PowerPoint with macros (pptm)', async () => {
	const email = createEmailWithAttachment('presentation.pptm', 'fake pptm content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect pptm file');
	const macro = result.results.macros.find(m => m.subtype === 'office_document');
	assert.ok(macro, 'Should identify as office_document');
});

test('should detect Excel add-in with macros (xlam)', async () => {
	const email = createEmailWithAttachment('addin.xlam', 'fake xlam content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect xlam file');
});

test('should detect Word template with macros (dotm)', async () => {
	const email = createEmailWithAttachment('template.dotm', 'fake dotm content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect dotm file');
});

test('should detect Excel template with macros (xltm)', async () => {
	const email = createEmailWithAttachment('template.xltm', 'fake xltm content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect xltm file');
});

test('should detect PowerPoint template with macros (potm)', async () => {
	const email = createEmailWithAttachment('template.potm', 'fake potm content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect potm file');
});

// Test legacy Office format detection

test('should detect legacy Word document (doc)', async () => {
	const email = createEmailWithAttachment('document.doc', 'fake doc content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect doc file');
	const macro = result.results.macros.find(m => m.subtype === 'legacy_office');
	assert.ok(macro, 'Should identify as legacy_office');
	assert.strictEqual(macro.risk, 'high', 'Should mark as high risk');
});

test('should detect legacy Excel document (xls)', async () => {
	const email = createEmailWithAttachment('spreadsheet.xls', 'fake xls content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect xls file');
	const macro = result.results.macros.find(m => m.subtype === 'legacy_office');
	assert.ok(macro, 'Should identify as legacy_office');
	assert.strictEqual(macro.risk, 'high', 'Should mark as high risk');
});

test('should detect legacy PowerPoint document (ppt)', async () => {
	const email = createEmailWithAttachment('presentation.ppt', 'fake ppt content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect ppt file');
	const macro = result.results.macros.find(m => m.subtype === 'legacy_office');
	assert.ok(macro, 'Should identify as legacy_office');
});

test('should detect legacy Word template (dot)', async () => {
	const email = createEmailWithAttachment('template.dot', 'fake dot content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect dot file');
	const macro = result.results.macros.find(m => m.subtype === 'legacy_office');
	assert.ok(macro, 'Should identify as legacy_office');
});

test('should detect legacy Excel template (xlt)', async () => {
	const email = createEmailWithAttachment('template.xlt', 'fake xlt content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect xlt file');
});

test('should detect legacy PowerPoint template (pot)', async () => {
	const email = createEmailWithAttachment('template.pot', 'fake pot content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect pot file');
});

test('should detect legacy Excel add-in (xla)', async () => {
	const email = createEmailWithAttachment('addin.xla', 'fake xla content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect xla file');
});

test('should detect legacy PowerPoint add-in (ppa)', async () => {
	const email = createEmailWithAttachment('addin.ppa', 'fake ppa content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect ppa file');
});

// Test PDF JavaScript detection

test('should detect PDF with JavaScript', async () => {
	const pdfWithJS = '%PDF-1.4\n/JavaScript (app.alert("Hello");)\n/JS (app.alert("Test");)';
	const email = createEmailWithAttachment('document.pdf', pdfWithJS);
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect PDF with JavaScript');
	const macro = result.results.macros.find(m => m.subtype === 'pdf_javascript');
	assert.ok(macro, 'Should identify as pdf_javascript');
	assert.strictEqual(macro.risk, 'medium', 'Should mark as medium risk');
});

test('should not flag clean PDF', async () => {
	const cleanPDF = '%PDF-1.4\nThis is a clean PDF with no JavaScript.';
	const email = createEmailWithAttachment('document.pdf', cleanPDF);
	const result = await scanner.scan(email);

	const pdfJS = result.results.macros.find(m => m.subtype === 'pdf_javascript');
	assert.ok(!pdfJS, 'Should not flag clean PDF');
});

test('should detect PDF with /JS tag', async () => {
	const pdfWithJS = '%PDF-1.4\n/JS (malicious code here)';
	const email = createEmailWithAttachment('invoice.pdf', pdfWithJS);
	const result = await scanner.scan(email);

	const macro = result.results.macros.find(m => m.subtype === 'pdf_javascript');
	assert.ok(macro, 'Should detect /JS tag in PDF');
});

// Test archive detection

test('should detect ZIP archive', async () => {
	const email = createEmailWithAttachment('files.zip', 'PK\u0003\u0004fake zip');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect zip archive');
	assert.strictEqual(archive.extension, 'zip', 'Should identify as zip');
	assert.strictEqual(archive.risk, 'medium', 'Should mark as medium risk');
});

test('should detect RAR archive', async () => {
	const email = createEmailWithAttachment('files.rar', 'Rar!fake rar');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect rar archive');
});

test('should detect 7z archive', async () => {
	const email = createEmailWithAttachment('files.7z', '7z\u00BC\u00AFfake 7z');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect 7z archive');
});

test('should detect TAR archive', async () => {
	const email = createEmailWithAttachment('files.tar', 'fake tar content');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect tar archive');
});

test('should detect GZ archive', async () => {
	const email = createEmailWithAttachment('files.gz', '\u001F\u008Bfake gz');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect gz archive');
});

test('should detect BZ2 archive', async () => {
	const email = createEmailWithAttachment('files.bz2', 'BZhfake bz2');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect bz2 archive');
});

test('should detect ISO image', async () => {
	const email = createEmailWithAttachment('disk.iso', 'fake iso content');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect iso image');
});

test('should detect CAB archive', async () => {
	const email = createEmailWithAttachment('files.cab', 'MSCFfake cab');
	const result = await scanner.scan(email);

	const archive = result.results.executables.find(item => item.type === 'archive');
	assert.ok(archive, 'Should detect cab archive');
});

// Test standalone macro scripts

test('should detect VBScript file (vbs)', async () => {
	const email = createEmailWithAttachment('script.vbs', 'MsgBox "Hello"');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect vbs file');
	const macro = result.results.macros.find(m => m.subtype === 'script');
	assert.ok(macro, 'Should identify as script');
});

test('should detect PowerShell script (ps1)', async () => {
	const email = createEmailWithAttachment('script.ps1', 'Write-Host "Hello"');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect ps1 file');
	const macro = result.results.macros.find(m => m.subtype === 'script');
	assert.ok(macro, 'Should identify as script');
});

test('should detect batch file (bat)', async () => {
	const email = createEmailWithAttachment('script.bat', '@echo off');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect bat file');
	const macro = result.results.macros.find(m => m.subtype === 'script');
	assert.ok(macro, 'Should identify as script');
});

test('should detect command file (cmd)', async () => {
	const email = createEmailWithAttachment('script.cmd', '@echo off');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect cmd file');
});

test('should detect screensaver file (scr)', async () => {
	const email = createEmailWithAttachment('fake.scr', 'MZ\u0090\u0000fake exe');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect scr file');
});

test('should detect PIF file (pif)', async () => {
	const email = createEmailWithAttachment('fake.pif', 'fake pif content');
	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length > 0, 'Should detect pif file');
});

// Test that safe files are not flagged

test('should not flag safe Office documents (docx)', async () => {
	const email = createEmailWithAttachment('document.docx', 'safe docx content');
	const result = await scanner.scan(email);

	// Docx should not be flagged as macro-capable
	const macroDoc = result.results.macros.find(m => m.filename && m.filename.includes('docx'));
	assert.ok(!macroDoc, 'Should not flag safe docx');
});

test('should not flag safe Excel documents (xlsx)', async () => {
	const email = createEmailWithAttachment('spreadsheet.xlsx', 'safe xlsx content');
	const result = await scanner.scan(email);

	const macroDoc = result.results.macros.find(m => m.filename && m.filename.includes('xlsx'));
	assert.ok(!macroDoc, 'Should not flag safe xlsx');
});

test('should not flag safe PowerPoint documents (pptx)', async () => {
	const email = createEmailWithAttachment('presentation.pptx', 'safe pptx content');
	const result = await scanner.scan(email);

	const macroDoc = result.results.macros.find(m => m.filename && m.filename.includes('pptx'));
	assert.ok(!macroDoc, 'Should not flag safe pptx');
});

test('should not flag text files', async () => {
	const email = createEmailWithAttachment('document.txt', 'This is a text file.');
	const result = await scanner.scan(email);

	const macroDoc = result.results.macros.find(m => m.filename && m.filename.includes('txt'));
	assert.ok(!macroDoc, 'Should not flag text files');
});

test('should not flag image files', async () => {
	const email = createEmailWithAttachment('image.jpg', '\u00FF\u00D8\u00FFfake jpg');
	const result = await scanner.scan(email);

	const macroDoc = result.results.macros.find(m => m.filename && m.filename.includes('jpg'));
	assert.ok(!macroDoc, 'Should not flag image files');
});

// Test multiple attachments

test('should detect multiple dangerous attachments', async () => {
	const boundary = '----=_Part_0_123456789.123456789';
	const email = `From: sender@example.com
To: recipient@example.com
Subject: Files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

Multiple attachments

--${boundary}
Content-Type: application/octet-stream; name="invoice.docm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.docm"

${Buffer.from('fake docm').toString('base64')}
--${boundary}
Content-Type: application/octet-stream; name="data.xlsm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="data.xlsm"

${Buffer.from('fake xlsm').toString('base64')}
--${boundary}
Content-Type: application/octet-stream; name="files.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="files.zip"

${Buffer.from('PK\u0003\u0004fake zip').toString('base64')}
--${boundary}--`;

	const result = await scanner.scan(email);

	assert.ok(result.results.macros.length >= 2, 'Should detect both Office documents');
	assert.ok(result.results.executables.length > 0, 'Should detect archive');
});

test('should handle mix of safe and dangerous attachments', async () => {
	const boundary = '----=_Part_0_123456789.123456789';
	const email = `From: sender@example.com
To: recipient@example.com
Subject: Files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

Mixed attachments

--${boundary}
Content-Type: application/octet-stream; name="document.docx"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="document.docx"

${Buffer.from('safe docx').toString('base64')}
--${boundary}
Content-Type: application/octet-stream; name="invoice.doc"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.doc"

${Buffer.from('dangerous doc').toString('base64')}
--${boundary}
Content-Type: application/octet-stream; name="image.png"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="image.png"

${Buffer.from('\u0089PNGfake png').toString('base64')}
--${boundary}--`;

	const result = await scanner.scan(email);

	// Should only flag the .doc file
	const macros = result.results.macros.filter(m => m.filename);
	assert.ok(macros.length > 0, 'Should detect dangerous doc');
	assert.ok(macros.some(m => m.filename.includes('doc')), 'Should flag .doc file');
});
