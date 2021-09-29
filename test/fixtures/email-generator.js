const chance = require('chance').Chance();

function generateEmail() {
  const ret = [];
  const domain = chance.domain();
  const fromEmail = chance.email({ domain });

  // Headers
  ret.push(
    `Return-Path: ${fromEmail}`,
    `To: ${chance.email()}`,
    `From: ${fromEmail}`,
    `Subject: ${chance.sentence({ words: 3 })}`,
    `Messeage-Id: <${chance.string({
      length: 8,
      alpah: true,
      numeric: true
    })}@${domain}>`,
    `Date: ${chance.date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_15328"`,
    ``,
    // text part
    `----=_MIME_BOUNDARY_000_15328`,
    `Content-Type: text/plain`,
    ``,
    chance.paragraph(),
    chance.url(),
    chance.email(),
    chance.phone(),
    chance.paragraph(),
    ``,
    // executable
    `----=_MIME_BOUNDARY_000_15328`,
    `Content-Type: application/octet-stream; name="hello_world.exe"`,
    `Content-Description: hello_world.exe`,
    `Content-Disposition: attachment; filename="hello_world.exe"`,
    `Content-Transfer-Encoding: BASE64`,
    ``,
    `f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAUBAAAAAAAABAAAAAAAAAAGA5AAAAAAAAAAAAAEAAOAAL`,
    ``,
    // end
    `----=_MIME_BOUNDARY_000_15328--`
  );

  return ret.join('\n');
}

module.exports = generateEmail;
