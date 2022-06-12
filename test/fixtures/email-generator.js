const Chance = require('chance');

function setupChance(config) {
  const chance = new Chance();

  chance.mixin({
    urls() {
      const ret = [];

      for (let i = 0; i < chance.integer(config.urls); i++) {
        ret.push(chance.url());
      }

      return ret;
    }
  });

  return chance;
}

function generateEmail(config) {
  config = {
    urls: {
      max: 1,
      min: 1
    },
    ...config
  };

  const chance = setupChance(config);

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
      alpha: true,
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
    ...chance.urls(),
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
