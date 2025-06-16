const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { Buffer } = require('node:buffer');
const Redis = require('ioredis-mock');
const delay = require('delay');
const isCI = require('is-ci');
const memProfile = require('memoizee/profile');
const test = require('ava');
const { lookpath } = require('lookpath');
const SpamScanner = require('..');

function fixtures(name) {
  return path.join(__dirname, 'fixtures', name);
}

const scanner = new SpamScanner();

test('scans chinese email encoded', async (t) => {
  const { tokens, mail } = await scanner.getTokensAndMailFromSource(
    `TODO SOME CHINESE ENCODED EML`
  );
  console.log('tokens', tokens, 'mail', mail);
  t.fail();
});

test('scans tokens', async (t) => {
  const { tokens, mail } = await scanner.getTokensAndMailFromSource(
    `
Delivered-To: niftylettuce@gmail.com
Received: by 2002:a17:90b:a17:0:0:0:0 with SMTP id gg23csp669324pjb;
        Wed, 15 Jun 2022 16:09:46 -0700 (PDT)
X-Google-Smtp-Source: AGRyM1tCFKoyf+t8yxkuTVtUXOK3pe/wJgNc3C2b1ZRTJY5brHH3sk1sBhfcD/jKEAgX7F2A/qxs
X-Received: by 2002:a62:6407:0:b0:519:3571:903e with SMTP id y7-20020a626407000000b005193571903emr1926931pfb.30.1655334586105;
        Wed, 15 Jun 2022 16:09:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1655334586; cv=pass;
        d=google.com; s=arc-20160816;
        b=qoV6lw/GWDnVOih8Zp44LKv7txQ6Y1VOfYGJAy5g7cFRJcCc+mRa0TwE/irtsKSYsG
         7+lLjuOQwp69GQvLQe4NBp9RrJMANwFIAfDvj5nVmp4n5M05G4rikYH9oh60gaj/NhxP
         +q3ItsVPQtDihrLXOv8nG/fl3UYXuo/jC+1Hax+4k3d2GuaFbrwOfMnlMDyUwEOKg1if
         iVYQavvKb0dYtt3YFblCeeYDC99hnvFb02OpPl/G+YGiAWRgxYu5f62XaKzqa995m2eu
         ZiMIsSX40iBdJPvXburaP33KYOpWIrRcwbdGCQxYezUPss6fMBrybTI0pcHyjJEl4Jvi
         BqYw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:suggested_attachment_session_id:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :from:dkim-signature;
        bh=TBGSA+Lz4i6awHbR/3g9RXYt78JO5/EMN3slc3eUSqg=;
        b=IDMRsnpgkambaTlu6i9svksxBxseUD891Y4Mg7VKjj7fG6TWkcjqc1DrEw7mazbhiu
         l5G4TXeDINEZjyjCZVI7NkErDQSqope8/Ad66Ay4y+Zobe2uptvQCZglJ1A3p+4oUnr6
         w9J8FcvGgNdJSwrajPZC7asMuUn++Xhvt7BGec+2h+H+iioHbWjU5rKQCyeWVQdANhUR
         9lesFBRG9upC321drK+3nSQSl6H0aP6Bp3NeOGgEaDTBWHV2KZg8jnz7n6Jcg82352W5
         R3JrLmSMjMLFHbB28JKWIJ0M75A3eA0ehnSld2JI5x2eawWdgPmxnBqPfWnJR0DQNaJw
         bJGQ==
ARC-Authentication-Results: i=3; mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=cca0MqgX;
       arc=pass (i=2 spf=pass spfdomain=outlook.com dkim=pass dkdomain=outlook.com dmarc=pass fromdomain=outlook.com);
       spf=pass (google.com: domain of srs0=f9a5=wx=outlook.com=totalresource4u@forwardemail.net designates 138.197.213.185 as permitted sender) smtp.mailfrom="SRS0=f9a5=WX=outlook.com=totalresource4u@forwardemail.net";
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Return-Path: <SRS0=f9a5=WX=outlook.com=totalresource4u@forwardemail.net>
Received: from mx1.forwardemail.net (mx1.forwardemail.net. [138.197.213.185])
        by mx.google.com with ESMTPS id l1-20020a170902ec0100b0016409612071si542054pld.121.2022.06.15.16.09.45
        for <niftylettuce@gmail.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 15 Jun 2022 16:09:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=f9a5=wx=outlook.com=totalresource4u@forwardemail.net designates 138.197.213.185 as permitted sender) client-ip=138.197.213.185;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=cca0MqgX;
       arc=pass (i=2 spf=pass spfdomain=outlook.com dkim=pass dkdomain=outlook.com dmarc=pass fromdomain=outlook.com);
       spf=pass (google.com: domain of srs0=f9a5=wx=outlook.com=totalresource4u@forwardemail.net designates 138.197.213.185 as permitted sender) smtp.mailfrom="SRS0=f9a5=WX=outlook.com=totalresource4u@forwardemail.net";
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
ARC-Seal: i=2; a=rsa-sha256; t=1655334584; cv=pass; d=forwardemail.net;
 s=default;
 b=a2eeaz+OupU+FdW8VS957OmDZTLCSCwVT7MzY8Mki1bdKVIv3mZXzD3yX6uJNg3QwRJGRjS4h
 J6jFYtyyBbRHODrC8w5eczy0y/3SJ1lxxLoXv0jdxOyAFMi3KG62dAoRt8z/A9vH4XGbBB7Vc/n
 SdxVkawhamW1zbCqZJFrq0c=
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed;
 d=forwardemail.net; h=MIME-Version: Content-Type: Message-ID: Date:
 Subject: From; q=dns/txt; s=default; t=1655334584;
 bh=TBGSA+Lz4i6awHbR/3g9RXYt78JO5/EMN3slc3eUSqg=;
 b=LSScoijb1/KTMVuXUXHYsQRANrg2p+Fp5yN6QLsqEJgPu8sFHQk8+mb7CZ0OSdBxiNw6H/MXK
 jwWlgSxGd1WHOdRqcZsAnMP8IfjF4qOK4sBgyVaJOe0MRsPeC//38F6+sXA6OthmoQgQgVD/z1E
 m5+D/Ed+2259NvlGgIm8WLU=
ARC-Authentication-Results: i=2; mx1.forwardemail.net;
 dkim=pass header.i=@outlook.com header.s=selector1 header.a=rsa-sha256 header.b=cca0MqgX;
 spf=pass (mx1.forwardemail.net: domain of totalresource4u@outlook.com designates 40.92.107.57 as permitted sender) smtp.mailfrom=totalresource4u@outlook.com
 smtp.helo=apc01-tyz-obe.outbound.protection.outlook.com;
 arc=pass (i=1 spf=none dkim=none dmarc=none);
 dmarc=pass (p=NONE sp=QUARANTINE arc=pass) header.from=outlook.com header.d=outlook.com;
 bimi=skipped (too lax DMARC policy)
Received-SPF: pass (mx1.forwardemail.net: domain of totalresource4u@outlook.com designates 40.92.107.57 as permitted sender) client-ip=40.92.107.57;
Authentication-Results: mx1.forwardemail.net;
 dkim=pass header.i=@outlook.com header.s=selector1 header.a=rsa-sha256 header.b=cca0MqgX;
 spf=pass (mx1.forwardemail.net: domain of totalresource4u@outlook.com designates 40.92.107.57 as permitted sender) smtp.mailfrom=totalresource4u@outlook.com
 smtp.helo=apc01-tyz-obe.outbound.protection.outlook.com;
 arc=pass (i=1 spf=none dkim=none dmarc=none);
 dmarc=pass (p=NONE sp=QUARANTINE arc=pass) header.from=outlook.com header.d=outlook.com;
 bimi=skipped (too lax DMARC policy)
X-ForwardEmail-Sender: rfc822; totalresource4u@outlook.com
X-ForwardEmail-Session-ID: fu7jefgggaa75pbi
X-ForwardEmail-Version: 9.0.1
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=NJL58IWnOV1FjI1hBistg4PBQY4aAG+nb7HUXxnfhAIVP9VwoDFDZnrPoM19u4IqTyPzLQVKwmjtlo3eJpuAZP9KJ8uGFEt/Y7CS/p4wN8fDb7IpqFt2diEkdWZh34ZzkJE1k/ZBLCfy4/QnZp5RSna5iodw5a3JEUJpNzf5ZdcfMjhtyLS97tCJP6eGQGnYTjs8GCLsKrcL9lK7Eco/vQ04+GlzJMOWdx67ejgheBTU08cpULRbw0jnW2bQNXBisRzqyLmFB4yVQPq5QQa0O1S0M2mau5a0E/bGFEtakOSRe0L8ie8r/GYx0lB6ytAnRKnwe8jqaiorlwScKPNPUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TBGSA+Lz4i6awHbR/3g9RXYt78JO5/EMN3slc3eUSqg=;
 b=BirWu3IJCDFv1Sln/+Dd1Fe31oDRVTpoRazkJP40JAmKxykSUYuO1lYUh2pQbg46/fE9hVyvhG9P66/5t3fm31cmtGsmTLTYqr8fq1s0G32ty269+ImiMD/ZdsrEFvM0dt0/8OsqFTF2lqUypN0ZL0qVrUHaLdmCYSG9558P1ERW5vk8l8KCrQ+iEXoaJxpB44ZP4ATLrtFJgq/4mXk62BLZDt3i0BaJy70UWxxaQ6wo3spdscNd+1co0hHGAaeFoQT+o6qViTmgpSUNVZ4ELT982RNhFU9M7UjUOo2xz2H0WTpIj2YXgCICRG2CHGwKgpzbO4eWOoVJU94rc0OMzw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=outlook.com;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=TBGSA+Lz4i6awHbR/3g9RXYt78JO5/EMN3slc3eUSqg=;
 b=cca0MqgXTc+9v806ROMPlnmMUY+RutE7EjBFpj9IP9CXFaiqN2S/9qqgkNjZMDqlv8z0A7PsbYaYqHWMHwx8sKUGvhjFqvXC9zv+tUxgLeGJn1q1FJeAgKi4HWI0EQG5lAWN8jUkqHsR9HhSX37eBQX5lNzOdVgZGur4NhmL5+r8RYDUt7UgqbXYe48eP+SXcMLwjDBNvefPjq6d1vjWv5CZohjyaqkCqFNukLX4xu0GmGXa7iynCEtVoK7aIIxJ2X6v1tRedgNs138bGHlCdLRaNGtRKpmRrs4w+f3H3WxoqTn6rjMF2J4/nDvutBL5nsuKp47JlvV3hD8oYPknow==
Received: from SEZPR02MB5959.apcprd02.prod.outlook.com (2603:1096:101:7a::5)
 by HK0PR02MB2673.apcprd02.prod.outlook.com (2603:1096:203:69::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5332.22; Wed, 15 Jun
 2022 23:08:43 +0000
Received: from SEZPR02MB5959.apcprd02.prod.outlook.com
 ([fe80::b593:da36:5bc2:97eb]) by SEZPR02MB5959.apcprd02.prod.outlook.com
 ([fe80::b593:da36:5bc2:97eb%6]) with mapi id 15.20.5332.015; Wed, 15 Jun 2022
 23:08:43 +0000
From: Mike Smith <totalresource4u@outlook.com>
Subject: Prices
Thread-Topic: Prices
Thread-Index: AQHYgQzSS0T2acndokiUfe9V9ycZNA==
Date: Wed, 15 Jun 2022 23:08:43 +0000
Message-ID:
 <SEZPR02MB5959964215117D1058F93ECCF5AD9@SEZPR02MB5959.apcprd02.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach:
X-MS-TNEF-Correlator:
suggested_attachment_session_id: fbc7de91-34ff-2608-86b6-eb2db61c77f4
x-tmn: [vQZGw5sMQfKorjMKdzQpihuVP8/rzFAW]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 48b00965-0523-42e2-d6a7-08da4f23fe56
x-ms-traffictypediagnostic: HK0PR02MB2673:EE_
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info:
 Pu1Aan0UyMzix2JfVqWWJKUfozat4jgOA9V62MxToZthsbRS381ji8wyyKzjCbNFeCtog8nA2PoW16AvryUGTx0201+FVc2GlcbAx0OzNmRpMXyNGABR6HF6RDyvnaqcG2LR5V98bcwaGgJsBXVmiDQ0PaLtXvU2g7fpOUO3qquOvzOw5aa1BI2kCW5ZAOBO37x8upXbXPS4eO7/H5kHcw/z32kW2yXCdM1pTYDZ41K9Y5duMmZ0NcvLuKQSCfX0cU1NEX5XeIu2NAC5+XGTMlYsQOf69taZKjZq8mjokAv3sdDypvcHSGUWCq9DWEzBwxT66dKgfvQxfZbZW2oj8UrghTpHtYa+Q1ppYXZM9E+IZbRV3xAbafBmAZCigEuwwgei5fXwTGpLAs4UhE1WCYXEEWxd9RzgTzQr1BMGcv3oaQCHyV0sKpG09REuMYjhCJUgSX8/lMUrDpU1t3qim3suwm0aZc/80D14zI7LzYSd84XV6ema6IkhzHjN6ngGzxkOjLkBb+gJl+n2Ni9PBtgXV8FomAKdlWt+nbDxSfGy6Zi7uK0FaRRLcKmSjLVr
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0:
 =?iso-8859-1?Q?yKoXVZXyuorEdsQ8jGPUjj9uti8/b8/fdT8sN14mz12wc8JYIRhY5TDPQh?=
 =?iso-8859-1?Q?6pXpXvahid6h/MiUVHu48iKCFWwOM/hkaK/+fjajuHAvL0x/f52SBfUHRx?=
 =?iso-8859-1?Q?I46MQvImnDeXr3CtBMAU37DuRVsgXrqLJYsjp82OpIgGYnSKaFcVM4Fizo?=
 =?iso-8859-1?Q?R0SyywCEsQn4X9ML2KeWsega1N48xu/XbFi6RqMdFpJeebHD00SGmF9FAH?=
 =?iso-8859-1?Q?Xd3fQdxCFL8MfKgJiIQnkhhIczrqZ85zFMGhgxuGKbhanSpfdtC7n+VjsG?=
 =?iso-8859-1?Q?RRQTjhrFlVjzJKrYqg2PbeajUP9xnIIDm0/eicboeKv+qOmzpa40l989Ut?=
 =?iso-8859-1?Q?8XQXcZSED3FVo9CvSUmEjsF95wKHAo64GhR1Bf9MnPqpkH6kxXQ6+QbkKK?=
 =?iso-8859-1?Q?6WzIduwhwOWiiri22s/qsTvoVox4BOBPCCc+Z2tT6frWgOZAfQMJAaWFP0?=
 =?iso-8859-1?Q?DPYRWrgVA8pkYlPAFhGGdlbwNW4E/2gjjeamWd1J4uI2Jflr7utnmO7VME?=
 =?iso-8859-1?Q?H9GqiYcwUEjjqtru0SJ4XCla7oLQEhp0hch9YDzT6xWpnWDq0Clj+peTt/?=
 =?iso-8859-1?Q?UNvsK+aNxfuo6V/G82dicL6JSA8O8ttAtxaZwwtSoh/VwEGlD8wd2uW+hE?=
 =?iso-8859-1?Q?ksq05XcvYoguA4UCoDerFUYBRgrTIAcBY4nehSNxXv/uPSJdsXdDMNaZxC?=
 =?iso-8859-1?Q?CcoBZvW1GvCf9/S3GdoSzKdc7SjD0EI07ZuX0q74ImzW1HUfOHXslV6Xr/?=
 =?iso-8859-1?Q?OMnqd4PKbHmFvI+RKwSZmH0Egko+jc+oJT5X9nommJYsLQQrIntM3bYr2Q?=
 =?iso-8859-1?Q?467r87CL2s2iHmWcfCqtTvHJhJT8cBjop+WauS5FLemyH2YlhCzX00c5Ld?=
 =?iso-8859-1?Q?IKt49YV/w+3S7MeHqelR3bl9vSNRdAgnyio8HwJTvT920h8B0n6UuzRwqP?=
 =?iso-8859-1?Q?e+aYrTAXwx+UV/x/KU4OEfYHLsTQvSSaLZlOSrRfSMJvSPghdAYfZBQ9z0?=
 =?iso-8859-1?Q?khfnq0K9z1e5CmDKjM1INE46EpD4WKAlb8ppGvGi2AHGh/1jq79GQ/vZtn?=
 =?iso-8859-1?Q?CZrZ7tLEVSm9fenUpvOTPytDjiZxVp8FBFaJq+AraZQACl6NDX/FGDJYbJ?=
 =?iso-8859-1?Q?ND+BslEjW/StibTTTSDrtaS6pWq2TEUlyLowLN5sEewRVz4Dr7ODLYGq9W?=
 =?iso-8859-1?Q?bs7hFjofUtGihfPLqfwQfYnoXMK0jwlQgiIBEQVgVoUgovXKVYuX0l7QOD?=
 =?iso-8859-1?Q?K0q3KbkOUdi6JpcL2JTMqkEzDeN7Nj04UXgCEfOWej4mmEpPSgtDu7KVZY?=
 =?iso-8859-1?Q?Ri48HPXdbZh0N8lmPQkEA+bup5j0jSDZEG/cKRECKlenKzQlzu3sVCpYw0?=
 =?iso-8859-1?Q?9luexAV9GGSIgVedC5O7ruZ+ZNBIKSHfRszVeudGUeOy1DIhdzvK2CifcT?=
 =?iso-8859-1?Q?7Z6Yt/XKPzVFhbPhBctZwd6c5t9H3viuy18Fw7k2WKgRdSxQNf3n6fDq7Z?=
 =?iso-8859-1?Q?A=3D?=
Content-Type: multipart/alternative;
  boundary="_000_SEZPR02MB5959964215117D1058F93ECCF5AD9SEZPR02MB5959apcp_"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SEZPR02MB5959.apcprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 48b00965-0523-42e2-d6a7-08da4f23fe56
X-MS-Exchange-CrossTenant-originalarrivaltime: 15 Jun 2022 23:08:43.5425
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HK0PR02MB2673

--_000_SEZPR02MB5959964215117D1058F93ECCF5AD9SEZPR02MB5959apcp_
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

Hi,

I am reaching out to see if there is anything that would like to upgrade, r=
epair or redesign on your site. I am a web designer/developer that can do j=
ust about anything you can imagine at very affordable prices.

Let me know what you think.

Kind Regards,
Mike Smith
Web designer & developer

PS: - if this is something, you are interested please respond to this email=
 for Portfolio and Price list. Also, please feel free to share your require=
ments and queries.


--_000_SEZPR02MB5959964215117D1058F93ECCF5AD9SEZPR02MB5959apcp_
Content-Type: text/html; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
<style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bo=
ttom:0;} </style>
</head>
<body dir=3D"ltr">
<div style=3D"font-family: Calibri, Arial, Helvetica, sans-serif; font-size=
: 12pt; color: rgb(0, 0, 0);" class=3D"elementToProof">
Hi,
<div><br>
</div>
<div>I am reaching out to see if there is anything that would like to upgra=
de, repair or redesign on your site. I am a web designer/developer that can=
 do just about anything you can imagine at very affordable prices.</div>
<div><br>
</div>
<div>Let me know what you think.</div>
<div><br>
</div>
<div>Kind Regards,</div>
<div>Mike Smith</div>
<div>Web designer &amp; developer</div>
<div><br>
</div>
<div>PS: - if this is something, you are interested please respond to this =
email for Portfolio and Price list. Also, please feel free to share your re=
quirements and queries.</div>
<br>
</div>
</body>
</html>

--_000_SEZPR02MB5959964215117D1058F93ECCF5AD9SEZPR02MB5959apcp_--
`.trim()
  );
  console.log('tokens', tokens);
  console.log('mail', mail);
  t.fail();
});

//
// TODO: re-enable these three tests once classifier is fixed
//
/*
test('should detect spam', async (t) => {
  const scan = await scanner.scan(fixtures('spam.eml'));
  t.true(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'spam');
});

test('should detect spam fuzzy', async (t) => {
  const scan = await scanner.scan(fixtures('spam-fuzzy.eml'));
  t.true(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'spam');
});

test('should detect ham', async (t) => {
  const scan = await scanner.scan(fixtures('ham.eml'));
  t.false(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'ham');
});
*/

test('should parse eop-nam02.prod.protection.outlook.com properly', async (t) => {
  const results = await Promise.all([
    scanner.isCloudflareBlocked('eop-nam02.prod.protection.outlook.com'),
    scanner.isCloudflareBlocked('prod.protection.outlook.com'),
    scanner.isCloudflareBlocked('protection.outlook.com'),
    scanner.isCloudflareBlocked('outlook.com')
  ]);
  t.deepEqual(results, [
    {
      isAdult: false,
      isMalware: false
    },
    {
      isAdult: false,
      isMalware: false
    },
    {
      isAdult: false,
      isMalware: false
    },
    {
      isAdult: false,
      isMalware: false
    }
  ]);
});

test('should detect not phishing with different org domains (temporary)', async (t) => {
  const scan = await scanner.scan(fixtures('phishing.eml'));
  t.false(scan.is_spam);
  t.true(scan.results.phishing.length === 0);
});

test('should detect idn masquerading', async (t) => {
  const client = new Redis();
  const scanner = new SpamScanner({ client, checkIDNHomographAttack: true });
  const scan = await scanner.scan(fixtures('idn.eml'));
  t.true(scan.is_spam);
  t.true(scan.results.phishing.length > 0);
});

test('should detect executable files', async (t) => {
  const scan = await scanner.scan(fixtures('executable.eml'));
  t.true(scan.is_spam);
  t.true(scan.results.executables.length > 0);
});

test('should check against Cloudflare', async (t) => {
  const link = Buffer.from('eHZpZGVvcy5jb20=', 'base64').toString();
  const results = await scanner.getPhishingResults({
    html: `<a href="${link}">test</a>${link}<A href="${link}/foo">${link}</A>`,
    text: link
  });
  t.deepEqual(results.messages, [
    `Link hostname of ${link} was detected by Cloudflare's Family DNS to contain adult-related content, phishing, and/or malware.`
  ]);
});

//
// NOTE: I added support for GTUBE because I have a suspicion that some
// large email providers may send test emails with the GTUBE test
// to see if the mail server has spam filtering enabled, but this is
// also a nice way for us to send test messages to see that Spam Scanner
// is actually running and parsing messages properly
//
// <https://spamassassin.apache.org/gtube/>
// <https://spamassassin.apache.org/gtube/gtube.txt>
//
test('GTUBE test', async (t) => {
  const results = await scanner.getArbitraryResults({
    html: `
Subject: Test spam mail (GTUBE)
Message-ID: <GTUBE1.1010101@example.net>
Date: Wed, 23 Jul 2003 23:30:00 +0200
From: Sender <sender@example.net>
To: Recipient <recipient@example.net>
Precedence: junk
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

This is the GTUBE, the
  Generic
  Test for
  Unsolicited
  Bulk
  Email

If your spam filter supports it, the GTUBE provides a test by which you
can verify that the filter is installed correctly and is detecting incoming
spam. You can send yourself a test mail containing the following string of
characters (in upper case and with no white spaces and line breaks):

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

You should send this test mail from an account outside of your network.
    `.trim()
  });
  t.deepEqual(results, [
    'Message detected to contain the GTUBE test from https://spamassassin.apache.org/gtube/.'
  ]);
});

//
// virus scanning detection against EICAR test
//
// <https://en.wikipedia.org/wiki/EICAR_test_file>
// <https://secure.eicar.org/eicar_com.txt>
// <https://www.eicar.org/?page_id=3950>
//
test('EICAR test', async (t) => {
  const clamd = await lookpath('clamd');
  if (!clamd) {
    if (isCI) {
      t.fail(
        'clamd executable not available, please ensure clamscan is installed'
      );
      return;
    }

    t.pass('clamd executable not available, skipping clamscan test locally');
    return;
  }

  const content = await fs.promises.readFile(fixtures('eicar.com.txt'));
  const results = await scanner.getVirusResults({
    attachments: [{ content }]
  });
  t.log(results);
  t.true(
    results.includes('Attachment #1 was infected with Eicar-Test-Signature.') ||
      results.includes('Attachment #1 was infected with Win.Test.EICAR_HDB-1.')
  );
});

// <https://github.com/sindresorhus/file-type/issues/377>
test('allows < Word 2004 doc', async (t) => {
  const content = await fs.promises.readFile(fixtures('sample.doc'));
  const results = await scanner.getExecutableResults({
    attachments: [{ content }]
  });
  t.deepEqual(results, []);
});

// <https://github.com/peerigon/parse-domain/issues/116>
test('strips zero-width characters', (t) => {
  t.is(
    scanner.getHostname(
      'https://‌www.foobar.com.br‌/12345/index.php?m=foo@bar.com'
    ),
    'www.foobar.com.br'
  );
  t.is(
    scanner.getNormalizedUrl(
      'https://‌www.foobar.com.br‌/12345/index.php?m=foo@bar.com'
    ),
    'www.foobar.com.br/12345/index.php'
  );
});

test('getUrls filters out emails to be hostname only', (t) => {
  const urls = scanner.getUrls(`
    test.it123.com.foobar123.com
        robot.itýbeep.com
      baz.iT
      bop.it
      CAPS.CO
    foo.it123
     foo.itbeep.beep.mx.bar@gmail.com
      http://duckduckgo.com
    foo.mxýbeep@gmail.com
    foo.itýbeep.com
     foo.isfoo@beep.com foo.isnic'
  `);
  t.log(urls);
  t.deepEqual(urls, [
    'test.it123.com.foobar123.com',
    'robot.xn--itbeep-cza.com',
    'bop.it',
    'caps.co',
    'gmail.com',
    'duckduckgo.com',
    'foo.mx',
    'foo.xn--itbeep-cza.com',
    'beep.com'
  ]);
});

test('caches cloudflare block results', async (t) => {
  const link = Buffer.from('cG9ybi5jb20=', 'base64').toString();
  let now = performance.now();
  let diff = 0;
  const result1 = await scanner.memoizedIsCloudflareBlocked(link);
  diff = performance.now() - now;
  t.true(diff > 1);
  now = performance.now();
  const result2 = await scanner.memoizedIsCloudflareBlocked(link);
  diff = performance.now() - now;
  t.true(diff < 1);
  now = performance.now();
  const result3 = await scanner.memoizedIsCloudflareBlocked(link);
  diff = performance.now() - now;
  t.true(diff < 1);
  t.deepEqual(result1, {
    isAdult: true,
    isMalware: false
  });
  t.deepEqual(result1, result2);
  t.deepEqual(result2, result3);
  t.true(
    memProfile.statistics[Object.keys(memProfile.statistics)[0]].cached >= 2
  );
  const good = await scanner.memoizedIsCloudflareBlocked('google.com');
  t.deepEqual(good, {
    isAdult: false,
    isMalware: false
  });
});

test('caches with redis', async (t) => {
  const client = new Redis();
  const scanner = new SpamScanner({ client });
  const key = `${scanner.config.cachePrefix}:example.com`;
  // purge cache key
  await client.del(key);
  const result1 = await scanner.memoizedIsCloudflareBlocked('example.com');
  t.deepEqual(result1, { isAdult: false, isMalware: false });
  // caches it the background so wait 0.5s
  await delay(500);
  const value = await client.get(key);
  t.is(value, 'false:false');
  const result2 = await scanner.memoizedIsCloudflareBlocked('example.com');
  t.deepEqual(result1, result2);
});

for (const locale of [
  'ar',
  'da',
  'nl',
  'en',
  'fi',
  'fa',
  'fr',
  'de',
  'hu',
  'in',
  'it',
  'ja',
  'nb',
  'nn',
  'po',
  'pt',
  'es',
  'sv',
  'ro',
  'ru',
  'ta',
  'tr',
  'vi',
  'zh'
]) {
  test(`getTokens works with locale "${locale}"`, async (t) => {
    const scanner = new SpamScanner();
    const tokens = await scanner.getTokens(
      "hello they're world greetings today is a new day and tomorrow is another day", // = 13
      //                           ^  ^          ^           ^   ^               = 4
      locale
    );
    // "hello" is a stopword in "in"
    // <https://github.com/NaturalNode/natural/issues/651>
    t.is(tokens.length, 8);
    t.pass();
  });
}

test('detects >= 90% certainty and uses passed locale', async (t) => {
  const scanner = new SpamScanner();
  const tokens = await scanner.getTokens('Ciao amigo', 'pt');
  t.deepEqual(tokens, ['cia', 'amig']);
  t.is(tokens.length, 2);
});

test('language spoofed as Japanese but actually Chinese', async (t) => {
  const scanner = new SpamScanner();
  const tokens = await scanner.getTokens('我是中國人。', 'jp');
  t.is(tokens.length, 2);
});

test('language detected as Chinese', async (t) => {
  const scanner = new SpamScanner();
  const tokens = await scanner.getTokens('我是中國人。');
  t.is(tokens.length, 2);
});

test('spoofs language but is detected as Chinese', async (t) => {
  const scanner = new SpamScanner();
  const tokens = await scanner.getTokens(
    "hello they're world greetings today is a new day and tomorrow is another day",
    'zh'
  );
  t.is(tokens.length, 8);
});

test('spoofs language but is detected as English', async (t) => {
  const scanner = new SpamScanner();
  const tokens = await scanner.getTokens('我是中國人。', 'en');
  t.is(tokens.length, 2);
});

test('stopword removal works with Chinese', async (t) => {
  const scanner = new SpamScanner();
  const tokens = await scanner.getTokens('我是中國人。', 'zh');
  t.is(tokens.length, 2);
});

test.todo('IDN homograph attack test');
test.todo('50/50 ham vs spam dataset test');
test.todo('test classifier.json against dataset to determine % accuracy');
test.todo('should detect nsfw using nsfw.js');
test.todo('should detect phishing querystring redirections');
