// Lists of the providers a message is read by, kept apart from the code that
// reads it. Each domain is registered (checked with its registry, and for
// a numbered one, to the same owner as the rest) and is named by its
// provider's own documentation or by two of: the rules of Rspamd (redirectors.inc) and Apache SpamAssassin
// (20_freemail_domains.cf), both under the Apache License 2.0, the list of
// MailTrackerBlocker (BSD 3-Clause), and willwhite/freemail (MIT).

// The domains a service numbers, each registered to it: `from` to `to`
// after `name`, written with `digits` digits ("cmail1.com" to "cmail30.com").
// Only the numbers in use, as the next one is anyone's to register.
const numbered = (name, from, to, digits = 1) => Array.from({length: to - from + 1}, (_, index) => `${name}${String(from + index).padStart(digits, '0')}.com`);

// Hosts that count each click on a link of a message and send the reader on
// to the address it shows: a link through one goes elsewhere by design (see
// isDeceptiveLink). A host under one of these domains is one.
export const CLICK_TRACKERS = [
	// Email services, by their documented click tracking
	// Twilio SendGrid (*.ct.sendgrid.net)
	'sendgrid.net',
	// Mailchimp (*.list-manage.com) and Mandrill
	'list-manage.com',
	...numbered('list-manage', 1, 2),
	'mandrillapp.com',
	// Amazon SES (*.awstrack.me)
	'awstrack.me',
	// Postmark (click.pstmrk.it)
	'pstmrk.it',
	// HubSpot (*.hubspotlinks.com, t.hubspotemail.net, sales mail)
	'hubspotlinks.com',
	'hubspotlinksfree.com',
	'hubspotlinksstarter.com',
	'hubspotfree.net',
	'hubspotstarter.net',
	'sidekickopen.com',
	...numbered('sidekickopen', 1, 90, 2),
	'hubspotemail.net',
	'hs-sales-engage.com',
	// Constant Contact (r20.rs6.net)
	'rs6.net',
	// Klaviyo (trk.klclick.com, trk.klclick1.com)
	'klclick.com',
	...numbered('klclick', 1, 5),
	'klaviyomail.com',
	// Mailjet (*.mjt.lu)
	'mjt.lu',
	// Salesforce Marketing Cloud (click.exacttarget.com, cl.exct.net)
	'exacttarget.com',
	'exct.net',
	// Brevo, formerly Sendinblue (*.sendibt2.com, *.r.a.d.sendibm1.com) and
	// Newsletter2Go
	...numbered('sendibm', 1, 7),
	...numbered('sendibt', 1, 4),
	'amxe.net',
	// Kit, formerly ConvertKit (click.convertkit-mail2.com, *.click.kit-mail3.com)
	'convertkit-mail.com',
	...numbered('convertkit-mail', 2, 6),
	...numbered('kit-mail', 1, 8),
	// Campaign Monitor (*.createsend1.com, cmail20.com)
	...numbered('cmail', 1, 30),
	...numbered('createsend', 1, 30),
	// ActiveCampaign (*.lt.acemlnb.com, *.lt.emlnk1.com)
	'acemlna.com',
	'acemlnb.com',
	'acemlnc.com',
	'acemlnd.com',
	'emlnk.com',
	...numbered('emlnk', 1, 9),
	// Acoustic, formerly Silverpop (links.mkt41.net)
	'mkt32.net',
	...['41', '51', '61', '71', '81'].map(pod => `mkt${pod}.net`),
	// Keap, formerly Infusionsoft
	...numbered('keap-link', 1, 20, 3),
	'infusion-links.com',
	// Drip
	...numbered('dripemail', 1, 3),
	// Your Mailing List Provider
	'ymlpmail1.com',
	// EmailOctopus
	...numbered('eomail', 1, 8),
	// MailerLite (*.clicks.mlsend.com)
	'mlsend.com',
	'mlsend2.com',
	// Beehiiv (link.mail.beehiiv.com)
	'link.mail.beehiiv.com',
	'bhclick.com',
	// Substack, through Mailgun (see also isClickTracker)
	'email.mg1.substack.com',
	'email.mg2.substack.com',
	// Adobe Campaign (*-t.adobe-campaign.com)
	'adobe-campaign.com',
	// Oracle Eloqua (*.t.en25.com)
	'en25.com',
	// Bloomreach, formerly Exponea
	'bloomreach.com',
	'exponea.com',
	// Dotdigital
	'dmtrk.net',
	'dmtrk.com',
	'ddlnk.net',
	'ddlnk.com',
	'trackedlink.net',
	// Emma (t.e2ma.net)
	'e2ma.net',
	// AWeber
	'clicks.aweber.com',
	// Benchmark Email
	'bmetrack.com',
	'benchurl.com',
	// The click tracking of iContact (click.icptrack.com)
	'icptrack.com',
	// Campaigner (trk.cp20.com)
	'cp20.com',
	// VerticalResponse (cts.vresp.com)
	'vresp.com',
	// Selligent
	'emsecure.net',
	'slgnt.eu',
	'slgnt.us',
	// Intercom
	'intercom-clicks.com',
	// Customer.io (e.customeriomail.com)
	'customeriomail.com',
	// SparkPost, now Bird (spgo.io, eu.spgo.io)
	'spgo.io',
	'sparkpostmail.com',
	// Omnisend
	'soundestlink.com',
	'omnisendlink.com',
	// Zoho Campaigns and CRM
	'maillist-manage.com',
	'maillist-manage.eu',
	'maillist-manage.in',
	'maillist-manage.com.au',
	'zohoinsights-crm.com',
	// SendPulse
	'stat-pulse.com',
	'sendpul.se',
	// Microsoft Dynamics 365 (*.svc.dynamics.com)
	'svc.dynamics.com',
	// Squarespace, Wix and GoDaddy
	'engage.squarespace-mail.com',
	'shoutout.wix.com',
	'secureclick.net',
	// Listrak
	'listrakbi.com',
	// Higher Logic
	'informz.net',
	// Granicus govDelivery
	'links.govdelivery.com',
	'lnks.gd',
	// EveryAction
	'click.everyaction.com',
	// Services of other countries: MDirector and Acumbamail of Spain, MailUp
	// of Italy, APSIS of Sweden, Cuenote and EmberPoint of Japan, ActiveTrail
	// of Israel and Agentbox of Australia
	'mdrctr.com',
	'acblnk.com',
	'acmbtrc.com',
	'acmtrk.com',
	'clickacumba.com',
	'musvc.com',
	'musvc1.net',
	'musvc2.net',
	'anpdm.com',
	'cuenote.jp',
	'mpse.jp',
	'sendmsg.co.il',
	'agentboxmail.com.au',
	// Webex Connect, formerly IMImobile
	'imiclk.com',
	// Mirabel
	'mirabelsmarketingmanager.com',
	// Sales mail: Outreach, Salesloft, Yesware and Mailtrack
	'outrch.com',
	'salesloftlinks.com',
	't.yesware.com',
	'mltrk.io',
	// Links that open an app (AppsFlyer, Branch) and those of affiliate
	// networks, which a newsletter shows the shop's address over
	'onelink.me',
	'app.link',
	'linksynergy.com',
	'awin1.com',
	'anrdoezrs.net',
	'dpbolvw.net',
	'jdoqocy.com',
	'kqzyfj.com',
	'tkqlhce.com',
	'shareasale.com',
	'pntra.com',
	'pxf.io',
	'sjv.io',
	'ojrq.net',
	'skimresources.com',
	'redirectingat.com',
	'viglink.com',
	'avantlink.com',
	'tradedoubler.com',
	// Security gateways, which rewrite each link of the mail they pass to check
	// it when it is clicked, so a message forwarded from behind one shows the
	// address it had: Microsoft Defender's Safe Links
	'safelinks.protection.outlook.com',
	'safelinks.protection.office365.us',
	'protection.apps.mil',
	'protection.partner.outlook.cn',
	// Proofpoint
	'urldefense.com',
	'urldefense.proofpoint.com',
	'urldefense.us',
	'urlisolation.com',
	// Mimecast (protect-*.mimecast.com, url.*.mimecastprotect.com)
	'mimecast.com',
	'mimecastprotect.com',
	// Barracuda (linkprotect.cudasvc.com) and Cisco
	'cudasvc.com',
	'secure-web.cisco.com',
	// Sophos, Trend Micro, Symantec and Trellix, formerly FireEye
	'protection.sophos.com',
	'ctp.trendmicro.com',
	'clicktime.symantec.com',
	'protect2.fireeye.com',
	// Check Point, formerly Avanan
	'protect.checkpoint.com',
	'avanan.click',
	'url-protection.com',
	// Hornetsecurity
	'atpscan.global.hornetsecurity.com',
	'seclinks.cloud-security.net',
	// Vade, Libraesva, Zix, TitanHQ, Trustwave, Topsec and EdgePilot
	'antiphishing.vadesecure.com',
	'urlsand.esvalabs.com',
	'link.zixcentral.com',
	'linklock.titanhq.com',
	'scanmail.trustwave.com',
	'scanner.topsec.com',
	'link.edgepilot.com',
	// VIPRE and Bitdefender
	'emailprotection.link',
	'mailanyone.net',
	'lsems.gravityzone.bitdefender.com',
	'linkscan.io',
];

// Providers of mailboxes to the public, where an address is anyone's and
// not the provider's own (see isMailbox, which also knows the providers
// that have a domain in every country by name)
export const MAILBOX_DOMAINS = new Set([
	'126.com',
	'139.com',
	'163.com',
	'21cn.com',
	'263.net',
	'a1.net',
	'abv.bg',
	'alice.it',
	'aliyun.com',
	'anonaddy.me',
	'aol.com',
	'arcor.de',
	'aruba.it',
	'att.net',
	'azet.sk',
	'bell.net',
	'bellsouth.net',
	'bigmir.net',
	'bigpond.com',
	'bigpond.net.au',
	'blueyonder.co.uk',
	'bol.com.br',
	'btinternet.com',
	'cableone.net',
	'centrum.cz',
	'centurylink.net',
	'centurytel.net',
	'charter.net',
	'chello.nl',
	'citromail.hu',
	'comcast.net',
	'cox.net',
	'cs.com',
	'daum.net',
	'earthlink.net',
	'eircom.net',
	'email.cz',
	'fastmail.fm',
	'free.fr',
	'freenet.de',
	'frontier.com',
	'frontiernet.net',
	'fuse.net',
	'gazeta.pl',
	'gci.net',
	'gmail.com',
	'gmx.com',
	'gmx.de',
	'gmx.net',
	'go.ro',
	'googlemail.com',
	'hanmail.net',
	'hawaiiantel.net',
	'hey.com',
	'hot.ee',
	'hotmail.com',
	'hushmail.com',
	'icloud.com',
	'ig.com.br',
	'iinet.net.au',
	'inbox.lv',
	'interfree.it',
	'interia.pl',
	'iol.it',
	'juno.com',
	'kakao.com',
	'kpnmail.nl',
	'laposte.net',
	'libero.it',
	'live.com',
	'livedoor.com',
	'mac.com',
	'mail.com',
	'mail.dk',
	'mail.ru',
	'mail2world.com',
	'mailbox.org',
	'mailinator.com',
	'me.com',
	'mixmail.com',
	'msn.com',
	'my.com',
	'mynet.com',
	'nate.com',
	'naver.com',
	'ntlworld.com',
	'o2.pl',
	'onet.pl',
	'online.de',
	'online.nl',
	'op.pl',
	'optonline.net',
	'optusnet.com.au',
	'orange.es',
	'orange.fr',
	'orange.pl',
	'outlook.com',
	'ozemail.com.au',
	'peoplepc.com',
	'plus.com',
	'pm.me',
	'post.cz',
	'posteo.de',
	'proton.me',
	'protonmail.ch',
	'protonmail.com',
	'ptd.net',
	'qq.com',
	'qwest.net',
	'rambler.ru',
	'rcn.com',
	'rediff.com',
	'rediffmail.com',
	'rediffmailpro.com',
	'rogers.com',
	'rr.com',
	'runbox.com',
	'sapo.pt',
	'sbcglobal.net',
	'seznam.cz',
	'sfr.fr',
	'shaw.ca',
	'simplelogin.com',
	'sina.com',
	'snet.net',
	'sohu.com',
	'spectrum.net',
	'spray.se',
	'startmail.com',
	'sunrise.ch',
	'swbell.net',
	't-online.de',
	'talktalk.net',
	'tds.net',
	'tele2.nl',
	'telefonica.net',
	'telenet.be',
	'telfort.nl',
	'telus.net',
	'terra.com.br',
	'tim.it',
	'tin.it',
	'tiscali.it',
	'tom.com',
	'tpg.com.au',
	'tuta.com',
	'tutanota.com',
	'ukr.net',
	'uol.com.br',
	'usa.com',
	'verizon.net',
	'videotron.ca',
	'virgilio.it',
	'virginmedia.com',
	'walla.co.il',
	'wanadoo.es',
	'wanadoo.fr',
	'web.de',
	'wideopenwest.com',
	'windstream.net',
	'wp.pl',
	'xs4all.nl',
	'xtra.co.nz',
	'yahoo.com',
	'yam.com',
	'yandex.com',
	'yandex.ru',
	'yeah.net',
	'ymail.com',
	'yopmail.com',
	'ziggo.nl',
	'zoho.com',
	'zohomail.com',
	'zoominternet.net',
	'zoznam.sk',
]);
