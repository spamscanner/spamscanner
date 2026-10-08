/* global document, window */
// spamscanner.net: theme, menus, copy buttons, tooltips, table of contents,
// tabs, the video and sharing.
(() => {
	const root = document.documentElement;
	root.classList.add('js');
	const byId = id => document.querySelector(`[id="${id}"]`);

	const live = document.createElement('div');
	live.className = 'sr-only';
	live.setAttribute('aria-live', 'polite');
	document.body.append(live);

	// Theme: system, light or dark; the choice is kept in localStorage.
	const toggle = document.querySelector('.theme-toggle');
	const choices = ['system', 'light', 'dark'];
	let choice = root.dataset.theme || 'system';
	let labels = {};
	try {
		labels = JSON.parse(toggle.dataset.labels);
	} catch {}

	const themeLabel = () => `${(toggle && toggle.dataset.label) || 'Theme'}: ${labels[choice] || choice}`;
	const applyTheme = () => {
		if (choice === 'system') {
			delete root.dataset.theme;
		} else {
			root.dataset.theme = choice;
		}

		if (toggle) {
			toggle.dataset.choice = choice;
			toggle.title = themeLabel();
			toggle.setAttribute('aria-label', themeLabel());
		}
	};

	applyTheme();
	if (toggle) {
		toggle.addEventListener('click', () => {
			choice = choices[(choices.indexOf(choice) + 1) % choices.length];
			try {
				if (choice === 'system') {
					localStorage.removeItem('theme');
				} else {
					localStorage.setItem('theme', choice);
				}
			} catch {}

			applyTheme();
			live.textContent = themeLabel();
		});
	}

	// Disclosure menus: the header navigation and the docs sidebar on small screens.
	const menus = [...document.querySelectorAll('.menu-toggle, .side-toggle')];
	const setMenu = (button, open) => {
		button.setAttribute('aria-expanded', String(open));
		byId(button.getAttribute('aria-controls')).classList.toggle('open', open);
	};

	for (const button of menus) {
		button.addEventListener('click', () => setMenu(button, button.getAttribute('aria-expanded') !== 'true'));
	}

	document.addEventListener('click', event => {
		for (const button of menus) {
			const panel = byId(button.getAttribute('aria-controls'));
			if (button.getAttribute('aria-expanded') === 'true' && !button.contains(event.target) && !panel.contains(event.target)) {
				setMenu(button, false);
			}
		}
	});

	// Copy buttons: a data-copy value, or the code block they sit in.
	const copyText = async text => {
		try {
			await navigator.clipboard.writeText(text);
		} catch {
			const area = document.createElement('textarea');
			area.value = text;
			area.setAttribute('readonly', '');
			area.style.position = 'fixed';
			area.style.opacity = '0';
			document.body.append(area);
			area.select();
			document.execCommand('copy');
			area.remove();
		}
	};

	for (const button of document.querySelectorAll('.copy')) {
		let timer;
		const label = button.textContent;
		button.addEventListener('click', async () => {
			const block = button.closest('.code');
			const text = button.dataset.copy || (block ? block.querySelector('pre').textContent : '');
			await copyText(text);
			button.textContent = button.dataset.copied || 'Copied';
			button.classList.add('done');
			live.textContent = button.textContent;
			clearTimeout(timer);
			timer = setTimeout(() => {
				button.textContent = label;
				button.classList.remove('done');
			}, 1600);
		});
	}

	// Tooltips: on hover and keyboard focus, on tap for touch; Escape closes.
	let open = null;
	let pointer = 'mouse';
	let wasOpen = false;
	const place = (trigger, tip) => {
		tip.style.position = 'fixed';
		tip.style.left = '0px';
		tip.style.top = '0px';
		const box = trigger.getClientRects()[0] || trigger.getBoundingClientRect();
		const size = tip.getBoundingClientRect();
		const width = root.clientWidth;
		const left = Math.max(8, Math.min(box.left + (box.width / 2) - (size.width / 2), width - size.width - 8));
		let top = box.bottom + 8;
		if (top + size.height > window.innerHeight - 8 && box.top - size.height - 8 > 8) {
			top = box.top - size.height - 8;
		}

		tip.style.left = `${Math.round(left)}px`;
		tip.style.top = `${Math.round(top)}px`;
	};

	const hide = () => {
		if (open) {
			open.tip.classList.remove('open');
			open.trigger.classList.remove('active');
			open = null;
		}
	};

	const show = (trigger, tip) => {
		if (open && open.tip !== tip) {
			hide();
		}

		tip.classList.add('open');
		trigger.classList.add('active');
		place(trigger, tip);
		open = {trigger, tip};
	};

	for (const trigger of document.querySelectorAll('[aria-describedby]')) {
		const tip = byId(trigger.getAttribute('aria-describedby'));
		if (!tip || !tip.classList.contains('tip')) {
			continue;
		}

		trigger.addEventListener('pointerenter', event => {
			if (event.pointerType === 'mouse') {
				show(trigger, tip);
			}
		});
		trigger.addEventListener('pointerleave', event => {
			if (event.pointerType === 'mouse' && document.activeElement !== trigger) {
				hide();
			}
		});
		trigger.addEventListener('focus', () => show(trigger, tip));
		trigger.addEventListener('blur', () => {
			if (open && open.trigger === trigger) {
				hide();
			}
		});
		trigger.addEventListener('click', event => {
			// On touch, the first tap shows the tooltip; a second tap follows the link.
			if (pointer !== 'mouse' && !(wasOpen && trigger.tagName === 'A')) {
				event.preventDefault();
				show(trigger, tip);
			}
		});
	}

	document.addEventListener('pointerdown', event => {
		pointer = event.pointerType || 'mouse';
		wasOpen = Boolean(open && open.trigger.contains(event.target));
		if (open && !open.trigger.contains(event.target)) {
			hide();
		}
	}, true);
	document.addEventListener('keydown', event => {
		if (event.key === 'Escape') {
			hide();
			for (const button of menus) {
				if (button.getAttribute('aria-expanded') === 'true') {
					setMenu(button, false);
					button.focus();
				}
			}
		}
	});

	// Table of contents: highlight the section being read.
	const header = document.querySelector('.site-header');
	const tocLinks = [...document.querySelectorAll('.toc a')];
	const sections = tocLinks.map(link => byId(decodeURIComponent(link.hash.slice(1))));
	let frame = 0;
	const spy = () => {
		frame = 0;
		const offset = (header ? header.offsetHeight : 0) + 32;
		let index = 0;
		for (const [i, section] of sections.entries()) {
			if (section && section.getBoundingClientRect().top - offset <= 0) {
				index = i;
			}
		}

		if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 4) {
			index = sections.length - 1;
		}

		for (const [i, link] of tocLinks.entries()) {
			link.classList.toggle('active', i === index);
		}
	};

	const onScroll = () => {
		if (open) {
			place(open.trigger, open.tip);
		}

		if (tocLinks.length > 0 && !frame) {
			frame = globalThis.requestAnimationFrame(spy);
		}
	};

	window.addEventListener('scroll', onScroll, {passive: true});
	window.addEventListener('resize', onScroll, {passive: true});
	if (tocLinks.length > 0) {
		spy();
	}

	// Tabs: arrow keys move between them, as in the WAI-ARIA tabs pattern.
	for (const list of document.querySelectorAll('[role="tablist"]')) {
		const tabs = [...list.querySelectorAll('[role="tab"]')];
		const select = tab => {
			for (const other of tabs) {
				const selected = other === tab;
				other.setAttribute('aria-selected', String(selected));
				other.tabIndex = selected ? 0 : -1;
				byId(other.getAttribute('aria-controls')).hidden = !selected;
			}
		};

		for (const [index, tab] of tabs.entries()) {
			tab.addEventListener('click', () => select(tab));
			tab.addEventListener('keydown', event => {
				const step = {ArrowRight: 1, ArrowLeft: -1}[event.key];
				if (step) {
					const next = tabs[(index + step + tabs.length) % tabs.length];
					select(next);
					next.focus();
					event.preventDefault();
				}
			});
		}
	}

	// Popovers are dialogs: focus goes to the first control when one opens.
	for (const pop of document.querySelectorAll('[popover][role="dialog"]')) {
		pop.addEventListener('toggle', event => {
			if (event.newState === 'open') {
				const first = pop.querySelector('video, button:not([popovertargetaction="hide"]), a[href], input');
				if (first) {
					first.focus();
				}
			}
		});
	}

	// The video: the Watch button opens it in a popover where popovers are
	// supported, and the MP4 itself everywhere else. Closing it pauses it.
	const videoPop = document.querySelector('[data-video-pop]');
	if (videoPop && typeof videoPop.showPopover === 'function') {
		const video = videoPop.querySelector('video');
		let opener = null;
		for (const link of document.querySelectorAll('[data-video-open]')) {
			link.addEventListener('click', event => {
				if (event.metaKey || event.ctrlKey || event.shiftKey || event.button === 1) {
					return;
				}

				event.preventDefault();
				opener = link;
				// The poster loads only when someone opens the video.
				if (!video.poster && video.dataset.poster) {
					video.poster = video.dataset.poster;
				}

				videoPop.showPopover();
			});
		}

		videoPop.addEventListener('toggle', event => {
			if (event.newState === 'closed') {
				video.pause();
				if (opener) {
					opener.focus();
				}
			}
		});
	}

	// Languages: a choice made in the menu is kept, so the first-visit redirect
	// to the browser's language never overrides it.
	for (const link of document.querySelectorAll('[data-lang]')) {
		link.addEventListener('click', () => {
			try {
				localStorage.setItem('lang', link.dataset.lang);
			} catch {}
		});
	}

	// Sharing: plain links to each network's own share page, the device's share
	// sheet where there is one, and a copy button.
	const sharePop = document.querySelector('[data-share-pop]');
	if (sharePop) {
		const data = {title: document.title, text: sharePop.dataset.text, url: sharePop.dataset.url};
		const canNative = typeof navigator.share === 'function' && (!navigator.canShare || navigator.canShare(data));
		const touch = globalThis.matchMedia && globalThis.matchMedia('(pointer: coarse)').matches;
		const status = sharePop.querySelector('[data-share-status]');
		const statusText = status.textContent;
		const nativeShare = async () => {
			try {
				await navigator.share(data);
			} catch {}
		};

		const nativeButton = sharePop.querySelector('[data-share-native]');
		if (canNative) {
			nativeButton.hidden = false;
			nativeButton.addEventListener('click', nativeShare);
		}

		// On phones and tablets, Share opens the system share sheet directly.
		for (const button of document.querySelectorAll('[data-share]')) {
			button.addEventListener('click', event => {
				if (canNative && touch) {
					event.preventDefault();
					nativeShare();
				}
			});
		}

		const field = sharePop.querySelector('[data-share-url]');
		field.addEventListener('focus', () => field.select());
		sharePop.querySelector('[data-share-copy]').addEventListener('click', async () => {
			await copyText(data.url);
			status.textContent = sharePop.dataset.copied || 'Link copied.';
		});

		// Email and Messages links need an app for mailto: or sms:. Without one the
		// browser does nothing, so if the page keeps focus, copy the text instead.
		for (const link of sharePop.querySelectorAll('a[href^="mailto:"], a[href^="sms:"]')) {
			link.addEventListener('click', () => {
				let left = false;
				const away = () => {
					left = true;
				};

				window.addEventListener('blur', away, {once: true});
				setTimeout(async () => {
					window.removeEventListener('blur', away);
					if (!left && document.visibilityState === 'visible') {
						await copyText(`${data.text} ${data.url}`);
						status.textContent = sharePop.dataset.noApp || 'No app opened, so the text and link were copied.';
					}
				}, 1500);
			});
		}

		// Mastodon has no central share page: ask for the server once and remember it.
		const mastodonLink = sharePop.querySelector('[data-mastodon]');
		const mastodonForm = sharePop.querySelector('[data-mastodon-form]');
		const mastodonInput = mastodonForm.querySelector('input');
		try {
			mastodonInput.value = localStorage.getItem('mastodon') || '';
		} catch {}

		mastodonLink.addEventListener('click', event => {
			event.preventDefault();
			mastodonForm.hidden = false;
			mastodonInput.focus();
		});
		mastodonForm.addEventListener('submit', event => {
			event.preventDefault();
			const host = (mastodonInput.value || 'mastodon.social').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '');
			if (!/^([a-z\d]([a-z\d-]*[a-z\d])?\.)+[a-z]{2,}$/.test(host)) {
				status.textContent = sharePop.dataset.badServer || 'Enter a server name such as mastodon.social.';
				return;
			}

			status.textContent = statusText;
			try {
				localStorage.setItem('mastodon', host);
			} catch {}

			window.open(`https://${host}/share?text=${encodeURIComponent(`${data.text} ${data.url}`)}`, '_blank', 'noopener');
		});
	}

	// Keep the current page visible in a long sidebar.
	const nav = document.querySelector('.sidebar');
	const current = nav && nav.querySelector('[aria-current="page"]');
	if (current && nav.scrollHeight > nav.clientHeight && current.offsetTop > nav.clientHeight * 0.6) {
		nav.scrollTop = current.offsetTop - (nav.clientHeight / 3);
	}
})();
