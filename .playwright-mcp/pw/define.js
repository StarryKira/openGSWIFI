async (page0) => { const fn = async (page, LABEL, SCHEME, BASE = 'http://127.0.0.1:18080', PREFIX = '') => {
  const dir = '/private/tmp/claude-501/-Users-haruka-RustroverProjects-openGSWIFI/8d715e2d-43a0-4bef-af8d-ef0e55f2d27e/scratchpad/luci-shots';
  const errors = [];
  const onC = m => { if (m.type() === 'error') errors.push(m.text().slice(0, 200)); };
  const onE = e => errors.push('pageerror: ' + String(e).slice(0, 200));
  page.on('console', onC); page.on('pageerror', onE);
  await page.emulateMedia({ colorScheme: SCHEME });

  const login = async () => {
    await page.goto(BASE + '/cgi-bin/luci/');
    await page.waitForLoadState('domcontentloaded');
    const pw = page.locator('input[name="luci_password"]');
    if (await pw.count()) {
      await pw.fill('password');
      await Promise.all([ page.waitForLoadState('networkidle'), pw.press('Enter') ]);
    }
  };

  // Contrast of every piece of text inside our own widgets against what is
  // really behind it (translucent layers and opacity composited).
  const analyze = () => page.evaluate(() => {
    const cv = document.createElement('canvas'); cv.width = cv.height = 1;
    const cx = cv.getContext('2d', { willReadFrequently: true });
    const rgba = (c) => { cx.clearRect(0, 0, 1, 1); cx.fillStyle = '#000'; cx.fillStyle = c; cx.fillRect(0, 0, 1, 1); const d = cx.getImageData(0, 0, 1, 1).data; return [d[0], d[1], d[2], d[3] / 255]; };
    const over = (top, bot) => { const a = top[3]; return [0, 1, 2].map(i => top[i] * a + bot[i] * (1 - a)).concat(1); };
    const lum = (c) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
    const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
    const bgOf = (el) => {
      const chain = [];
      for (let e = el; e; e = e.parentElement) chain.push(e);
      let bg = [255, 255, 255, 1], img = false;
      for (let i = chain.length - 1; i >= 0; i--) {
        const cs = getComputedStyle(chain[i]);
        if (cs.backgroundImage && cs.backgroundImage !== 'none' && chain[i] !== el) img = true;
        const c = rgba(cs.backgroundColor);
        if (c[3] > 0) bg = over(c, bg);
      }
      return { bg, img };
    };
    const out = [];
    const roots = document.querySelectorAll('#maincontent .gsw, #view .gsw');
    const seen = new Set();
    roots.forEach(root => root.querySelectorAll('*').forEach(el => {
      if (seen.has(el)) return; seen.add(el);
      const own = Array.from(el.childNodes).filter(n => n.nodeType === 3 && n.nodeValue.trim()).map(n => n.nodeValue.trim()).join(' ');
      if (!own) return;
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) return;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.display === 'none') return;
      let op = 1;
      for (let e = el; e; e = e.parentElement) op *= parseFloat(getComputedStyle(e).opacity);
      const { bg, img } = bgOf(el);
      const fg0 = rgba(cs.color); fg0[3] *= op;
      const fg = over(fg0, bg);
      const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 600;
      out.push({ cls: (el.className && el.className.baseVal === undefined ? String(el.className) : el.tagName).slice(0, 40) || el.tagName, tag: el.tagName, text: own.slice(0, 24), ratio: Math.round(ratio(fg, bg) * 100) / 100, large: size >= 24 || (size >= 18.5 && bold), img });
    }));
    out.sort((a, b) => a.ratio - b.ratio);
    const vw = document.documentElement.clientWidth;
    const wide = Array.from(document.querySelectorAll('#maincontent .gsw *')).filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && (r.right > vw + 1); }).slice(0, 5).map(e => (String(e.className) || e.tagName).slice(0, 40) + ' right=' + Math.round(e.getBoundingClientRect().right));
    return {
      n: out.length,
      min: out.length ? out[0].ratio : null,
      low: out.filter(o => o.ratio < (o.large ? 3 : 4.5)).slice(0, 8),
      overflowX: document.documentElement.scrollWidth - vw,
      wide,
      html: { darkmode: document.documentElement.getAttribute('data-darkmode'), argon: document.documentElement.getAttribute('data-argon-mode'), bodyBg: getComputedStyle(document.body).backgroundColor }
    };
  });

  const result = {};
  for (const [vname, w, h] of [['desktop', 1280, 900], ['phone', 390, 844]]) {
    await page.setViewportSize({ width: w, height: h });
    await login();
    for (const p of ['overview', 'settings', 'protect', 'log', 'tools']) {
      await page.goto(BASE + '/cgi-bin/luci/admin/services/gswifi/' + p);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1800);
      if (p === 'tools') {
        // exercise the calculator and one command card so their output is on the page
        await page.fill('input[placeholder="宽带账号"]', '13800000000@GDPF.XY');
        await page.click('button:has-text("计算")');
        await page.waitForTimeout(900);
      }
      result[`${p}/${vname}`] = await analyze();
      const extra = await page.evaluate(() => Math.max(0, ...Array.from(document.querySelectorAll('*')).filter(e => /(auto|scroll)/.test(getComputedStyle(e).overflowY) && e !== document.documentElement && e !== document.body && e.clientHeight > 300 && !e.classList.contains('gsw-log') && !e.classList.contains('gsw-pre')).map(e => e.scrollHeight - e.clientHeight)));
      if (extra > 0) { await page.setViewportSize({ width: w, height: h + extra + 40 }); await page.waitForTimeout(500); }
      await page.screenshot({ path: `${dir}/${PREFIX}${p}-${LABEL}-${vname}.png`, fullPage: true });
      if (extra > 0) await page.setViewportSize({ width: w, height: h });

    }
  }
  page.off('console', onC); page.off('pageerror', onE);
  const summary = Object.fromEntries(Object.entries(result).map(([k, v]) => [k, { n: v.n, min: v.min, low: v.low.map(l => `${l.ratio} ${l.cls}|${l.text}${l.img ? ' (img bg)' : ''}`), overflowX: v.overflowX, wide: v.wide }]));
  return { label: LABEL, html: Object.values(result)[0].html, errors: [...new Set(errors)], summary };
}; page0.context().__gswMatrix = fn; try { globalThis.__gswMatrix = fn; } catch (e) {} return 'defined'; }
