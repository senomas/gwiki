'use strict';
// Usage: node screenshot.js
// Env: E2E_BASE_URL, E2E_AUTH_USER, E2E_AUTH_PASS, SCREENSHOT_DIR
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const baseURL = process.env.E2E_BASE_URL || 'http://gwiki:8080';
const authUser = process.env.E2E_AUTH_USER || '';
const authPass = process.env.E2E_AUTH_PASS || '';
const screenshotDir = process.env.SCREENSHOT_DIR || '/work/tests/e2e/screenshots';

function timestamp() {
  return new Date().toISOString().replace(/[T:]/g, '-').replace(/\..+/, '').replace(/-(\d{2})-(\d{2})$/, '$1$2');
}

(async () => {
  fs.mkdirSync(screenshotDir, { recursive: true });

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });

  await page.goto(`${baseURL}/login`);

  if (authUser && authPass) {
    await page.fill('input[name="username"]', authUser);
    await page.fill('input[name="password"]', authPass);
    await Promise.all([
      page.waitForNavigation({ timeout: 5000 }).catch(() => {}),
      page.click('button[type="submit"]'),
    ]);
    if (page.url().includes('/login')) {
      console.error('Login failed — still on /login');
      await browser.close();
      process.exit(1);
    }
  }

  const ts = timestamp();

  const homePath = path.join(screenshotDir, `home-${ts}.png`);
  await page.screenshot({ path: homePath });
  console.log('home:', homePath);

  const links = await page.evaluate(() =>
    Array.from(document.querySelectorAll('a[href*="/notes/"]'))
      .map(e => e.href)
      .filter(h => !h.includes('/edit') && !h.includes('/new'))
      .slice(0, 1)
  );

  if (links[0]) {
    await page.goto(links[0]);
    await page.waitForTimeout(1000);
    const notePath = path.join(screenshotDir, `note-${ts}.png`);
    await page.screenshot({ path: notePath, fullPage: true });
    console.log('note:', notePath);
  }

  await browser.close();
})();
