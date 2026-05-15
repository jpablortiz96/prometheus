import { mkdir } from "node:fs/promises";
import path from "node:path";

import { chromium } from "playwright";

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "apps", "web", "public", "screenshots", "final");
const BASE_URL = process.env.SCREENSHOT_BASE_URL ?? "http://127.0.0.1:3000";

function failIfErrors(errors) {
  if (errors.length === 0) {
    return;
  }
  throw new Error(`Client-side runtime errors detected: ${errors.join(" | ")}`);
}

async function dismissOverlayIfPresent(page) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const overlay = page.locator(".overlay-shell").first();
    const visible = await overlay.isVisible().catch(() => false);
    if (!visible) {
      return;
    }
    const closeButton = overlay.getByRole("button", { name: "Close" }).first();
    await closeButton.click({ force: true });
    await page.waitForTimeout(500);
  }
  await page.evaluate(() => {
    document.querySelectorAll(".overlay-shell").forEach((node) => node.remove());
  });
}

async function capture() {
  await mkdir(OUTPUT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const runtimeErrors = [];
  page.on("pageerror", (error) => {
    runtimeErrors.push(error.message);
  });

  await page.goto(BASE_URL, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await page.waitForTimeout(1000);
  await dismissOverlayIfPresent(page);
  await page.screenshot({ path: path.join(OUTPUT_DIR, "dashboard.png"), fullPage: true });

  const integrationPanel = page.locator(".stack-panel").filter({ hasText: "Operational dependencies" }).first();
  await integrationPanel.scrollIntoViewIfNeeded();
  await integrationPanel.screenshot({ path: path.join(OUTPUT_DIR, "integration-status.png") });

  await page.getByRole("button", { name: "Judge Mode" }).click({ force: true });
  await page.screenshot({ path: path.join(OUTPUT_DIR, "judge-mode.png"), fullPage: true });

  await page.goto(BASE_URL, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await dismissOverlayIfPresent(page);
  const firstStreamCard = page.locator(".stream-card").first();
  await firstStreamCard.scrollIntoViewIfNeeded();
  await firstStreamCard.evaluate((node) => {
    node.click();
  });
  await page.screenshot({ path: path.join(OUTPUT_DIR, "evidence-drawer.png"), fullPage: true });

  await page.goto(BASE_URL, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await dismissOverlayIfPresent(page);
  await page.getByRole("button", { name: "Generate Audit Bundle" }).click({ force: true });
  await page.screenshot({ path: path.join(OUTPUT_DIR, "audit-bundle.png"), fullPage: true });

  await page.goto(BASE_URL, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await dismissOverlayIfPresent(page);
  await page.getByRole("button", { name: "Red Team Drill" }).click({ force: true });
  await page.waitForTimeout(8_500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, "tribunal-modal.png"), fullPage: true });

  await page.goto(`${BASE_URL}/demo`, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await page.screenshot({ path: path.join(OUTPUT_DIR, "demo-route.png"), fullPage: true });

  await page.goto(`${BASE_URL}/scenarios`, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await page.screenshot({ path: path.join(OUTPUT_DIR, "scenario-lab.png"), fullPage: true });

  await page.goto(`${BASE_URL}/threat-intel`, { waitUntil: "load", timeout: 60000 });
  await page.waitForSelector(".hero-bar", { timeout: 60000 });
  await page.getByRole("button", { name: "Analyze + Run Safe Simulation" }).click({ force: true });
  await page.waitForSelector("text=Live Agent Tool Gateway proof", { timeout: 60000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, "threat-intel.png"), fullPage: true });

  failIfErrors(runtimeErrors);

  await browser.close();
  console.log(`Screenshots saved to ${OUTPUT_DIR}`);
}

capture().catch((error) => {
  console.error(error);
  process.exit(1);
});
