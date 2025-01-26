import { test, expect } from '@playwright/test';
import { configuration } from '../conf.ts';

test('test', async ({ page }) => {
  const conf = await configuration();
  await page.goto(conf.baseUrl);
  await expect(page.getByText('This is the default page.')).toBeVisible();
});
