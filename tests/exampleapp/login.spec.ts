import { test, expect } from '@playwright/test';
import { configuration } from '../conf.ts';

test('test', async ({ page }) => {
  const conf = await configuration();
  await page.goto(conf.baseUrl + "/exampleapp/");
  await expect(page.getByText('This is the example app.')).toBeVisible();
  await expect(page.getByText('not authenticated')).toBeVisible();
  await page.getByRole('button', { name: 'Login' }).click();
  await page.getByRole('textbox', { name: 'Username or email' }).fill('user1');
  await page.getByRole('textbox', { name: 'Password' }).fill('user1');
  await page.getByRole('button', { name: 'Sign In' }).click();
  await expect(page.locator("#loginStatus")).toContainText("authenticated");
  await page.getByRole('button', { name: 'Logout' }).click();
  await expect(page.locator("#loginStatus")).toContainText('not authenticated');
});
