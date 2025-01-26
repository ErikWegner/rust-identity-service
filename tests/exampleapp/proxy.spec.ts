import { test, expect } from '@playwright/test';
import { configuration } from '../conf.ts';
import { loginUser } from '../helper.ts';

test('test', async ({ page }) => {
  const conf = await configuration();
  await page.goto(conf.baseUrl + "/exampleapp/");
  // Start unauthenticated
  await expect(page.locator('#loginStatus')).toContainText('not authenticated');

  // Make request to echo endpoint
  await expect(page.locator('#csrftoken')).toBeEmpty();
  await page.getByRole('button', { name: 'Echo request' }).click();
  // Proxying request is denied
  await expect(page.locator('#echoresponse')).toContainText('Missing or invalid CSRF token');

  // Login as user1
  await page.getByRole('button', { name: 'Login' }).click();
  await loginUser(page, 'user1');
  await expect(page.locator('#loginStatus')).toContainText('authenticated');

  // Make authenticated request to echo endpoint
  await expect(page.locator('#csrftoken')).toBeEmpty();
  await page.getByRole('button', { name: 'Echo request' }).click();
  await expect(page.locator('#echoresponse')).toContainText('Missing or invalid CSRF token');

  // Obtain CSRF token
  await page.getByRole('button', { name: 'CSRF-Token' }).click();
  await expect(page.locator('#csrftoken')).not.toBeEmpty();

  // Make authenticated request to echo endpoint with CSRF token
  await page.getByRole('button', { name: 'Echo request' }).click();

  // Request was successful
  await expect(page.locator('#echoresponse')).toContainText('POST request at //echorequest');

  // JWT was sent
  await expect(page.locator('#echoresponse')).toContainText('authorization: Bearer eyJhb');

  await page.getByRole('button', { name: 'Logout' }).click();
  await expect(page.locator('#loginStatus')).toContainText('not authenticated');
  await expect(page.locator('#csrftoken')).toBeEmpty();
});
