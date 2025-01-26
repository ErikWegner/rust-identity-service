import { Page } from "@playwright/test";

export type KnownUsers = 'user1';

export const loginUser = async (page: Page, user: KnownUsers) => {
  await page.getByRole('textbox', { name: 'Username or email' }).fill('user1');
  await page.getByRole('textbox', { name: 'Password' }).fill('user1');
  await page.getByRole('button', { name: 'Sign In' }).click();
}
