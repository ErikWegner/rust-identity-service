import { test, expect } from '@playwright/test';
import { configuration } from './conf.ts';

test.describe('/app', () => {
  test.describe('/up', () => {
    test('is OK', async ({ request }) => {
      const conf = await configuration();
      const response = await request.get(conf.baseUrl + '/app/up');

      expect(response.status()).toBe(200);
      expect(await response.text()).toBe("up");
    });
  });
});
