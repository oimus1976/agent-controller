import { reset } from "cloudflare:test";
import { afterEach } from "vitest";

afterEach(async () => {
  await reset();
});
