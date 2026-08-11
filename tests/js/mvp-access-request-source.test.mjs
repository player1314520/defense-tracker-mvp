import assert from "node:assert/strict";
import { test } from "node:test";

import {
  trustedRequestSource,
} from "../../supabase/functions/access-applications/request-source.mjs";


test("request source accepts only the proxy-overwritten single IP header", () => {
  assert.equal(
    trustedRequestSource(new Headers({ "x-v9-client-ip": "203.0.113.7" })),
    "203.0.113.7",
  );
  assert.equal(
    trustedRequestSource(new Headers({ "x-v9-client-ip": "2001:DB8::7" })),
    "2001:db8::7",
  );
});


test("client-controlled forwarding headers and lists are ignored", () => {
  assert.equal(
    trustedRequestSource(new Headers({
      "x-real-ip": "203.0.113.8",
      "cf-connecting-ip": "203.0.113.9",
      "x-forwarded-for": "203.0.113.10",
    })),
    "unavailable",
  );
  assert.equal(
    trustedRequestSource(new Headers({
      "x-v9-client-ip": "203.0.113.7, 198.51.100.2",
    })),
    "unavailable",
  );
  assert.equal(
    trustedRequestSource(new Headers({ "x-v9-client-ip": "not-an-ip" })),
    "unavailable",
  );
});
