import assert from "node:assert/strict";
import { test } from "node:test";

import {
  classifyInviteError,
  classifyThrownInviteError,
} from "../../supabase/functions/invite-member/provisioning.mjs";


test("invitation provider errors have bounded retry semantics", () => {
  assert.deepEqual(classifyInviteError(null), {
    outcome: "provisioned",
    resultCode: "created",
  });
  assert.deepEqual(classifyInviteError({ code: "user_already_exists" }), {
    outcome: "provisioned",
    resultCode: "already_exists",
  });
  assert.deepEqual(classifyInviteError({ status: 429 }), {
    outcome: "retryable_failure",
    resultCode: "rate_limited",
  });
  assert.deepEqual(classifyInviteError({ status: 503 }), {
    outcome: "retryable_failure",
    resultCode: "provider_unavailable",
  });
  assert.deepEqual(
    classifyInviteError({ code: "email_address_invalid" }),
    { outcome: "deterministic_failure", resultCode: "invalid_identity" },
  );
});


test("only abort exceptions are classified as timeouts", () => {
  assert.deepEqual(classifyThrownInviteError({ name: "AbortError" }), {
    outcome: "retryable_failure",
    resultCode: "timeout",
  });
  assert.deepEqual(classifyThrownInviteError(new Error("redacted")), {
    outcome: "retryable_failure",
    resultCode: "unexpected",
  });
});
