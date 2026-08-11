import assert from "node:assert/strict";
import { test } from "node:test";

import {
  accessProvisioningStatus,
} from "../../supabase/functions/access-applications/provisioning-outcome.mjs";
import {
  applicationOutcomeForClaimAction,
  applicationOutcomeForCompletion,
} from "../../supabase/functions/invite-member/provisioning.mjs";

test("access decision reports invited only after the application transition applied", () => {
  assert.equal(accessProvisioningStatus({
    applicationApplied: true,
    applicationOutcome: "invited",
  }), "invited");
  assert.equal(accessProvisioningStatus({
    applicationApplied: false,
    applicationOutcome: "invited",
  }), "retryable");
  assert.equal(accessProvisioningStatus(null), "retryable");
});

test("deterministic failures cancel while transient or busy attempts stay retryable", () => {
  assert.equal(applicationOutcomeForCompletion({
    applied: true,
    outcome: "deterministic_failure",
    reason: null,
    compensate: false,
  }), "cancelled");
  assert.equal(applicationOutcomeForCompletion({
    applied: true,
    outcome: "retryable_failure",
    reason: null,
    compensate: false,
  }), "retryable");
  assert.equal(applicationOutcomeForClaimAction("busy"), "retryable");
  assert.equal(applicationOutcomeForClaimAction("provisioned"), "invited");
  assert.equal(applicationOutcomeForClaimAction("cancelled"), "cancelled");
  assert.equal(applicationOutcomeForClaimAction("unknown"), "retryable");
});

test("completion loss never claims that an invitation was sent", () => {
  assert.equal(applicationOutcomeForCompletion({
    applied: false,
    outcome: "provisioned",
    reason: "stale_attempt",
    compensate: false,
  }), "retryable");
  assert.equal(accessProvisioningStatus({
    applicationApplied: true,
    applicationOutcome: "cancelled",
  }), "cancelled");
  assert.equal(accessProvisioningStatus({
    applicationApplied: true,
    applicationOutcome: "unexpected",
  }), "retryable");
});
