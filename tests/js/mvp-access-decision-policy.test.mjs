import test from "node:test";
import assert from "node:assert/strict";

import {
  isApplicationApprovalRole,
} from "../../supabase/functions/access-applications/decision-policy.mjs";

test("access applications can only approve non-privileged member roles", () => {
  for (const role of ["collector", "analyst", "editor", "approver"]) {
    assert.equal(isApplicationApprovalRole(role), true, role);
  }

  for (const role of ["owner", "admin", "OWNER", "", null, undefined]) {
    assert.equal(isApplicationApprovalRole(role), false, String(role));
  }
});
