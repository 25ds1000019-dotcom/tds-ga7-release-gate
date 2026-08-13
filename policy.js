'use strict';

const LEAST_PRIVILEGE = { contents: 'read', packages: 'write', 'id-token': 'none' };
const SHA40 = /^[0-9a-f]{40}$/;

function exactlyLeastPrivilege(permissions) {
  if (!permissions || typeof permissions !== 'object' || Array.isArray(permissions)) return false;
  const keys = Object.keys(permissions).sort();
  const expected = Object.keys(LEAST_PRIVILEGE).sort();
  return keys.length === expected.length && keys.every((key, i) => key === expected[i] && permissions[key] === LEAST_PRIVILEGE[key]);
}

function evaluateReleaseGate(input) {
  const violations = [];
  const workflow = input && input.workflow && typeof input.workflow === 'object' ? input.workflow : {};
  const image = input && input.image && typeof input.image === 'object' ? input.image : {};

  if (!exactlyLeastPrivilege(workflow.permissions)) violations.push('EXCESS_PERMISSION');
  if (input?.event === 'pull_request' && workflow.trigger !== 'pull_request') violations.push('UNSAFE_PR_TRIGGER');
  if (workflow.testsPassed !== true || workflow.matrixComplete !== true || workflow.failFast !== false) violations.push('TESTS_INCOMPLETE');

  if (!Array.isArray(workflow.actions) || workflow.actions.some(action => !action || action.owner !== 'actions' && !SHA40.test(action.ref || ''))) violations.push('MUTABLE_ACTION');
  if (image.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (image.runsAsRoot !== false) violations.push('ROOT_RUNTIME');
  if (image.secretMode !== 'none' && image.secretMode !== 'buildkit') violations.push('SECRET_IN_LAYER');
  if (image.criticalVulnerabilities !== 0) violations.push('CRITICAL_CVE');
  if (image.digestPinned !== true) violations.push('UNPINNED_IMAGE');

  if (input?.target === 'production') {
    if (input.event !== 'push' || input.ref !== 'refs/heads/main') violations.push('INVALID_PRODUCTION_REF');
    if (workflow.environmentApproval !== true) violations.push('APPROVAL_REQUIRED');
  }
  return { decision: violations.length ? 'block' : 'promote', violations };
}

module.exports = { evaluateReleaseGate };
