'use strict';
const assert = require('node:assert/strict');
const { evaluateReleaseGate } = require('./policy');

const safe = {
  target: 'production', event: 'push', ref: 'refs/heads/main',
  workflow: { trigger: 'push', permissions: { contents: 'read', packages: 'write', 'id-token': 'none' }, testsPassed: true, matrixComplete: true, failFast: false, environmentApproval: true, actions: [{ owner: 'actions', name: 'checkout', ref: 'v4' }, { owner: 'docker', name: 'login-action', ref: '0123456789abcdef0123456789abcdef01234567' }] },
  image: { multiStage: true, runsAsRoot: false, secretMode: 'buildkit', criticalVulnerabilities: 0, digestPinned: true }
};
assert.deepEqual(evaluateReleaseGate(safe), { decision: 'promote', violations: [] });
assert.deepEqual(evaluateReleaseGate({ ...safe, event: 'pull_request', target: 'preview', workflow: { ...safe.workflow, trigger: 'pull_request_target', environmentApproval: undefined } }).violations, ['UNSAFE_PR_TRIGGER']);
assert.deepEqual(evaluateReleaseGate({ ...safe, workflow: { ...safe.workflow, permissions: { contents: 'read', packages: 'write', 'id-token': 'write' } }, image: { ...safe.image, runsAsRoot: true } }).violations, ['EXCESS_PERMISSION', 'ROOT_RUNTIME']);
console.log('release gate policy tests passed');
