function respond(value) {
  return ContentService.createTextOutput(JSON.stringify(value)).setMimeType(ContentService.MimeType.JSON);
}

function exactlyLeastPrivilege(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) return false;
  var wanted = { contents: 'read', packages: 'write', 'id-token': 'none' };
  var keys = Object.keys(p).sort();
  var expected = Object.keys(wanted).sort();
  return keys.length === expected.length && keys.every(function(k, i) { return k === expected[i] && p[k] === wanted[k]; });
}

function evaluateReleaseGate(input) {
  var violations = [];
  var workflow = input && input.workflow && typeof input.workflow === 'object' ? input.workflow : {};
  var image = input && input.image && typeof input.image === 'object' ? input.image : {};
  if (!exactlyLeastPrivilege(workflow.permissions)) violations.push('EXCESS_PERMISSION');
  if (input && input.event === 'pull_request' && workflow.trigger !== 'pull_request') violations.push('UNSAFE_PR_TRIGGER');
  if (workflow.testsPassed !== true || workflow.matrixComplete !== true || workflow.failFast !== false) violations.push('TESTS_INCOMPLETE');
  if (!Array.isArray(workflow.actions) || workflow.actions.some(function(a) { return !a || (a.owner !== 'actions' && !/^[0-9a-f]{40}$/.test(a.ref || '')); })) violations.push('MUTABLE_ACTION');
  if (image.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (image.runsAsRoot !== false) violations.push('ROOT_RUNTIME');
  if (image.secretMode !== 'none' && image.secretMode !== 'buildkit') violations.push('SECRET_IN_LAYER');
  if (image.criticalVulnerabilities !== 0) violations.push('CRITICAL_CVE');
  if (image.digestPinned !== true) violations.push('UNPINNED_IMAGE');
  if (input && input.target === 'production') {
    if (input.event !== 'push' || input.ref !== 'refs/heads/main') violations.push('INVALID_PRODUCTION_REF');
    if (workflow.environmentApproval !== true) violations.push('APPROVAL_REQUIRED');
  }
  return { decision: violations.length ? 'block' : 'promote', violations: violations };
}

function doPost(e) {
  try { return respond(evaluateReleaseGate(JSON.parse(e.postData.contents))); }
  catch (_) { return respond({ decision: 'block', violations: ['TESTS_INCOMPLETE'] }); }
}
function doGet() { return respond({ decision: 'block', violations: ['TESTS_INCOMPLETE'] }); }
