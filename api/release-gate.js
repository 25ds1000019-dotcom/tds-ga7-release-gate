module.exports = (req, res) => {
  const x = req.body || {}; const w = x.workflow || {}; const i = x.image || {}; const v = [];
  const p = w.permissions || {}; const expected = { contents: 'read', packages: 'write', 'id-token': 'none' };
  if (Object.keys(p).length !== 3 || Object.keys(expected).some(k => p[k] !== expected[k])) v.push('EXCESS_PERMISSION');
  if (x.event === 'pull_request' && w.trigger !== 'pull_request') v.push('UNSAFE_PR_TRIGGER');
  if (w.testsPassed !== true || w.matrixComplete !== true || w.failFast !== false) v.push('TESTS_INCOMPLETE');
  if (!Array.isArray(w.actions) || w.actions.some(a => !a || (a.owner !== 'actions' && !/^[0-9a-f]{40}$/.test(a.ref || '')))) v.push('MUTABLE_ACTION');
  if (i.multiStage !== true) v.push('SINGLE_STAGE_IMAGE'); if (i.runsAsRoot !== false) v.push('ROOT_RUNTIME');
  if (!['none','buildkit'].includes(i.secretMode)) v.push('SECRET_IN_LAYER'); if (i.criticalVulnerabilities !== 0) v.push('CRITICAL_CVE'); if (i.digestPinned !== true) v.push('UNPINNED_IMAGE');
  if (x.target === 'production') { if (x.event !== 'push' || x.ref !== 'refs/heads/main') v.push('INVALID_PRODUCTION_REF'); if (w.environmentApproval !== true) v.push('APPROVAL_REQUIRED'); }
  res.status(200).json({ decision: v.length ? 'block' : 'promote', violations: v });
};
