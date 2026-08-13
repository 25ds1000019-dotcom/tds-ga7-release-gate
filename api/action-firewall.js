module.exports = (req, res) => {
  const x = req.body; const out = r => res.status(200).json({decision:r==='ALLOW'?'allow':'block',reason:r});
  if (!x || typeof x !== 'object' || Array.isArray(x) || !['provenance','humanApproved','untrustedContent','action'].every(k=>k in x) && !['provenance','humanApproved','action'].every(k=>k in x) || Object.keys(x).some(k=>!['provenance','humanApproved','untrustedContent','action'].includes(k)) || !['trusted','untrusted'].includes(x.provenance) || typeof x.humanApproved !== 'boolean' || ('untrustedContent' in x && typeof x.untrustedContent !== 'string') || !x.action || typeof x.action !== 'object' || Array.isArray(x.action) || typeof x.action.tool !== 'string' || !x.action.args || typeof x.action.args !== 'object' || Array.isArray(x.action.args) || Object.keys(x.action).some(k=>!['tool','args'].includes(k))) return out('INVALID_SCHEMA');
  const t=x.action.tool,a=x.action.args, exact=(keys)=>Object.keys(a).length===keys.length&&keys.every(k=>k in a);
  if (!['search','lookup_record','send_email','render_html'].includes(t)) return out('TOOL_NOT_ALLOWED');
  if (t==='search' && (!exact(['query'])||typeof a.query!=='string'||a.query.length<1||a.query.length>200)) return out('INVALID_SCHEMA');
  if (t==='lookup_record' && (!exact(['tenantId','recordId'])||typeof a.tenantId!=='string'||typeof a.recordId!=='string'||!a.recordId)) return out('INVALID_SCHEMA');
  if (t==='send_email' && (!exact(['to','subject','body'])||['to','subject','body'].some(k=>typeof a[k]!=='string'))) return out('INVALID_SCHEMA');
  if (t==='render_html' && (!exact(['html'])||typeof a.html!=='string')) return out('INVALID_SCHEMA');
  if (t==='lookup_record' && a.tenantId!=='tenant-xmr54zi') return out('TENANT_SCOPE');
  if (t==='send_email' && (!/^[^@\s]+@notify-fbxszdp\.example$/i.test(a.to) || a.to.slice(a.to.lastIndexOf('@')+1)!=='notify-fbxszdp.example')) return out('EGRESS_DENIED');
  if (t==='send_email' && !x.humanApproved) return out('APPROVAL_REQUIRED');
  if (t==='render_html' && /<\s*(script|iframe)\b|\bon\w+\s*=|javascript\s*:/i.test(a.html)) return out('UNSAFE_OUTPUT');
  return out('ALLOW');
};
