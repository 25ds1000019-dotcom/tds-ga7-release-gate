module.exports = (req, res) => {
 const x=req.body, out=r=>res.status(200).json({decision:r==='APPROVE'?'approve':'reject',reason:r});
 const bad=!x||typeof x!=='object'||Array.isArray(x)||typeof x.environment!=='string'||!x.state||typeof x.state!=='object'||Array.isArray(x.state)||typeof x.providerVersion!=='string'||typeof x.destroyApproved!=='boolean'||!x.resource||typeof x.resource!=='object'||Array.isArray(x.resource);
 if(bad) return out('INVALID_PLAN'); const s=x.state,r=x.resource;
 if(typeof s.backend!=='string'||typeof s.locked!=='boolean'||typeof r.address!=='string'||typeof r.type!=='string'||!['create','update','delete'].includes(r.action)||!r.labels||typeof r.labels!=='object'||Array.isArray(r.labels)||typeof r.forceDestroy!=='boolean'||!(r.secret===null||typeof r.secret==='string')) return out('INVALID_PLAN');
 if(x.environment!=='prod-pdyl30') return out('ENVIRONMENT_MISMATCH');
 if(!['gcs','s3','azurerm','remote'].includes(s.backend)||s.locked!==true) return out('STATE_UNSAFE');
 if(!['6.2.1','= 6.2.1','~> 6.0'].includes(x.providerVersion)) return out('UNPINNED_PROVIDER');
 const l={owner:'student-qq670',environment:'production',cost_center:'cc-zpsv'}; if(Object.keys(l).some(k=>r.labels[k]!==l[k])) return out('MISSING_LABELS');
 if(!(r.secret===null||(typeof r.secret==='string'&&/^secret://.+/.test(r.secret)))) return out('PLAINTEXT_SECRET');
 if(r.action==='delete'&&['storage_bucket','sql_database','persistent_disk'].includes(r.type)&&x.destroyApproved!==true) return out('DELETE_NOT_APPROVED');
 if(r.type==='storage_bucket'&&r.forceDestroy===true) return out('FORCE_DESTROY'); return out('APPROVE');
};
