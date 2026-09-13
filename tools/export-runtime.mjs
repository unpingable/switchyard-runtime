// Deterministic closed source export. Run with Node 18+; no network or credentials.
import {execFileSync} from 'node:child_process';
import {existsSync, mkdirSync, writeFileSync} from 'node:fs';
import {resolve, dirname} from 'node:path';
import {createHash} from 'node:crypto';
const [sourceArg, revision, destinationArg] = process.argv.slice(2);
if(!sourceArg || !destinationArg || !/^[a-f0-9]{40}$/.test(revision??''))
  throw Error('Usage: node export-runtime.mjs CANONICAL_CHECKOUT FULL_COMMIT_SHA NEW_DESTINATION');
const source=resolve(sourceArg), destination=resolve(destinationArg);
if(existsSync(destination))throw Error('Destination exists; do not overwrite a distribution');
const git=(...args)=>execFileSync('git',['-C',source,...args],{maxBuffer:10*1024*1024});
if(git('status','--porcelain').toString()!=='')throw Error('Canonical source must be clean');
if(git('rev-parse','HEAD').toString().trim()!==revision)throw Error('Revision must equal canonical clean HEAD');
const plain=['src/switchyard/__init__.py','src/switchyard/direct_api.py',
  'src/switchyard/nightshift_adapter.py','src/switchyard/appserver.py','src/switchyard/config.py',
  'src/switchyard/fd_custody.py','src/switchyard/provider_admission.py','src/switchyard/provider_runner.py',
  'src/switchyard/review_verifier.py',
  'src/switchyard/_vendor/__init__.py','src/switchyard/_vendor/rfc8785/__init__.py',
  'src/switchyard/_vendor/rfc8785/_impl.py','src/switchyard/_vendor/rfc8785/LICENSE',
  'src/switchyard/_vendor/rfc8785/VENDOR.md','src/switchyard/_vendor/rfc8785/py.typed',
  'src/switchyard/schemas/nightshift.provider-dispatch-occurrence.v1.schema.json',
  'src/switchyard/schemas/nightshift.worker-start-request.v3.schema.json',
  'src/switchyard/schemas/switchyard.codex-provider-admission.v1.schema.json',
  'src/switchyard/schemas/switchyard.codex-provider-admission.beta.v1.schema.json',
  'src/switchyard/schemas/switchyard.codex-provider-admission.beta-final.v1.schema.json',
  'src/switchyard/schemas/switchyard.codex-provider-admission.bounded-turn.v1.schema.json',
  'tests/test_direct_api.py','tests/test_runtime_packaging.py','tests/test_review_verifier_export.py',
  'tests/test_prelaunch_contract.py','tests/fixtures/prelaunch-vector.json',
  'tests/test_size_controls.py','tests/fixtures/bounded-turn-synthetic.json',
  'docs/BOUNDED_PROVIDER_CUSTODY_V1.md',
  'docs/DIRECT_API_OPENROUTER.md','docs/PROVIDER_PRELAUNCH_CLOSURE_V1.md'];
const mapping=Object.fromEntries(plain.map(path=>[path,path]));
for(const name of ['.gitignore','pyproject.toml','README.md','AGENTS.md','NOTICE','LICENSE'])
  mapping[name]='packaging/runtime/'+name;
mapping['tools/export-runtime.mjs']='scripts/export-runtime.mjs';
const files={};
// Read and validate every object before creating any output.
for(const [path,canonical_path] of Object.entries(mapping).sort(([a],[b])=>a.localeCompare(b,'en'))){
  const entry=git('ls-tree',revision,'--',canonical_path).toString();
  if(!/^100644 blob /.test(entry))throw Error(`Expected regular tracked source: ${canonical_path}`);
  const bytes=git('show',revision+':'+canonical_path);
  files[path]={canonical_path,bytes,sha256:createHash('sha256').update(bytes).digest('hex')};
}
mkdirSync(destination,{recursive:true});
for(const [path,item] of Object.entries(files)){
  mkdirSync(dirname(resolve(destination,path)),{recursive:true});
  writeFileSync(resolve(destination,path),item.bytes,{mode:0o644,flag:'wx'});
}
const manifest={schema:'switchyard.runtime-source-export/v1',canonical_source:'Switchyard',
  canonical_revision:revision,export_procedure:'tools/export-runtime.mjs',
  authored_material_license:'Apache-2.0',third_party_notices_retained:true,
  files:Object.fromEntries(Object.entries(files).map(([path,item])=>[path,
    {canonical_path:item.canonical_path,bytes:item.bytes.length,sha256:item.sha256}]))};
writeFileSync(destination+'/SOURCE-PROVENANCE.json',JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({destination,canonical_revision:revision,exported_files:Object.keys(files).length+1}));
