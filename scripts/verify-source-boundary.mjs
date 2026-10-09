// Publish the licensed export and new Community sources only.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const root = path.resolve(import.meta.dirname, '..');
const vendor = path.join(root, 'Packages/VaultageOpenCore');
const manifest = JSON.parse(fs.readFileSync(path.join(vendor, 'EXPORT-MANIFEST.json'), 'utf8'));
const approved = new Set(manifest.files.map(entry => entry.path));
approved.add('EXPORT-MANIFEST.json'); approved.add(manifest.hashFile);
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
for (const entry of manifest.files) {
 if (path.isAbsolute(entry.path) || entry.path.split('/').includes('..')) throw Error('Invalid vendor path');
 if (hash(path.join(vendor, entry.path)) !== entry.sha256) throw Error(`Licensed vendor bytes changed: ${entry.path}`);
}
function walk(base, relative='') {
 for (const entry of fs.readdirSync(path.join(base,relative),{withFileTypes:true})) {
  if (['.git','.build','.swiftpm'].includes(entry.name)) continue;
  const file=path.join(relative,entry.name);
  if(entry.isSymbolicLink()) throw Error(`Symlink in source tree: ${file}`);
  if(entry.isDirectory()) walk(base,file);
  else {
   if(/\.(?:p8|p12|pem|provisionprofile|dmg|zip|db|vault)$/.test(file) || /(^|\/)\.env(?:\.|$)/.test(file)) throw Error(`Private/artifact file in source tree: ${file}`);
   if(base===vendor && !approved.has(file)) throw Error(`Unallowlisted vendor file: ${file}`);
   const text=fs.readFileSync(path.join(base,file),'utf8');
   // The licensed parser includes PEM header literals. A complete PEM with an
   // encoded body is credential material; a parser's header string is not.
   const privatePEM = /-----BEGIN ((?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----[\r\n]+[A-Za-z0-9+/=\r\n]{32,}-----END \1-----/;
   if(privatePEM.test(text) || /\b(?:sk_live|sk_test|ghp)_[A-Za-z0-9]{16,}/.test(text)) throw Error(`Credential material in source file: ${file}`);
   if(base===root && file.startsWith('Sources/') && /\b(?:VaultageProviders|ServiceCatalog|WorkspaceProjections|BrokerServiceComposition|XPCBrokerClient|DeviceAccountClient|Clerk|Stripe)\b/.test(text)) throw Error(`Private/service integration in Community runtime: ${file}`);
  }
 }
}
walk(vendor);
walk(root);
console.log(`Source boundary passed: ${manifest.files.length} licensed vendor files match; no private provider, account/billing implementation, signing credential or artifact in Community sources.`);
