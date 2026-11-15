import { build } from 'esbuild';
import JavaScriptObfuscator from 'javascript-obfuscator';
import { mkdirSync, readFileSync, writeFileSync, copyFileSync, readdirSync, mkdtempSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const root = resolve(dirname(fileURLToPath(import.meta.url)),'..');
const target = resolve(process.argv[2]);
mkdirSync(target,{recursive:true});
mkdirSync(join(root,'artifacts'),{recursive:true});
const staging = mkdtempSync(join(root,'artifacts','obfuscated-'));
const options = {
  target:'node', compact:true, identifierNamesGenerator:'hexadecimal', renameGlobals:false, renameProperties:false,
  stringArray:true, stringArrayEncoding:['base64'], stringArrayThreshold:1, splitStrings:true, splitStringsChunkLength:8,
  controlFlowFlattening:true, controlFlowFlatteningThreshold:0.3, deadCodeInjection:false,
  selfDefending:false, debugProtection:false, disableConsoleOutput:false, sourceMap:false,
  transformObjectKeys:false, unicodeEscapeSequence:false
};
for (const name of readdirSync(join(root,'desktop')).filter(n=>n.endsWith('.mjs'))) {
  const code=readFileSync(join(root,'desktop',name),'utf8');
  writeFileSync(join(staging,name),JavaScriptObfuscator.obfuscate(code,options).getObfuscatedCode());
}
// Resolve third-party code from the pinned root installation, not a new download.
for(const name of ['server','start','stop','tunnel','setup-discovery']) {
  await build({entryPoints:[join(staging,name+'.mjs')],outfile:join(target,name+'.mjs'),bundle:true,
    nodePaths:[join(root,'node_modules')],platform:'node',target:'node24',format:'esm',external:['node:*'],
    minifyIdentifiers:true,minifyWhitespace:true,legalComments:'eof',sourcemap:false});
}
const html=readFileSync(join(root,'desktop/owner.html'),'utf8').replace(/<script>([\s\S]*?)<\/script>/,(_,script)=>
  '<script>'+JavaScriptObfuscator.obfuscate(script,{...options,target:'browser',controlFlowFlattening:false}).getObfuscatedCode()+'</script>');
writeFileSync(join(target,'owner.html'),html);
copyFileSync(join(root,'desktop/package.json'),join(target,'package.json'));
const require=createRequire(import.meta.url);
const core=require.resolve('@hpke/core/package.json');
const dependencyRequire=createRequire(core);
const common=dependencyRequire.resolve('@hpke/common/package.json');
let notices='ENCPTD: AGPL-3.0-only. Corresponding source: https://github.com/eski11/encrypted\n\n';
for(const manifest of [core,common]) {
  const metadata=JSON.parse(readFileSync(manifest,'utf8'));
  notices+=`${metadata.name} ${metadata.version}\n${readFileSync(join(dirname(manifest),'LICENSE'),'utf8')}\n\n`;
}
writeFileSync(join(target,'ThirdPartyNotices.txt'),notices);
console.log('Built obfuscated Windows release with bundled pinned HPKE implementation and no source maps.');
