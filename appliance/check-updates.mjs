import { readFile } from 'node:fs/promises';

const versionsText = await readFile(new URL('./versions.env', import.meta.url), 'utf8');
const versions = Object.fromEntries(versionsText.trim().split('\n').map(line => line.split('=', 2)));
const required = ['NODE_VERSION', 'NODE_ARCH', 'NODE_SHA256'];
for (const key of required) {
  if (!versions[key]) throw new Error(`Missing ${key} in appliance/versions.env.`);
}

const fetchText = async url => {
  const response = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Unable to fetch ${url}: HTTP ${response.status}`);
  return response.text();
};

const releases = JSON.parse(await fetchText('https://nodejs.org/dist/index.json'));
const latestLts = releases.find(release => release.lts && release.files.includes(`linux-${versions.NODE_ARCH}`));
if (!latestLts) throw new Error('Node release index does not contain a supported LTS Linux build.');

const archive = `node-${versions.NODE_VERSION}-linux-${versions.NODE_ARCH}.tar.xz`;
const checksums = await fetchText(`https://nodejs.org/dist/${versions.NODE_VERSION}/SHASUMS256.txt`);
const checksumLine = checksums.split('\n').find(line => line.endsWith(`  ${archive}`));
if (!checksumLine) throw new Error(`Node checksum manifest does not contain ${archive}.`);
const publishedChecksum = checksumLine.split(/\s+/, 1)[0];

const report = [
  '# Reiven appliance update check',
  '',
  `- Pinned Node: ${versions.NODE_VERSION}`,
  `- Latest Node LTS: ${latestLts.version} (${latestLts.lts})`,
  `- Pinned checksum matches upstream: ${publishedChecksum === versions.NODE_SHA256 ? 'yes' : 'no'}`,
  '- Ubuntu and Caddy packages: resolved from signed Noble updates/security repositories during each image build',
  '- Reiven application: built from the workflow commit',
].join('\n');

console.log(report);
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFile } = await import('node:fs/promises');
  await appendFile(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);
}

if (publishedChecksum !== versions.NODE_SHA256) {
  throw new Error('Pinned Node checksum does not match the upstream release manifest.');
}
if (latestLts.version !== versions.NODE_VERSION) {
  throw new Error(`Pinned Node ${versions.NODE_VERSION} is not the latest LTS (${latestLts.version}); review and update the runtime pin.`);
}
