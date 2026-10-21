// Cas réels de regroupement (octobre 2026). Lancer avec : node --test tests/sujets.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { regrouper, signauxPresse, GRANDS_NOMS, jetons } from '../scripts/sujets.mjs';

const courants = new Set(readFileSync(new URL('../config/mots-courants.txt', import.meta.url), 'utf8').split('\n').filter((l) => l && !l.startsWith('#')));
const conf = JSON.parse(readFileSync(new URL('../config/editeurs.json', import.meta.url), 'utf8'));
const generiques = new Set([...GRANDS_NOMS, ...conf.editeurs.flatMap((e) => e.motsCles).flatMap((k) => jetons(k))]);

const A = [
  ['2026-10-20', 'BleepingComputer', 'PHP warns admins of two critical flaws, emergency patches coming tomorrow'],
  ['2026-10-21', 'The Hacker News', 'PHP2Shell: Two Unpatched Critical PHP RCE Flaws (CVSS 9.2) Trigger Emergency Security Alert'],
  ['2026-10-21', 'Clubic', 'Deux failles critiques menacent des millions de sites PHP, une mise à jour d’urgence arrive ce mercredi après-midi'],
  ['2026-10-21', 'ZATAZ', 'PHP2Shell : deux failles critiques menacent les serveurs web'],
  ['2026-10-21', 'LeMagIT', 'PHP : deux vulnérabilités critiques déjà exploitées en cours de correction'],
  ['2026-10-17', 'The Hacker News', 'Hackers Use Compromised ConnectWise Credential to Sign In to 173 Microsoft 365 Tenants'],
  ['2026-10-18', 'The Hacker News', 'ConnectWise Suspends Cloud Backup After Attackers Compromise Microsoft 365 Tenants'],
  ['2026-10-19', 'LeMagIT', 'Des pirates compromettent des environnements Microsoft 365 via ConnectWise'],
  ['2026-10-19', 'BleepingComputer', 'WordPress SEO plugin Rank Math compromised to backdoor websites'],
  ['2026-10-19', 'The Hacker News', 'Popular WordPress SEO Plugin Rank Math PRO Hijacked to Deliver Self-Restoring Backdoor'],
  ['2026-10-21', 'BleepingComputer', 'Stolen UpdraftCentral keys used to backdoor WordPress sites'],
  ['2026-10-21', 'The Hacker News', 'Attackers Abuse UpdraftCentral Keys to Plant Backdoors on WordPress Sites'],
  ['2026-10-20', 'BleepingComputer', 'DHS bans DeepSeek products across US federal civilian agencies'],
  ['2026-10-21', 'The Hacker News', 'U.S. Orders DeepSeek Removed From Federal Civilian Systems, Bans New Purchases'],
  ['2026-10-19', 'The Hacker News', 'OpenCode Console Breach May Have Exposed OpenAI, Anthropic, and Google API Keys'],
  ['2026-10-20', 'The Hacker News', 'Ex-OpenAI Engineer Detained in Spy Device Case as Saudi Royal Contacts Emerge'],
  ['2026-10-17', 'ZATAZ', 'Taxis et VTC : ce que vos données révèlent de vous'],
  ['2026-10-20', 'ZATAZ', 'Arnaque Netflix à 1 € : le cadeau qui piège vos données'],
];

function grouper() {
  const items = A.map(([date, source, titre], k) => ({ id: `a${k}`, type: 'actu', date, source, titre, resume: '', cves: [], signaux: signauxPresse(titre) }));
  regrouper(items, { courants, generiques });
  return (titre) => items.find((i) => i.titre.startsWith(titre)).sujet;
}

test('les 5 articles PHP forment un seul sujet', () => {
  const s = grouper();
  const sujets = new Set(['PHP warns', 'PHP2Shell: Two', 'Deux failles critiques', 'PHP2Shell : deux', 'PHP : deux'].map(s));
  assert.equal(sujets.size, 1);
});
test('ConnectWise regroupé malgré plusieurs articles', () => {
  const s = grouper();
  assert.equal(new Set(['Hackers Use Compromised ConnectWise', 'ConnectWise Suspends', 'Des pirates compromettent'].map(s)).size, 1);
});
test('deux histoires WordPress différentes restent séparées', () => {
  const s = grouper();
  assert.equal(s('WordPress SEO plugin Rank Math'), s('Popular WordPress SEO'));
  assert.equal(s('Stolen UpdraftCentral'), s('Attackers Abuse UpdraftCentral'));
  assert.notEqual(s('WordPress SEO plugin Rank Math'), s('Stolen UpdraftCentral'));
});
test('DeepSeek regroupé, OpenAI non', () => {
  const s = grouper();
  assert.equal(s('DHS bans DeepSeek'), s('U.S. Orders DeepSeek'));
  assert.notEqual(s('OpenCode Console'), s('Ex-OpenAI'));
});
test('pas de rapprochement sur des mots banals', () => {
  const s = grouper();
  assert.notEqual(s('Taxis et VTC'), s('Arnaque Netflix'));
});
test('signaux presse', () => {
  assert.ok(signauxPresse('PHP : deux vulnérabilités critiques déjà exploitées en cours de correction').includes('exploitation active'));
  assert.deepEqual(signauxPresse('⚡ Weekly Recap: 98 Zero-Days, Rogue AI Agents'), []);
});
