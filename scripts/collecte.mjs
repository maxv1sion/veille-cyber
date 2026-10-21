// Veille cyber - collecte automatique (GitHub Actions, Node 20+, aucune dépendance)
// Récupère CERT-FR, CERT Santé, CISA KEV, EPSS et des flux d'actualité,
// fusionne dans data/registre.json, purge selon la conservation et produit la synthèse hebdo.
//
// Mode test hors ligne : VEILLE_FIXTURES=<dossier> lit les réponses dans des fichiers
// (nom = URL avec les caractères non alphanumériques remplacés par "_").

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { regrouper, signauxPresse, RE_SECURITE, GRANDS_NOMS, jetons } from './sujets.mjs';

const RACINE = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = join(RACINE, 'data');
const FIXTURES = process.env.VEILLE_FIXTURES || '';
const MAINTENANT = process.env.VEILLE_DATE ? new Date(process.env.VEILLE_DATE) : new Date();
const UA = 'veille-cyber (GitHub Actions; usage non commercial)';

const JOUR = 86400000;
const iso = (d) => new Date(d).toISOString().slice(0, 10);
const ilYa = (jours) => iso(MAINTENANT.getTime() - jours * JOUR);
const pause = (ms) => (FIXTURES ? Promise.resolve() : new Promise((r) => setTimeout(r, ms)));

const lireJson = async (chemin, defaut) => {
  try { return JSON.parse(await readFile(chemin, 'utf8')); } catch { return defaut; }
};
const ecrireJson = async (chemin, objet, compact = false) => {
  await mkdir(dirname(chemin), { recursive: true });
  await writeFile(chemin, JSON.stringify(objet, null, compact ? 0 : 2) + '\n');
};

// ---------- Réseau ----------
async function telecharger(url, { json = false } = {}) {
  if (FIXTURES) {
    let f = join(FIXTURES, url.replace(/[^a-z0-9]/gi, '_'));
    if (!existsSync(f)) f = join(FIXTURES, url.split('?')[0].replace(/[^a-z0-9]/gi, '_'));
    if (!existsSync(f)) throw new Error(`fixture absente : ${f}`);
    const txt = await readFile(f, 'utf8');
    return json ? JSON.parse(txt) : txt;
  }
  let derniere;
  for (let essai = 1; essai <= 3; essai++) {
    try {
      const rep = await fetch(url, {
        headers: { 'User-Agent': UA, Accept: json ? 'application/json' : '*/*' },
        signal: AbortSignal.timeout(45000),
      });
      if (!rep.ok) throw new Error(`HTTP ${rep.status}`);
      return json ? await rep.json() : await rep.text();
    } catch (e) {
      derniere = e;
      await pause(2000 * essai);
    }
  }
  throw new Error(`${url} : ${derniere?.message || derniere}`);
}

// ---------- Outils texte ----------
const ENTITES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: '’', lsquo: '‘', laquo: '«', raquo: '»', hellip: '…', eacute: 'é', egrave: 'è', agrave: 'à', ccedil: 'ç' };
function decoder(s = '') {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&([a-z]+);/gi, (m, n) => ENTITES[n.toLowerCase()] ?? m);
}
const sansHtml = (s = '') => decoder(decoder(s)).replace(/<\/?(strong|em|b|i|u|a|span|code|abbr)(\s[^>]*)?>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').replace(/\s+([.,)])/g, '$1').trim();
const couper = (s, n) => (s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s);
const extraireCves = (s = '') => [...new Set((s.match(/CVE-\d{4}-\d{4,}/gi) || []).map((c) => c.toUpperCase()))];
const dateSure = (s) => { const d = new Date(s); return isNaN(d) ? null : iso(d); };
const sansMarkdown = (s = '') => s.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/[*_`#>]/g, '').replace(/\s+/g, ' ').trim();

// Analyse RSS 2.0 et Atom suffisante pour les flux utilisés
function analyserFlux(xml) {
  const blocs = xml.match(/<item[\s>][\s\S]*?<\/item>/g) || xml.match(/<entry[\s>][\s\S]*?<\/entry>/g) || [];
  const champ = (b, nom) => { const m = b.match(new RegExp(`<${nom}(?:\\s[^>]*)?>([\\s\\S]*?)</${nom}>`, 'i')); return m ? decoder(m[1]).trim() : ''; };
  return blocs.map((b) => {
    let lien = champ(b, 'link');
    if (!lien) { const m = b.match(/<link[^>]*href="([^"]+)"/i); lien = m ? m[1] : ''; }
    return {
      titre: sansHtml(champ(b, 'title')),
      lien: lien.trim(),
      date: dateSure(champ(b, 'pubDate') || champ(b, 'published') || champ(b, 'updated') || champ(b, 'dc:date')),
      description: champ(b, 'description') || champ(b, 'summary') || champ(b, 'content'),
      guid: champ(b, 'guid') || champ(b, 'id'),
    };
  });
}

// ---------- Éditeurs suivis ----------
function preparerEditeurs(conf) {
  return (conf.editeurs || []).map((e) => ({
    nom: e.nom,
    regex: e.motsCles.map((k) => new RegExp(`(^|[^a-z0-9])${k.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^a-z0-9])`, 'i')),
  }));
}
function editeursSuivis(suivis, ...textes) {
  const t = textes.flat().filter(Boolean).join(' | ');
  return suivis.filter((e) => e.regex.some((r) => r.test(t))).map((e) => e.nom);
}

// ---------- Collecteurs ----------
const etat = {};
const noter = (source, ok, detail) => { etat[source] = { ok, detail, le: MAINTENANT.toISOString() }; };

async function collecterCertFr(conf, existants) {
  const sortie = [];
  const base = conf.base.replace(/\/$/, '');
  const limite = ilYa(conf.fenetreDetailJours);
  let budget = conf.detailsMaxParPassage;

  for (const [type, chemin, libelle] of [['alerte', 'alerte', 'alertes'], ['avis', 'avis', 'avis']]) {
    try {
      const liste = await telecharger(`${base}/${chemin}/json/`, { json: true });
      const candidats = liste
        .filter((x) => x.reference && (x.last_revision_date || '').slice(0, 10) >= limite)
        .sort((a, b) => (b.last_revision_date || '').localeCompare(a.last_revision_date || ''));
      let detailles = 0;
      for (const x of candidats) {
        const id = `certfr:${x.reference}`;
        const maj = (x.last_revision_date || '').slice(0, 10);
        const connu = existants.get(id);
        if (connu && connu.maj === maj && connu._detail) continue;
        if (budget <= 0) break;
        budget--;
        try {
          const d = await telecharger(`${base}/${chemin}/${x.reference}/json/`, { json: true });
          await pause(300);
          detailles++;
          const revs = (d.revisions || []).map((r) => (r.revision_date || '').slice(0, 10)).filter(Boolean).sort();
          const systemes = d.affected_systems || [];
          const editeurs = [...new Set(systemes.map((s) => s.product?.vendor?.name).filter((n) => n && n !== 'N/A'))];
          const produits = [...new Set(systemes.map((s) => s.product?.name).filter((n) => n && n !== 'N/A'))];
          sortie.push({
            id, source: 'CERT-FR', type,
            reference: x.reference,
            titre: d.title || x.title,
            resume: couper(sansMarkdown(d.summary || ''), 400),
            lien: `${base}/${chemin}/${x.reference}/`,
            date: revs[0] || maj,
            maj,
            editeurs, produits,
            cves: (d.cves || []).map((c) => c.name).filter(Boolean),
            risques: (d.risks || []).map((r) => r.description).filter(Boolean),
            cloturee: d.closed_at || null,
            scada: !!x.scada,
            _detail: true,
          });
        } catch (e) {
          console.warn(`CERT-FR détail ${x.reference} : ${e.message}`);
        }
      }
      noter(`CERT-FR ${libelle}`, true, `${candidats.length} récents, ${detailles} lus en détail`);
    } catch (e) {
      noter(`CERT-FR ${libelle}`, false, e.message);
    }
  }

  for (const f of conf.flux) {
    try {
      const items = analyserFlux(await telecharger(f.url));
      for (const it of items) {
        const ref = (it.lien.match(/(CERTFR-\d{4}-[A-Z]{3}-\d+)/) || [])[1] || it.guid || it.lien;
        sortie.push({
          id: `certfr:${ref}`, source: 'CERT-FR', type: f.type, reference: ref,
          titre: it.titre, resume: couper(sansHtml(it.description), 400), lien: it.lien,
          date: it.date, maj: it.date, editeurs: [], produits: [], cves: extraireCves(it.titre + ' ' + it.description), risques: [],
        });
      }
      noter(`CERT-FR ${f.type}`, true, `${items.length} éléments`);
    } catch (e) {
      noter(`CERT-FR ${f.type}`, false, e.message);
    }
  }
  return sortie;
}

async function collecterCertSante(conf) {
  try {
    const items = analyserFlux(await telecharger(conf.url));
    noter('CERT Santé', true, `${items.length} éléments`);
    return items.map((it) => {
      const titrePropre = it.titre.replace(/\s*\|\s*modifié le.*$/i, '');
      const editeur = titrePropre.split(' - ')[0].trim();
      const majM = it.titre.match(/modifié le (\d{2})-(\d{2})-(\d{4})/i);
      return {
        id: `certsante:${it.guid || it.lien}`, source: 'CERT Santé', type: 'avis',
        titre: titrePropre, resume: couper(sansHtml(it.description), 400), lien: it.lien,
        date: it.date, maj: majM ? `${majM[3]}-${majM[2]}-${majM[1]}` : it.date,
        editeurs: editeur ? [editeur] : [], produits: [], cves: extraireCves(it.titre), risques: [],
      };
    });
  } catch (e) {
    noter('CERT Santé', false, e.message);
    return [];
  }
}

async function collecterKev(conf, retentionJours) {
  try {
    const doc = await telecharger(conf.url, { json: true });
    const vulns = doc.vulnerabilities || [];
    const tous = new Map(vulns.map((v) => [v.cveID, v]));
    const limite = ilYa(retentionJours);
    const items = vulns.filter((v) => (v.dateAdded || '') >= limite).map((v) => ({
      id: `kev:${v.cveID}`, source: 'CISA KEV', type: 'kev', reference: v.cveID,
      titre: v.vulnerabilityName || v.cveID,
      resume: couper(`${v.shortDescription || ''} Action requise : ${v.requiredAction || ''}`.trim(), 500),
      lien: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      date: v.dateAdded, maj: v.dateAdded,
      editeurs: v.vendorProject ? [v.vendorProject] : [], produits: v.product ? [v.product] : [],
      cves: [v.cveID], risques: [],
      rancongiciel: (v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
      echeance: v.dueDate || null,
    }));
    noter('CISA KEV', true, `catalogue ${doc.catalogVersion || '?'} : ${vulns.length} entrées, ${items.length} dans la période`);
    return { items, tous };
  } catch (e) {
    noter('CISA KEV', false, e.message);
    return { items: [], tous: null };
  }
}

async function collecterActualites(sources) {
  const sortie = [];
  for (const s of sources.filter((x) => x.actif !== false)) {
    try {
      const items = analyserFlux(await telecharger(s.url));
      let gardes = 0;
      for (const it of items) {
        if (!it.lien || !it.titre) continue;
        if (s.filtreSecurite && !RE_SECURITE.test(it.titre)) continue;
        gardes++;
        sortie.push({
          id: `actu:${it.lien.replace(/[?#].*$/, '')}`, source: s.nom, type: 'actu',
          titre: it.titre, resume: couper(sansHtml(it.description), 280), lien: it.lien,
          date: it.date || iso(MAINTENANT), maj: it.date || iso(MAINTENANT),
          editeurs: [], produits: [], cves: extraireCves(it.titre + ' ' + it.description), risques: [],
        });
      }
      noter(s.nom, true, s.filtreSecurite ? `${gardes} articles cyber sur ${items.length}` : `${items.length} éléments`);
    } catch (e) {
      noter(s.nom, false, e.message);
    }
  }
  return sortie;
}

async function enrichirEpss(conf, items) {
  const cache = await lireJson(join(DATA, 'epss.json'), {});
  const limite = ilYa(conf.fenetreJours);
  const aujourdhui = iso(MAINTENANT);
  const aRafraichir = [...new Set(items.filter((i) => (i.date || '') >= limite).flatMap((i) => i.cves))]
    .filter((c) => !cache[c] || cache[c].le !== aujourdhui)
    .slice(0, conf.cveMaxParPassage);
  let lus = 0;
  try {
    for (let i = 0; i < aRafraichir.length;) {
      const lot = [];
      let longueur = 0;
      while (i < aRafraichir.length && longueur + aRafraichir[i].length + 1 < 1900) { lot.push(aRafraichir[i]); longueur += aRafraichir[i].length + 1; i++; }
      const rep = await telecharger(`${conf.url}?cve=${lot.join(',')}&limit=${lot.length}`, { json: true });
      for (const c of lot) cache[c] = { ...(cache[c] || {}), le: aujourdhui };
      for (const d of rep.data || []) cache[d.cve] = { epss: +d.epss, pct: +d.percentile, le: aujourdhui };
      lus += lot.length;
      await pause(500);
    }
    noter('EPSS', true, `${lus} CVE mises à jour`);
  } catch (e) {
    noter('EPSS', false, e.message);
  }
  // purge du cache : CVE qui ne sont plus dans le registre
  const utiles = new Set(items.flatMap((i) => i.cves));
  for (const c of Object.keys(cache)) if (!utiles.has(c)) delete cache[c];
  await ecrireJson(join(DATA, 'epss.json'), cache, true);
  return cache;
}

// ---------- Priorisation ----------
const RE_RCE = /exécution de code arbitraire à distance|execution de code arbitraire a distance|remote code execution/i;
function prioriser(it, kevSet, epss) {
  it.kev = it.type === 'kev' || it.cves.some((c) => kevSet.has(c));
  it.cvesKev = it.cves.filter((c) => kevSet.has(c));
  let max = 0, cveMax = null;
  for (const c of it.cves) { const e = epss[c]?.epss; if (e != null && e > max) { max = e; cveMax = c; } }
  it.epssMax = cveMax ? Math.round(max * 10000) / 10000 : null;
  it.epssCve = cveMax;
  it.rce = it.risques.some((r) => RE_RCE.test(r)) || RE_RCE.test(it.titre);

  if (it.type === 'actu') it.priorite = it.kev || it.signaux?.length ? 'haute' : 'info';
  else if (['cti', 'actualite', 'durcissement'].includes(it.type)) it.priorite = it.kev ? 'haute' : 'info';
  else if ((it.type === 'alerte' && !it.cloturee) || it.kev || max >= 0.5) it.priorite = 'critique';
  else if (it.type === 'alerte' || it.rce || max >= 0.1) it.priorite = 'haute';
  else it.priorite = 'moyenne';
  return it;
}

// ---------- Synthèse hebdomadaire ----------
function semaineIso(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const jour = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - jour);
  const debutAnnee = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const num = Math.ceil(((t - debutAnnee) / JOUR + 1) / 7);
  return `${t.getUTCFullYear()}-S${String(num).padStart(2, '0')}`;
}
function bornesSemainePrecedente() {
  const d = new Date(Date.UTC(MAINTENANT.getUTCFullYear(), MAINTENANT.getUTCMonth(), MAINTENANT.getUTCDate()));
  const jour = d.getUTCDay() || 7;
  const lundi = new Date(d.getTime() - (jour - 1 + 7) * JOUR);
  const dimanche = new Date(lundi.getTime() + 6 * JOUR);
  return { debut: iso(lundi), fin: iso(dimanche), code: semaineIso(lundi) };
}
const RANG = { critique: 0, haute: 1, moyenne: 2, info: 3 };
const allege = (i) => ({ id: i.id, source: i.source, type: i.type, reference: i.reference, titre: i.titre, resume: i.resume, lien: i.lien, date: i.date, editeurs: i.editeurs, suivis: i.suivis, cves: i.cves.slice(0, 12), nbCves: i.cves.length, kev: i.kev, cvesKev: i.cvesKev, epssMax: i.epssMax, epssCve: i.epssCve, rce: i.rce, priorite: i.priorite, cloturee: i.cloturee || null, rancongiciel: i.rancongiciel || false, signaux: i.signaux, relais: i.relais, presse: i.presse, officiel: i.officiel || null, officielInfo: i.officielInfo || null, principal: i.principal, aussi: i.aussi, doublonDe: i.doublonDe || null });

async function produireHebdo(items) {
  const { debut, fin, code } = bornesSemainePrecedente();
  const chemin = join(DATA, 'hebdo', `${code}.json`);
  const index = await lireJson(join(DATA, 'hebdo', 'index.json'), { semaines: [] });
  if (existsSync(chemin) && !process.env.VEILLE_FORCER_HEBDO) return false;

  const sem = items.filter((i) => i.date >= debut && i.date <= fin);
  const tri = (a, b) => RANG[a.priorite] - RANG[b.priorite] || (b.suivis.length > 0) - (a.suivis.length > 0) || (b.epssMax || 0) - (a.epssMax || 0) || b.date.localeCompare(a.date);
  const vulns = sem.filter((i) => ['alerte', 'avis', 'kev'].includes(i.type) && !i.doublonDe);
  const hebdo = {
    semaine: code, debut, fin, genere: MAINTENANT.toISOString(),
    chiffres: {
      alertes: sem.filter((i) => i.type === 'alerte').length,
      avisCertFr: sem.filter((i) => i.type === 'avis' && i.source === 'CERT-FR').length,
      avisCertSante: sem.filter((i) => i.type === 'avis' && i.source === 'CERT Santé' && !i.doublonDe).length,
      kevAjoutees: sem.filter((i) => i.type === 'kev').length,
      critiques: vulns.filter((i) => i.priorite === 'critique').length,
      signauxPresse: sem.filter((i) => i.type === 'actu' && i.principal && i.signaux?.length && !i.officiel).length,
      surParcSuivi: vulns.filter((i) => i.suivis.length).length,
    },
    alertes: sem.filter((i) => i.type === 'alerte').sort(tri).map(allege),
    kev: sem.filter((i) => i.type === 'kev').sort(tri).map(allege),
    parcSuivi: vulns.filter((i) => i.suivis.length && i.type === 'avis').sort(tri).slice(0, 25).map(allege),
    autresCritiques: vulns.filter((i) => !i.suivis.length && i.priorite === 'critique' && i.type === 'avis').sort(tri).slice(0, 15).map(allege),
    menaces: sem.filter((i) => ['cti', 'actualite', 'durcissement'].includes(i.type)).sort(tri).map(allege),
    signauxPresse: sem.filter((i) => i.type === 'actu' && i.principal && i.signaux?.length && !i.officiel).sort(tri).slice(0, 15).map(allege),
  };
  await ecrireJson(chemin, hebdo);
  index.semaines = [...new Set([code, ...index.semaines])].sort().reverse();
  await ecrireJson(join(DATA, 'hebdo', 'index.json'), index);
  return true;
}

// ---------- Programme principal ----------
async function principal() {
  const sources = await lireJson(join(RACINE, 'config', 'sources.json'), null);
  if (!sources) throw new Error('config/sources.json illisible');
  const confEditeurs = await lireJson(join(RACINE, 'config', 'editeurs.json'), { editeurs: [] });
  const suivis = preparerEditeurs(confEditeurs);
  const suivisMotsCles = (confEditeurs.editeurs || []).flatMap((e) => e.motsCles);
  const registre = await lireJson(join(DATA, 'registre.json'), { items: [] });
  const existants = new Map(registre.items.map((i) => [i.id, i]));

  const nouveaux = [];
  if (sources.certfr?.actif) nouveaux.push(...(await collecterCertFr(sources.certfr, existants)));
  if (sources.certsante?.actif) nouveaux.push(...(await collecterCertSante(sources.certsante)));
  let kevSet = new Set(registre.kevCatalogue || []);
  if (sources.kev?.actif) {
    const { items, tous } = await collecterKev(sources.kev, sources.conservation.failleExploiteesJours || 90);
    nouveaux.push(...items);
    if (tous) kevSet = new Set(tous.keys());
  }
  nouveaux.push(...(await collecterActualites(sources.actualites || [])));

  // Fusion : un nouvel élément remplace l'ancien, sauf détail CERT-FR plus riche déjà connu
  let ajouts = 0;
  for (const n of nouveaux) {
    if (!n.date) continue;
    const ancien = existants.get(n.id);
    if (!ancien) ajouts++;
    if (ancien && ancien._detail && !n._detail) continue;
    existants.set(n.id, { ...ancien, ...n, vuLe: ancien?.vuLe || iso(MAINTENANT) });
  }

  // Conservation
  const limVuln = ilYa(sources.conservation.vulnerabilitesJours);
  const limActu = ilYa(sources.conservation.actualitesJours);
  const limKev = ilYa(sources.conservation.failleExploiteesJours || 90);
  let items = [...existants.values()].filter((i) => i.date >= (i.type === 'actu' ? limActu : i.type === 'kev' ? limKev : limVuln));

  const epss = sources.epss?.actif ? await enrichirEpss(sources.epss, items) : {};
  const courants = new Set((await readFile(join(RACINE, 'config', 'mots-courants.txt'), 'utf8').catch(() => '')).split('\n').filter((l) => l && !l.startsWith('#')));
  for (const i of items) if (i.type === 'actu') i.signaux = signauxPresse(i.titre, i.resume);
  const generiques = new Set([...GRANDS_NOMS, ...suivisMotsCles.flatMap((k) => jetons(k))]);
  regrouper(items, { courants, generiques });

  // Doublons entre sources officielles : un avis CERT Santé dont toutes les CVE figurent
  // dans un avis ou une alerte CERT-FR proche est replié sous celui-ci
  const certfr = items.filter((i) => i.source === 'CERT-FR' && ['avis', 'alerte'].includes(i.type) && i.cves.length);
  for (const i of certfr) delete i.aussi;
  for (const i of items) {
    delete i.doublonDe;
    if (i.source !== 'CERT Santé' || !i.cves.length) continue;
    const cible = certfr
      .filter((c) => i.cves.every((v) => c.cves.includes(v)) && Math.abs(new Date(c.date) - new Date(i.date)) <= 30 * JOUR)
      .sort((a, b) => (a.type === 'alerte' ? -1 : 0) - (b.type === 'alerte' ? -1 : 0) || a.date.localeCompare(b.date))[0];
    if (!cible) continue;
    i.doublonDe = { source: cible.source, titre: cible.titre, lien: cible.lien, reference: cible.reference };
    (cible.aussi ||= []).push({ source: i.source, titre: i.titre, lien: i.lien });
  }
  items = items.map((i) => {
    i.suivis = editeursSuivis(suivis, i.editeurs, i.produits, i.titre, i.type === 'actu' ? '' : i.resume.slice(0, 200));
    return prioriser(i, kevSet, epss);
  });
  items.sort((a, b) => b.date.localeCompare(a.date) || RANG[a.priorite] - RANG[b.priorite]);

  await ecrireJson(join(DATA, 'registre.json'), {
    genere: MAINTENANT.toISOString(),
    nbElements: items.length,
    kevCatalogue: [...kevSet].sort(),
    items,
  }, true);

  const hebdo = await produireHebdo(items);
  await ecrireJson(join(DATA, 'etat.json'), { derniereCollecte: MAINTENANT.toISOString(), ajouts, nbElements: items.length, sources: etat });

  console.log(`Collecte terminée : ${ajouts} nouveaux, ${items.length} au registre${hebdo ? ', synthèse hebdo produite' : ''}.`);
  for (const [s, e] of Object.entries(etat)) console.log(`  ${e.ok ? 'OK ' : 'KO '} ${s} : ${e.detail}`);
  if (Object.values(etat).every((e) => !e.ok)) process.exitCode = 1;
}

principal().catch((e) => { console.error(e); process.exit(1); });
