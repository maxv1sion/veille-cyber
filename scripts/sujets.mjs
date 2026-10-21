// Signaux presse et regroupement des publications qui parlent du même sujet
// (entre médias, et rattachement à l'avis officiel quand il existe)

const sansAccents = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '');

// Mots trop génériques pour distinguer un sujet d'un autre
const MOTS_VIDES = new Set(`
le la les un une des du de d l au aux et ou en dans sur pour par avec sans sous vers chez ce cet cette ces son sa ses leur leurs
qui que quoi dont est sont ete etre a ont avoir fait faire plus moins tres tout tous toute toutes deux trois cinq dix cent mille millions milliers
nouveau nouvelle nouveaux nouvelles premier premiere apres avant depuis encore deja aussi alors comme mais donc car pas ne se sa
the a an of to in on for and or with by from at as is are was were be been has have had its it this that these those their
new two three four five ten more than over into via after before amid now still just how why what who will can could may
faille failles vulnerabilite vulnerabilites vulnerability vulnerabilities flaw flaws bug bugs critique critiques critical severe grave graves
securite security cyber cybersecurite cybersecurity attaque attaques attack attacks attaquants attackers hackers hacker pirates pirate piratage hacked hacking
exploit exploits exploite exploitee exploitees exploited exploiting exploitation actively activement active
patch patches patched unpatched correctif correctifs corrige corriger corrigee mise jour jours update updates fix fixes fixed release releases released
urgence urgent emergency alerte alertes alert alerts warns warning prevent avertit met garde
multiples multiple produits products versions version utilisateurs users clients customers entreprises companies
remote distance code execution rce zero day zeroday 0day cve cvss score
data donnees fuite leak leaks breach breaches vol stolen
malware malwares logiciel logiciels software ransomware rancongiciel campaign campagne campagnes group groupe groupes threat menace menaces actor actors
report rapport researchers chercheurs found decouvert discovered says selon via week semaine today aujourd hui
federal agencies agency order orders orders ban bans banned block blocks blocked removed purchase purchases
hijack hijacked hijacks backdoor backdoors backdoored deliver delivers spread spreads distribute install installs steal steals stealing
abuse abuses abused plant plants compromise compromised compromises site sites website websites server servers account accounts credential credentials
key keys tenant tenants fake target targets targeted targeting use used uses using linked link china chinese russia russian north korea korean iran iranian
state government gouvernement weekly recap threatsday popular secretly minute minutes hour hours crypto miner miners take takes run runs let lets get gets
ship ships issue issues trigger triggers coming tomorrow demain admin admins administrateurs warn reste remains offline online public poc proof concept
unauthenticated authenticated authentification path flaw lien plugin plugins extension extensions package packages
phishing hameconnage arnaque arnaques scam scams cert github gitlab npm pypi repository repositories depot cible ciblee ciblees cibles vise visee
espion espionnage spyware stealer infostealer loader shellcode trojan troyen botnet backdoor porte derobee dark web darkweb record records exposed expose
`.split(/\s+/).filter(Boolean));

const singulier = (m) => (m.length > 4 && m.endsWith('s') && !m.endsWith('ss') ? m.slice(0, -1) : m);
export function jetons(texte = '') {
  const t = sansAccents(texte.toLowerCase());
  const mots = [...t.split(/[^a-z0-9]+/), ...t.split(/[^a-z]+/)].map(singulier);
  return [...new Set(mots.filter((m) => m.length >= 3 && !MOTS_VIDES.has(m) && !MOTS_VIDES.has(m + 's') && !/^\d+$/.test(m)))];
}

// ---------- Signaux presse ----------
const SIGNAUX = [
  ['exploitation active', /exploit[ée]e?s? activement|activement exploit|exploitation active|actively exploited|exploited in (the wild|attacks)|under active exploitation|exploited as a zero.?day/i],
  ['zero-day', /z[ée]ro.?day|0.?day/i],
  ['exécution de code à distance', /ex[ée]cution de code (arbitraire )?[àa] distance|remote code execution|\bRCE\b/i],
  ["correctif d'urgence", /(mise [àa] jour|correctif|patch)s? d'urgence|emergency (patch|update|security update|fix)|out.of.band/i],
  ['faille non corrigée', /non corrig[ée]e?s?|sans correctif|unpatched|no patch/i],
  ['faille critique', /(faille|vuln[ée]rabilit[ée])s? critique|critical (flaw|vulnerabilit|bug|security|rce)|CVSS[^0-9]{0,12}(9(\.\d)?|10(\.0)?)\b/i],
];
const RE_RECAP = /weekly recap|threatsday|week in review|this week in|r[ée]cap(itulatif)? de la semaine|semaine en bref|newsletter|webinar|podcast/i;
export function signauxPresse(titre = '', resume = '') {
  if (RE_RECAP.test(titre)) return [];
  const t = `${titre} ${resume}`;
  return SIGNAUX.filter(([, re]) => re.test(t)).map(([nom]) => nom);
}

export const RE_SECURITE = /cyber|s[ée]curit|faille|vuln[ée]rab|ran[çc]ongiciel|ransomware|pirat|hacker|malware|logiciel malveillant|phishing|hame[çc]onnage|fuite de donn|cyberattaque|\bCVE-|ANSSI|CERT|zero.?day|exploit|espionn|botnet|ddos|chiffrement|mot de passe|authentification|patch tuesday/i;

// ---------- Regroupement ----------
const JOUR = 86400000;
const ecartJours = (a, b) => Math.abs(new Date(a) - new Date(b)) / JOUR;
const FRANCAIS = new Set(['ZATAZ', 'Clubic', 'LeMagIT']);
const OFFICIELS = ['alerte', 'avis', 'kev'];
const RANG_OFFICIEL = (i) => (i.type === 'alerte' ? 0 : i.source === 'CERT-FR' ? 1 : i.source === 'CERT Santé' ? 2 : 3);

/**
 * Ajoute aux éléments :
 *  - presse : sujet (id du groupe), principal (bool), relais [{source, titre, lien}], officiel (id ou null)
 *  - officiels : presse [{source, titre, lien}] des articles rattachés
 */
export function regrouper(items, { courants = new Set(), seuil = 6, seuilOfficiel = 9, rare = 3, fenetrePresse = 3, fenetreOfficiel = 10 } = {}) {
  const presse = items.filter((i) => i.type === 'actu').sort((a, b) => a.date.localeCompare(b.date));
  const officiels = items.filter((i) => OFFICIELS.includes(i.type));

  for (const d of presse) d._jetons = jetons(d.titre);
  for (const d of officiels) d._jetons = jetons(`${d.titre} ${(d.produits || []).join(' ')} ${(d.editeurs || []).join(' ')} ${(d.resume || '').slice(0, 200)}`);
  const docs = [...presse, ...officiels];
  const df = new Map();
  for (const d of docs) for (const j of d._jetons) df.set(j, (df.get(j) || 0) + 1);
  const N = docs.length || 1;
  const poids = (j) => Math.log(N / (df.get(j) || 1));
  const memeCve = (a, b) => a.cves?.length && b.cves?.length && a.cves.some((c) => b.cves.includes(c));
  const communs = (a, b) => a._jetons.filter((j) => b._jetons.includes(j));
  const score = (a, b) => communs(a, b).reduce((s, j) => s + poids(j), 0);
  // Entre médias : même CVE, ou mots rares communs, ou un nom très rare (produit) en commun
  // Noms propres : mots absents de la liste des mots courants (produits, éditeurs, campagnes…)
  const dfPresse = new Map();
  for (const d of presse) for (const j of d._jetons) dfPresse.set(j, (dfPresse.get(j) || 0) + 1);
  const procheP = (a, b) => {
    if (memeCve(a, b)) return true;
    const noms = communs(a, b).filter((j) => !courants.has(j));
    return noms.some((j) => (dfPresse.get(j) || 0) <= rare) || noms.length >= 2 || (noms.length === 1 && score(a, b) >= seuil + 2);
  };
  const procheO = (p, o) => memeCve(p, o) || score(p, o) >= seuilOfficiel;

  // Regroupement autour d'un article de référence (pas de contagion en chaîne)
  const groupes = [];
  for (const p of presse) {
    const g = groupes.find((g) => ecartJours(g[0].date, p.date) <= fenetrePresse && (procheP(g[0], p) || g.filter((m) => procheP(m, p)).length >= 2));
    if (g) g.push(p); else groupes.push([p]);
  }

  for (const o of officiels) o.presse = [];
  for (const membres of groupes) {
    membres.sort((a, b) => (b.signaux?.length > 0) - (a.signaux?.length > 0) || FRANCAIS.has(b.source) - FRANCAIS.has(a.source) || a.date.localeCompare(b.date));
    const principal = membres[0];
    let meilleur = null, meilleurScore = 0;
    for (const o of officiels) {
      const candidats = membres.filter((m) => ecartJours(m.date, o.date) <= fenetreOfficiel && procheO(m, o));
      if (!candidats.length) continue;
      const s = Math.max(...candidats.map((m) => (memeCve(m, o) ? 1000 : score(m, o))));
      if (s > meilleurScore || (s === meilleurScore && RANG_OFFICIEL(o) < RANG_OFFICIEL(meilleur))) { meilleur = o; meilleurScore = s; }
    }
    const signaux = [...new Set(membres.flatMap((m) => m.signaux || []))];
    for (const m of membres) {
      m.sujet = principal.id;
      m.principal = m === principal;
      m.relais = membres.filter((x) => x !== m).map((x) => ({ source: x.source, titre: x.titre, lien: x.lien }));
      m.officiel = meilleur ? meilleur.id : null;
      m.officielInfo = meilleur ? { source: meilleur.source, titre: meilleur.titre, lien: meilleur.lien } : null;
      m.signaux = signaux;
    }
    if (meilleur) meilleur.presse.push(...membres.map((m) => ({ source: m.source, titre: m.titre, lien: m.lien })));
  }
  for (const d of docs) delete d._jetons;
  for (const o of officiels) if (!o.presse.length) delete o.presse;
  return groupes;
}
