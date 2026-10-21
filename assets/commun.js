// Fonctions partagées par les pages de la veille cyber
const Veille = (() => {
  const echapper = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const lienSur = (u) => (/^https?:\/\//i.test(u || '') ? u : '#');

  const MOIS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
  const JOURS = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
  const dateLongue = (d) => { const x = new Date(d + 'T12:00:00'); return `${JOURS[x.getDay()]} ${x.getDate()} ${MOIS[x.getMonth()]} ${x.getFullYear()}`; };
  const dateCourte = (d) => { const x = new Date(d + 'T12:00:00'); return `${x.getDate()} ${MOIS[x.getMonth()]}${x.getFullYear() !== new Date().getFullYear() ? ' ' + x.getFullYear() : ''}`; };
  const dateHeure = (iso) => new Date(iso).toLocaleString('fr-FR', { dateStyle: 'long', timeStyle: 'short' });

  const TYPES = {
    alerte: 'Alerte CERT-FR', avis: 'Avis de sécurité', kev: 'Exploitée (CISA KEV)',
    cti: 'Rapport sur la menace', actualite: "Bulletin d'actualité", durcissement: 'Recommandation', actu: 'Presse',
  };
  const PRIORITES = { critique: 'Critique', haute: 'Haute', moyenne: 'Moyenne', info: 'Information' };
  const pct = (x) => (x == null ? '' : `${(x * 100).toLocaleString('fr-FR', { maximumFractionDigits: x < 0.01 ? 2 : 0 })} %`);

  function raisons(i) {
    const r = [];
    if (i.type === 'alerte' && !i.cloturee) r.push('alerte CERT-FR en cours');
    if (i.type === 'alerte' && i.cloturee) r.push(`alerte clôturée le ${dateCourte(i.cloturee)}`);
    if (i.type === 'kev') r.push('exploitation active confirmée par la CISA');
    else if (i.kev) r.push(`exploitée activement (${i.cvesKev.join(', ')})`);
    if (i.rancongiciel) r.push('utilisée par des rançongiciels');
    if (i.epssMax >= 0.1) r.push(`probabilité d'exploitation ${pct(i.epssMax)} sous 30 jours`);
    if (i.rce) r.push('exécution de code à distance');
    if (i.echeance) r.push(`correctif exigé par la CISA avant le ${dateCourte(i.echeance)}`);
    if (i.type === 'actu') {
      for (const sg of i.signaux || []) if (!(sg === 'exécution de code à distance' && i.rce)) r.push(sg);
      const nb = new Set([i.source, ...(i.relais || []).map((x) => x.source)]).size;
      if (r.length && nb > 1) r.push(`relayé par ${nb} médias`);
    }
    return r;
  }

  function element(i, { avecDate = false, nbCvesMax = 8 } = {}) {
    const cves = i.cves || [];
    const exploitees = new Set(i.cvesKev || []);
    const cvesAff = [...cves].sort((a, b) => exploitees.has(b) - exploitees.has(a)).slice(0, nbCvesMax);
    const reste = (i.nbCves || cves.length) - cvesAff.length;
    const marques = [
      ...(i.suivis || []).map((s) => `<span class="marque parc" title="Éditeur de ton parc">${echapper(s)}</span>`),
      i.kev ? '<span class="marque kev">Exploitée</span>' : '',
      ...(i.editeurs || []).filter((e) => !(i.suivis || []).some((s) => s.toLowerCase().includes(e.toLowerCase()))).slice(0, 4).map((e) => `<span class="marque">${echapper(e)}</span>`),
      ...cvesAff.map((c) => `<a class="marque cve${exploitees.has(c) ? ' exploitee' : ''}" href="https://nvd.nist.gov/vuln/detail/${echapper(c)}" target="_blank" rel="noopener" title="${exploitees.has(c) ? 'Exploitée activement' : 'Voir la fiche NVD'}">${echapper(c)}</a>`),
      reste > 0 ? `<span class="marque">+ ${reste} CVE</span>` : '',
    ].join('');
    const r = raisons(i);
    const lienArticle = (x) => `<a href="${echapper(lienSur(x.lien))}" target="_blank" rel="noopener" title="${echapper(x.titre)}">${echapper(x.source)}</a>`;
    const parSource = (liste) => [...new Map(liste.map((x) => [x.source, x])).values()];
    const liens = [
      i.relais?.length ? `Aussi relayé par ${parSource(i.relais.filter((x) => x.source !== i.source)).map(lienArticle).join(', ') || 'le même média'}` : '',
      i.officielInfo ? `Avis officiel : <a href="${echapper(lienSur(i.officielInfo.lien))}" target="_blank" rel="noopener">${echapper(i.officielInfo.source)}, ${echapper(i.officielInfo.titre)}</a>` : '',
      i.aussi?.length ? `Aussi publié par ${parSource(i.aussi).map(lienArticle).join(', ')}` : '',
      i.doublonDe ? `Également couvert par <a href="${echapper(lienSur(i.doublonDe.lien))}" target="_blank" rel="noopener">${echapper(i.doublonDe.source)} ${echapper(i.doublonDe.reference || '')}</a>` : '',
      i.presse?.length ? `Dans la presse : ${parSource(i.presse).map(lienArticle).join(', ')}` : '',
    ].filter(Boolean);
    return `<li class="el p-${echapper(i.priorite)}">
      <h3><a href="${echapper(lienSur(i.lien))}" target="_blank" rel="noopener">${echapper(i.titre)}</a></h3>
      <div class="meta">
        <span class="prio">${PRIORITES[i.priorite] || ''}</span>
        <span>${echapper(TYPES[i.type] || i.type)}</span>
        <span>${/^CERTFR-/.test(i.reference || '') ? echapper(i.reference) : echapper(i.source)}</span>
        ${avecDate ? `<span>${dateCourte(i.date)}</span>` : ''}
        ${i.epssMax != null && i.epssMax >= 0.01 ? `<span title="Probabilité d'exploitation sous 30 jours (FIRST EPSS) pour ${echapper(i.epssCve)}">EPSS ${pct(i.epssMax)}</span>` : ''}
      </div>
      ${r.length ? `<p><strong>Pourquoi c'est prioritaire :</strong> ${echapper(r.join(', '))}.</p>` : ''}
      ${i.resume ? `<p>${echapper(i.resume)}</p>` : ''}
      ${marques ? `<div class="marques">${marques}</div>` : ''}
      ${liens.length ? `<p class="liens">${liens.join('<br>')}</p>` : ''}
    </li>`;
  }

  async function charger(chemin) {
    const rep = await fetch(`${chemin}?t=${Date.now()}`);
    if (!rep.ok) throw new Error(`${chemin} : HTTP ${rep.status}`);
    return rep.json();
  }

  function etatSources(etat, cible) {
    if (!etat?.sources) return;
    cible.innerHTML = Object.entries(etat.sources).map(([nom, e]) =>
      `<li><span class="pastille${e.ok ? '' : ' ko'}"></span>${echapper(nom)}${e.ok ? '' : ' : indisponible au dernier passage'}</li>`).join('');
  }

  return { echapper, lienSur, dateLongue, dateCourte, dateHeure, TYPES, PRIORITES, raisons, element, charger, etatSources, pct };
})();
