/**
 * HEARD-A1 rights-information and find-support content.
 *
 * Content lives in the repository (content/rights-guides/*.json,
 * content/support-resources.json) and is validated strictly at build/test time.
 * Every guide states its jurisdiction, primary sources and review status. Only a
 * guide with a recorded, current legal review may be presented as reviewed; all
 * other guides are labelled samples and are never presented as legal advice.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REVIEW_STATUSES = Object.freeze(['sample', 'draft', 'legally_reviewed']);
export const SOURCE_KINDS = Object.freeze(['constitution', 'statute', 'regulation', 'case', 'agency', 'secondary']);
export const RESOURCE_CATEGORIES = Object.freeze(['emergency', 'legal_help', 'records', 'complaints', 'mental_health', 'documentation']);
const JURISDICTION = /^US(-[A-Z]{2})?$/;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

export class ContentError extends Error {
  constructor(problems) { super(`Invalid content: ${problems.join('; ')}`); this.problems = problems; }
}

const text = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.length <= max && !/[<>]/.test(v);
const httpsUrl = v => { try { const u = new URL(v); return u.protocol === 'https:' && !u.username && !u.password; } catch { return false; } };
const validDate = v => typeof v === 'string' && DATE.test(v) && new Date(`${v}T00:00:00Z`).toISOString().startsWith(v);

/** Validate one guide; returns problems (empty when valid). */
export function guideProblems(g, { today = new Date().toISOString().slice(0, 10) } = {}) {
  const p = [];
  const at = msg => p.push(`${g?.slug ?? '?'}: ${msg}`);
  if (!g || typeof g !== 'object') return ['guide is not an object'];
  const allowed = new Set(['slug', 'title', 'summary', 'questions', 'jurisdiction', 'topics', 'sections', 'exceptions', 'deadlines', 'evidence', 'getHelp', 'sources', 'review']);
  for (const key of Object.keys(g)) if (!allowed.has(key)) at(`unknown field ${key}`);
  if (!SLUG.test(g.slug ?? '')) at('slug');
  if (!text(g.title, 120)) at('title');
  if (!text(g.summary, 400)) at('summary');
  if (!Array.isArray(g.questions) || !g.questions.length || !g.questions.every(q => text(q, 200))) at('questions');
  if (!g.jurisdiction || !JURISDICTION.test(g.jurisdiction.code ?? '') || !text(g.jurisdiction.label, 80) || !text(g.jurisdiction.note, 400)) at('jurisdiction');
  if (!Array.isArray(g.topics) || !g.topics.length || !g.topics.every(t => SLUG.test(t))) at('topics');
  if (!Array.isArray(g.sections) || !g.sections.length || !g.sections.every(s => text(s.heading, 120) && Array.isArray(s.paragraphs) && s.paragraphs.length && s.paragraphs.every(x => text(x, 1200)))) at('sections');
  for (const list of ['exceptions', 'deadlines', 'evidence', 'getHelp']) if (!Array.isArray(g[list]) || !g[list].every(x => text(x, 400))) at(list);
  if (!g.getHelp?.length) at('getHelp must explain how to reach qualified assistance');
  if (!Array.isArray(g.sources) || !g.sources.length) at('at least one source');
  else for (const s of g.sources) if (!text(s.title, 200) || !SOURCE_KINDS.includes(s.kind) || !text(s.citation, 200) || !httpsUrl(s.url)) at(`source ${s?.citation ?? '?'}`);
  if (Array.isArray(g.sources) && !g.sources.some(s => ['constitution', 'statute', 'regulation', 'case'].includes(s.kind))) at('needs a primary source');
  const r = g.review;
  if (!r || !REVIEW_STATUSES.includes(r.status) || !validDate(r.updatedAt)) at('review status/updatedAt');
  else if (r.status === 'legally_reviewed') {
    if (!text(r.reviewerRole, 120) || !validDate(r.reviewedAt) || !validDate(r.nextReviewDue)) at('legally_reviewed requires reviewerRole, reviewedAt and nextReviewDue');
    if (validDate(r.reviewedAt) && r.reviewedAt > today) at('reviewedAt in the future');
  } else if (r.reviewerRole || r.reviewedAt) at('only legally reviewed guides may name a review');
  return p;
}

export function resourceProblems(r) {
  const p = [];
  const at = msg => p.push(`${r?.id ?? '?'}: ${msg}`);
  if (!SLUG.test(r?.id ?? '')) at('id');
  if (!text(r?.name, 120)) at('name');
  if (!text(r?.description, 400)) at('description');
  if (!httpsUrl(r?.url)) at('url');
  if (!Array.isArray(r?.categories) || !r.categories.length || !r.categories.every(c => RESOURCE_CATEGORIES.includes(c))) at('categories');
  if (!JURISDICTION.test(r?.jurisdiction ?? '')) at('jurisdiction');
  if (!text(r?.cost, 80)) at('cost');
  if (!validDate(r?.checkedAt)) at('checkedAt');
  return p;
}

/** Presentation status: what the page may honestly say about review. */
export function reviewLabel(review, { today = new Date().toISOString().slice(0, 10) } = {}) {
  if (review.status === 'legally_reviewed') {
    return review.nextReviewDue < today
      ? { kind: 'overdue', text: `Last legally reviewed ${review.reviewedAt}. A new review is overdue; check current law before relying on this.` }
      : { kind: 'reviewed', text: `Legally reviewed ${review.reviewedAt} (${review.reviewerRole}). Next review due ${review.nextReviewDue}.` };
  }
  return { kind: 'sample', text: `Sample guide, not yet legally reviewed (updated ${review.updatedAt}). It is provided to demonstrate the format; check the cited sources and seek qualified advice before relying on it.` };
}

const contentRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'content');

/** Load and validate all content; throws ContentError listing every problem. */
export function loadContent(root = contentRoot, options = {}) {
  const guides = readdirSync(join(root, 'rights-guides')).filter(n => n.endsWith('.json')).sort()
    .map(n => JSON.parse(readFileSync(join(root, 'rights-guides', n), 'utf8')));
  const resources = JSON.parse(readFileSync(join(root, 'support-resources.json'), 'utf8')).resources;
  const problems = [...guides.flatMap(g => guideProblems(g, options)), ...resources.flatMap(resourceProblems)];
  const slugs = guides.map(g => g.slug);
  if (new Set(slugs).size !== slugs.length) problems.push('duplicate guide slug');
  const ids = resources.map(r => r.id);
  if (new Set(ids).size !== ids.length) problems.push('duplicate resource id');
  if (problems.length) throw new ContentError(problems);
  return { guides, resources };
}

/** Filter guides by jurisdiction code, topic and free-text query (public data only). */
export function filterGuides(guides, { jurisdiction, topic, q } = {}) {
  const query = typeof q === 'string' ? q.trim().toLowerCase().slice(0, 100) : '';
  return guides.filter(g =>
    (!jurisdiction || g.jurisdiction.code === jurisdiction || (g.jurisdiction.code === 'US' && jurisdiction.startsWith('US-'))) &&
    (!topic || g.topics.includes(topic)) &&
    (!query || [g.title, g.summary, ...g.questions, ...g.topics].join(' ').toLowerCase().includes(query)));
}

export function filterResources(resources, { category } = {}) {
  const sorted = [...resources].sort((a, b) => Number(b.categories.includes('emergency')) - Number(a.categories.includes('emergency')) || a.name.localeCompare(b.name));
  return category ? sorted.filter(r => r.categories.includes(category)) : sorted;
}
