/**
 * HEARD-10 intake schema. One versioned definition drives the wizard UI, server
 * validation and data classification. Identifying detail is always optional:
 * no legal name, email or phone is ever requested, and precision of dates and
 * places is the contributor's choice.
 */

export const INTAKE_SCHEMA_VERSION = '2026-11-15.1';
export const KINDS = Object.freeze(['question', 'experience', 'support']);

/** C1 private metadata, C2 confidential narrative, C3 identifying (see THREAT_MODEL classification). */
export const CLASSIFICATIONS = Object.freeze(['C1', 'C2', 'C3']);

const option = (value, label) => Object.freeze({ value, label });
export const CATEGORY_OPTIONS = Object.freeze([
  option('policing', 'Police or law enforcement'),
  option('immigration', 'Immigration'),
  option('benefits', 'Public benefits or services'),
  option('housing', 'Housing'),
  option('detention', 'Jails, prisons or detention'),
  option('speech_assembly', 'Speech, protest or assembly'),
  option('records', 'Public records or information'),
  option('discrimination', 'Discrimination by a public body'),
  option('other', 'Something else'),
  option('unsure', "I'm not sure"),
]);
export const HELP_OPTIONS = Object.freeze([
  option('understand_rights', 'Understand my rights'),
  option('find_legal_help', 'Find legal help'),
  option('document_evidence', 'Preserve or organize evidence'),
  option('records_request', 'Request public records'),
  option('share_story', 'Share my story publicly later'),
  option('unsure', "I'm not sure yet"),
]);
export const DATE_PRECISION = Object.freeze(['none', 'year', 'month', 'day']);
export const LOCATION_PRECISION = Object.freeze(['none', 'country', 'region', 'city']);
export const IDENTITY_MODES = Object.freeze(['private', 'pseudonymous', 'named']);

const field = def => Object.freeze({ required: false, requiredFor: [], ...def });

/** Ordered wizard steps. Each field declares its type, limits and classification. */
export const STEPS = Object.freeze([
  Object.freeze({
    id: 'pathway', title: 'What would you like to do?',
    fields: Object.freeze([
      field({ id: 'kind', type: 'choice', label: 'Choose what fits best', options: Object.freeze([option('question', 'Ask a question'), option('experience', 'Share an experience'), option('support', 'Ask for assistance')]), requiredFor: KINDS, classification: 'C1' }),
    ]),
  }),
  Object.freeze({
    id: 'privacy', title: 'Your privacy choices',
    fields: Object.freeze([
      field({ id: 'identity_mode', type: 'choice', label: 'If anything is ever published, how should you appear?', hint: 'Nothing is published unless you separately agree later. A pseudonym may not stop someone recognizing details.', options: Object.freeze([option('private', 'No name'), option('pseudonymous', 'A pseudonym'), option('named', 'A name I choose')]), requiredFor: KINDS, classification: 'C1' }),
    ]),
  }),
  Object.freeze({
    id: 'account', title: 'In your own words',
    fields: Object.freeze([
      field({ id: 'summary', type: 'text', label: 'A short title for this (optional)', hint: 'For your own reference. Avoid names.', maxLength: 120, classification: 'C2' }),
      field({ id: 'narrative', type: 'textarea', label: 'What happened, or what would you like to understand?', hint: 'Include only the details needed. Avoid passwords and other people’s private information.', maxLength: 20000, minLength: 10, requiredFor: KINDS, classification: 'C2' }),
    ]),
  }),
  Object.freeze({
    id: 'context', title: 'When and where',
    fields: Object.freeze([
      field({ id: 'date_precision', type: 'choice', label: 'How precisely do you want to share when this happened?', options: Object.freeze([option('none', "I'd rather not say"), option('year', 'Year only'), option('month', 'Month and year'), option('day', 'Exact date')]), classification: 'C1' }),
      field({ id: 'date', type: 'partial_date', label: 'When did this happen?', hint: 'Use the precision you chose: YYYY, YYYY-MM or YYYY-MM-DD.', classification: 'C3' }),
      field({ id: 'location_precision', type: 'choice', label: 'How precisely do you want to share where this happened?', hint: 'Location can affect which laws apply. More detail can also make you easier to identify.', options: Object.freeze([option('none', "I'd rather not say"), option('country', 'Country only'), option('region', 'State or region'), option('city', 'City or town')]), classification: 'C1' }),
      field({ id: 'location', type: 'text', label: 'Where did this happen?', hint: 'For example: "Ohio" or "Columbus, Ohio". Do not include a street address.', maxLength: 120, classification: 'C3' }),
      field({ id: 'categories', type: 'multi', label: 'What is this about? (optional)', options: CATEGORY_OPTIONS, maxItems: 4, classification: 'C1' }),
    ]),
  }),
  Object.freeze({
    id: 'help', title: 'What would help',
    fields: Object.freeze([
      field({ id: 'help_requested', type: 'multi', label: 'What kind of help are you looking for? (optional)', options: HELP_OPTIONS, maxItems: 6, classification: 'C1' }),
      field({ id: 'safety_concern', type: 'choice', label: 'Are you worried about your safety or retaliation if this becomes known? (optional)', hint: 'HEARD is not an emergency service. If someone is in immediate danger, seek local emergency help when it is safe to do so.', options: Object.freeze([option('no', 'No'), option('yes', 'Yes'), option('prefer_not', "I'd rather not say")]), classification: 'C2' }),
      field({ id: 'language', type: 'choice', label: 'Preferred language for any follow-up', options: Object.freeze([option('en', 'English'), option('es', 'Español')]), classification: 'C1' }),
    ]),
  }),
  Object.freeze({
    id: 'evidence', title: 'Supporting material',
    fields: Object.freeze([]),
    note: 'Uploading files is not available yet. Keep originals safe; do not send them by email or social media.',
  }),
  Object.freeze({ id: 'review', title: 'Review before you send.', fields: Object.freeze([]) }),
]);

export const FIELDS = Object.freeze(Object.fromEntries(STEPS.flatMap(s => s.fields.map(f => [f.id, Object.freeze({ ...f, step: s.id })]))));

export class IntakeValidationError extends Error {
  constructor(errors) { super('INTAKE_INVALID'); this.code = 'INTAKE_INVALID'; this.errors = errors; this.field = Object.keys(errors)[0]; }
}

const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
function cleanText(value, def) {
  if (typeof value !== 'string') return [null, 'type'];
  const text = value.normalize('NFC').replace(/\r\n?/g, '\n');
  if (CONTROL.test(text)) return [null, 'characters'];
  const trimmed = text.trim();
  if (def.maxLength && trimmed.length > def.maxLength) return [null, 'too_long'];
  if (trimmed === '') return [undefined, null];
  if (def.minLength && trimmed.length < def.minLength) return [null, 'too_short'];
  return [trimmed, null];
}

/**
 * Validate answers. `partial` (draft save) checks only supplied fields; full
 * validation (submission) also enforces required fields and cross-field rules.
 * Unknown fields are rejected so nothing unclassified is ever stored.
 * @returns {Record<string, unknown>} canonical answers (empty values dropped)
 */
export function validateAnswers(input, { partial = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new IntakeValidationError({ _: 'type' });
  const errors = {};
  const out = {};
  for (const [id, value] of Object.entries(input)) {
    const def = FIELDS[id];
    if (!def) { errors[id] = 'unknown_field'; continue; }
    if (value === null || value === undefined) continue;
    if (def.type === 'text' || def.type === 'textarea') {
      const [clean, error] = cleanText(value, def);
      if (error) errors[id] = error; else if (clean !== undefined) out[id] = clean;
    } else if (def.type === 'choice') {
      if (!def.options.some(o => o.value === value)) errors[id] = 'invalid_option'; else out[id] = value;
    } else if (def.type === 'multi') {
      if (!Array.isArray(value) || value.some(v => !def.options.some(o => o.value === v))) errors[id] = 'invalid_option';
      else if (new Set(value).size > def.maxItems) errors[id] = 'too_many';
      else if (value.length) out[id] = [...new Set(value)];
    } else if (def.type === 'partial_date') {
      if (typeof value !== 'string' || !/^\d{4}(-\d{2}(-\d{2})?)?$/.test(value)) errors[id] = 'invalid_date';
      else {
        const [y, m = '01', d = '01'] = value.split('-');
        const date = new Date(`${y}-${m}-${d}T00:00:00Z`);
        if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== `${y}-${m}-${d}` || Number(y) < 1900 || date.getTime() > Date.now() + 86_400_000) errors[id] = 'invalid_date';
        else out[id] = value;
      }
    }
  }
  // Cross-field: precision choices limit what may be stored, so a contributor who
  // chose "year only" cannot accidentally keep a full date.
  const datePrecision = out.date_precision ?? (out.date ? undefined : 'none');
  if (out.date) {
    const parts = out.date.split('-').length;
    const allowed = { none: 0, year: 1, month: 2, day: 3 }[datePrecision ?? 'day'];
    if (parts !== allowed) errors.date = 'precision_mismatch';
  }
  if (out.location && (out.location_precision ?? 'city') === 'none') errors.location = 'precision_mismatch';
  if (out.location && /\d{1,5}\s+\p{L}+\s+(street|st|avenue|ave|road|rd|blvd|lane|ln|drive|dr)\b/iu.test(out.location)) errors.location = 'too_specific';
  if (!partial) {
    for (const def of Object.values(FIELDS)) {
      if (def.requiredFor.length && (def.requiredFor.includes(out.kind) || def.id === 'kind') && out[def.id] === undefined && !errors[def.id]) errors[def.id] = 'required';
    }
  }
  if (Object.keys(errors).length) throw new IntakeValidationError(errors);
  return out;
}

/** Classification map of stored answers (for logging decisions and future exports). */
export function classify(answers) {
  return Object.fromEntries(Object.keys(answers).map(id => [id, FIELDS[id]?.classification ?? 'C2']));
}

/** Public schema for clients; contains no data. */
export function publicSchema() {
  return { version: INTAKE_SCHEMA_VERSION, steps: STEPS };
}
