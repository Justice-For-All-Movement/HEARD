'use client';

import type { FieldDef, StepDef } from '@heard/intake';
import { validateAnswers } from '@heard/intake';
import { type FormEvent, useEffect, useId, useRef, useState } from 'react';

type Answers = Record<string, string | string[]>;
type Policy = {
  purpose: string;
  version: string;
  title: string;
  text: string;
  recipients: readonly string[];
};
type Text = {
  heading: string;
  recipientHeading: string;
  recipientIntro: string;
  noPublicationNote: string;
  identityNote: string;
  sensitiveDataNote: string;
  confirmLabel: string;
  saveDraftLabel: string;
  statusReceivedTitle: string;
  statusReceivedBody: string;
  networkError: string;
  validationError: string;
};
type Receipt = { reference: string; nextSteps: string };
type Phase = 'intro' | 'resume' | 'recovery' | 'steps' | 'done';

const ERROR_TEXT: Record<string, string> = {
  required: 'This is required.',
  too_long: 'This is too long.',
  too_short: 'Please add a little more detail.',
  invalid_option: 'Choose one of the options.',
  invalid_date: 'Enter a real date in the format shown.',
  precision_mismatch: 'This does not match the precision you chose.',
  too_specific: 'Please leave out street addresses.',
  too_many: 'Choose fewer options.',
  characters: 'Remove unsupported characters.',
  consent: 'Please confirm this to send your submission.',
};

async function api<T>(
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: T }> {
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    headers: {
      ...headers,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  const response = await fetch(path, init);
  const text = await response.text();
  return {
    status: response.status,
    data: (text ? JSON.parse(text) : null) as T,
  };
}

export function IntakeWizard({
  schema,
  processingPolicy,
  text,
}: {
  schema: { version: string; steps: readonly StepDef[] };
  processingPolicy: Policy;
  text: Text;
}) {
  const steps = schema.steps;
  const [phase, setPhase] = useState<Phase>('intro');
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<Answers>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [banner, setBanner] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [hasSession, setHasSession] = useState(false);
  const [savedCode, setSavedCode] = useState(false);
  const [resumeCode, setResumeCode] = useState('');
  const [caseId, setCaseId] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [consented, setConsented] = useState(false);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const idempotencyKey = useRef<string>('');
  const headingRef = useRef<HTMLHeadingElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const baseId = useId();
  const step = steps[index];

  // Move focus to the new step heading so screen-reader users hear where they are.
  // biome-ignore lint/correctness/useExhaustiveDependencies: focus must move whenever the step or phase changes.
  useEffect(() => {
    headingRef.current?.focus();
  }, [index, phase]);
  useEffect(() => {
    if (Object.keys(errors).length || banner) summaryRef.current?.focus();
  }, [errors, banner]);

  const fieldId = (id: string) => `${baseId}-${id}`;

  function stepErrors(current: StepDef): Record<string, string> {
    const found: Record<string, string> = {};
    const values = Object.fromEntries(
      current.fields
        .map((f) => [f.id, answers[f.id]] as const)
        .filter(([, v]) => v !== undefined && v !== ''),
    );
    try {
      validateAnswers(
        { ...values, ...(answers.kind ? { kind: answers.kind } : {}) },
        { partial: true },
      );
    } catch (error) {
      Object.assign(
        found,
        (error as { errors?: Record<string, string> }).errors ?? {},
      );
    }
    for (const f of current.fields) {
      const kind = (answers.kind as string | undefined) ?? '';
      const required =
        f.id === 'kind' || (f.requiredFor as readonly string[]).includes(kind);
      const value = answers[f.id];
      if (
        required &&
        (value === undefined ||
          value === '' ||
          (Array.isArray(value) && !value.length))
      )
        found[f.id] = 'required';
    }
    if (current.id === 'privacy' && !consented) found.consent = 'consent';
    return Object.fromEntries(
      Object.entries(found).filter(
        ([k]) => k === 'consent' || current.fields.some((f) => f.id === k),
      ),
    );
  }

  async function ensureDraft(): Promise<boolean> {
    if (caseId) return true;
    const created = await api<{ caseId: string; revision: number }>(
      'POST',
      '/api/v1/drafts',
      { kind: answers.kind },
    );
    if (created.status !== 201) return false;
    setCaseId(created.data.caseId);
    setRevision(created.data.revision);
    return true;
  }

  async function save(): Promise<boolean> {
    if (!caseId) return ensureDraft();
    const result = await api<{
      revision: number;
      error?: { code: string; fields?: Record<string, string> };
    }>('PUT', `/api/v1/drafts/${caseId}`, {
      revision,
      answers: clean(answers),
    });
    if (result.status === 200) {
      setRevision(result.data.revision);
      return true;
    }
    if (result.status === 409)
      setBanner(
        'This draft changed in another window. Reload it before saving again.',
      );
    else if (result.status === 400 && result.data.error?.fields)
      setErrors(result.data.error.fields);
    else setBanner(text.networkError);
    return false;
  }

  async function startSession(): Promise<boolean> {
    const started = await api<{ recoveryCode: string }>(
      'POST',
      '/api/v1/anonymous/start',
      {},
    );
    if (started.status !== 201) return false;
    setRecoveryCode(started.data.recoveryCode);
    setHasSession(true);
    return true;
  }

  async function onContinue(event: FormEvent) {
    event.preventDefault();
    if (!step || busy) return;
    const found = stepErrors(step);
    setErrors(found);
    setBanner(null);
    if (Object.keys(found).length) return;
    setBusy(true);
    try {
      if (step.id === 'pathway' && !caseId && !hasSession) {
        if (!(await startSession())) return setBanner(text.networkError);
        setPhase('recovery');
        return;
      }
      if (step.id === 'privacy') {
        const consent = await api(
          'POST',
          `/api/v1/my/cases/${caseId}/consents`,
          {
            purpose: 'private_processing',
            decision: 'grant',
            policyVersion: processingPolicy.version,
          },
        );
        if (consent.status !== 201) return setBanner(text.networkError);
      }
      if (!(await save())) return;
      setIndex((i) => Math.min(i + 1, steps.length - 1));
    } catch {
      setBanner(text.networkError);
    } finally {
      setBusy(false);
    }
  }

  async function afterRecoverySaved(event: FormEvent) {
    event.preventDefault();
    if (!savedCode) return setErrors({ saved: 'required' });
    setBusy(true);
    try {
      setRecoveryCode(null);
      setPhase('steps');
      if (!caseId && !answers.kind) return setIndex(0);
      if (!(await ensureDraft())) return setBanner(text.networkError);
      setIndex(1);
    } finally {
      setBusy(false);
    }
  }

  async function resume(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setBanner(null);
    try {
      const redeemed = await api<{ recoveryCode: string }>(
        'POST',
        '/api/v1/anonymous/redeem',
        { recoveryCode: resumeCode },
      );
      if (redeemed.status !== 200)
        return setBanner('That recovery code was not accepted.');
      const mine = await api<{ cases: { caseId: string; status: string }[] }>(
        'GET',
        '/api/v1/my/cases',
      );
      const draft = mine.data.cases.find((c) => c.status === 'draft');
      setRecoveryCode(redeemed.data.recoveryCode);
      setHasSession(true);
      if (draft) {
        const loaded = await api<{ revision: number; answers: Answers }>(
          'GET',
          `/api/v1/drafts/${draft.caseId}`,
        );
        setCaseId(draft.caseId);
        setRevision(loaded.data.revision);
        setAnswers(loaded.data.answers);
        setConsented(false);
      }
      setPhase('recovery');
    } catch {
      setBanner(text.networkError);
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || !caseId) return;
    setBusy(true);
    setBanner(null);
    idempotencyKey.current ||= crypto.randomUUID();
    try {
      const sent = await api<
        Receipt & { error?: { code: string; fields?: Record<string, string> } }
      >(
        'POST',
        `/api/v1/drafts/${caseId}/submit`,
        { revision },
        { 'idempotency-key': idempotencyKey.current },
      );
      if (sent.status === 201 || sent.status === 200) {
        setReceipt({
          reference: sent.data.reference,
          nextSteps: sent.data.nextSteps,
        });
        setPhase('done');
      } else if (sent.status === 400 && sent.data.error?.fields) {
        setErrors(sent.data.error.fields);
        setBanner(text.validationError);
      } else if (sent.status === 409) {
        setBanner(
          'Something changed before sending. Review your privacy choice and answers, then try again.',
        );
      } else setBanner(text.networkError);
    } catch {
      setBanner(text.networkError);
    } finally {
      setBusy(false);
    }
  }

  const errorSummary =
    Object.keys(errors).length || banner ? (
      <div
        className="error-summary"
        role="alert"
        tabIndex={-1}
        ref={summaryRef}
      >
        <p>{banner ?? text.validationError}</p>
        {Object.keys(errors).length ? (
          <ul>
            {Object.entries(errors).map(([id, code]) => (
              <li key={id}>
                <a href={`#${fieldId(id)}`}>
                  {ERROR_TEXT[code] ?? 'Please check this answer.'}
                </a>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    ) : null;

  if (phase === 'done' && receipt) {
    return (
      <section className="wizard" aria-labelledby={`${baseId}-done`}>
        <h2 id={`${baseId}-done`} tabIndex={-1} ref={headingRef}>
          {text.statusReceivedTitle}
        </h2>
        <p>{text.statusReceivedBody}</p>
        <p className="reference">
          Reference: <strong>{receipt.reference}</strong>
        </p>
        <p>{receipt.nextSteps}</p>
      </section>
    );
  }

  if (phase === 'intro' || phase === 'resume') {
    return (
      <section className="wizard" aria-labelledby={`${baseId}-intro`}>
        <h2 id={`${baseId}-intro`} tabIndex={-1} ref={headingRef}>
          How this works
        </h2>
        <p>
          You do not need an email address or phone number. HEARD will give you
          a one-time recovery code instead. Hosting and network providers can
          still see connection details such as IP addresses.
        </p>
        <p>{text.sensitiveDataNote}</p>
        {errorSummary}
        {phase === 'intro' ? (
          <div className="actions">
            <button
              type="button"
              className="button"
              onClick={() => {
                setPhase('steps');
                setIndex(0);
              }}
            >
              Begin privately
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={() => setPhase('resume')}
            >
              Resume with a recovery code
            </button>
          </div>
        ) : (
          <form onSubmit={resume} noValidate>
            <label htmlFor={fieldId('resume')}>Recovery code</label>
            <input
              id={fieldId('resume')}
              name="recovery-code"
              autoComplete="off"
              spellCheck={false}
              value={resumeCode}
              onChange={(e) => setResumeCode(e.target.value)}
            />
            <div className="actions">
              <button type="submit" className="button" disabled={busy}>
                Resume
              </button>
            </div>
          </form>
        )}
      </section>
    );
  }

  if (phase === 'recovery' && recoveryCode) {
    return (
      <section className="wizard" aria-labelledby={`${baseId}-code`}>
        <h2 id={`${baseId}-code`} tabIndex={-1} ref={headingRef}>
          Save your recovery code
        </h2>
        <p>
          This code is the only way back to your draft. HEARD cannot show it
          again or recover it for you. Each code works once; you will get a new
          one when you use it.
        </p>
        <p className="recovery-code">
          Your recovery code: <code>{recoveryCode}</code>
        </p>
        {errorSummary}
        <form onSubmit={afterRecoverySaved} noValidate>
          <div className="check">
            <input
              type="checkbox"
              id={fieldId('saved')}
              checked={savedCode}
              onChange={(e) => setSavedCode(e.target.checked)}
              aria-invalid={errors.saved ? true : undefined}
            />
            <label htmlFor={fieldId('saved')}>
              I have saved my recovery code somewhere safe.
            </label>
          </div>
          <div className="actions">
            <button type="submit" className="button" disabled={busy}>
              {caseId ? 'Return to my draft' : 'Continue to my account'}
            </button>
          </div>
        </form>
      </section>
    );
  }

  if (!step) return null;
  const isReview = step.id === 'review';
  return (
    <section className="wizard" aria-labelledby={`${baseId}-step`}>
      <p className="progress" aria-live="polite">
        Step {index + 1} of {steps.length}
      </p>
      <ol className="steps" aria-label="Steps">
        {steps.map((s, i) => (
          <li key={s.id} aria-current={i === index ? 'step' : undefined}>
            {s.title}
          </li>
        ))}
      </ol>
      <h2 id={`${baseId}-step`} tabIndex={-1} ref={headingRef}>
        {step.title}
      </h2>
      {errorSummary}
      <form onSubmit={isReview ? submit : onContinue} noValidate>
        {step.note ? <p className="note">{step.note}</p> : null}
        {step.fields.map((field) => (
          <Field
            key={field.id}
            field={field}
            id={fieldId(field.id)}
            value={answers[field.id]}
            error={errors[field.id]}
            onChange={(value) =>
              setAnswers((a) => ({ ...a, [field.id]: value }))
            }
          />
        ))}
        {step.id === 'privacy' ? (
          <fieldset className="consent">
            <legend>{processingPolicy.title}</legend>
            <p id={`${fieldId('consent')}-text`}>{processingPolicy.text}</p>
            <p>{text.identityNote}</p>
            <div className="check">
              <input
                type="checkbox"
                id={fieldId('consent')}
                checked={consented}
                aria-describedby={`${fieldId('consent')}-text`}
                aria-invalid={errors.consent ? true : undefined}
                onChange={(e) => setConsented(e.target.checked)}
              />
              <label htmlFor={fieldId('consent')}>
                I agree that HEARD may keep and review what I submit as
                described above.
              </label>
            </div>
          </fieldset>
        ) : null}
        {isReview ? (
          <Review
            answers={answers}
            steps={steps}
            policy={processingPolicy}
            text={text}
          />
        ) : null}
        <div className="actions">
          {index > 0 ? (
            <button
              type="button"
              className="secondary-button"
              onClick={() => setIndex((i) => Math.max(0, i - 1))}
              disabled={busy}
            >
              Back
            </button>
          ) : null}
          <button type="submit" className="button" disabled={busy}>
            {isReview
              ? text.confirmLabel
              : index === 0
                ? 'Choose and continue'
                : `${text.saveDraftLabel} and continue`}
          </button>
        </div>
      </form>
    </section>
  );
}

function clean(answers: Answers): Answers {
  return Object.fromEntries(
    Object.entries(answers).filter(
      ([, v]) => v !== '' && !(Array.isArray(v) && !v.length),
    ),
  );
}

function Field({
  field,
  id,
  value,
  error,
  onChange,
}: {
  field: FieldDef;
  id: string;
  value: string | string[] | undefined;
  error: string | undefined;
  onChange: (value: string | string[]) => void;
}) {
  const hintId = field.hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined;
  const hint = field.hint ? (
    <p id={hintId} className="hint">
      {field.hint}
    </p>
  ) : null;
  const message = error ? (
    <p id={errorId} className="field-error">
      {ERROR_TEXT[error] ?? 'Please check this answer.'}
    </p>
  ) : null;

  if (field.type === 'choice' || field.type === 'multi') {
    const multiple = field.type === 'multi';
    const selected = Array.isArray(value) ? value : value ? [value] : [];
    return (
      <fieldset
        id={id}
        className="field"
        aria-describedby={describedBy}
        aria-invalid={error ? true : undefined}
        tabIndex={-1}
      >
        <legend>{field.label}</legend>
        {hint}
        {message}
        {(field.options ?? []).map((option) => {
          const optionId = `${id}-${option.value}`;
          return (
            <div className="check" key={option.value}>
              <input
                type={multiple ? 'checkbox' : 'radio'}
                id={optionId}
                name={id}
                value={option.value}
                checked={selected.includes(option.value)}
                onChange={(e) =>
                  onChange(
                    multiple
                      ? e.target.checked
                        ? [...selected, option.value]
                        : selected.filter((v) => v !== option.value)
                      : option.value,
                  )
                }
              />
              <label htmlFor={optionId}>{option.label}</label>
            </div>
          );
        })}
      </fieldset>
    );
  }
  const common = {
    id,
    name: id,
    value: typeof value === 'string' ? value : '',
    'aria-describedby': describedBy,
    'aria-invalid': error ? true : undefined,
    maxLength: field.maxLength,
    autoComplete: 'off',
  } as const;
  return (
    <div className="field">
      <label htmlFor={id}>{field.label}</label>
      {hint}
      {message}
      {field.type === 'textarea' ? (
        <>
          <textarea
            {...common}
            rows={10}
            onChange={(e) => onChange(e.target.value)}
          />
          <p className="hint" aria-live="polite">
            {(typeof value === 'string' ? value.length : 0).toLocaleString()} of{' '}
            {field.maxLength?.toLocaleString()} characters
          </p>
        </>
      ) : (
        <input
          {...common}
          type="text"
          inputMode={field.type === 'partial_date' ? 'numeric' : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </div>
  );
}

function Review({
  answers,
  steps,
  policy,
  text,
}: {
  answers: Answers;
  steps: readonly StepDef[];
  policy: Policy;
  text: Text;
}) {
  const label = (field: FieldDef, value: string | string[]) => {
    const values = Array.isArray(value) ? value : [value];
    return values
      .map((v) => field.options?.find((o) => o.value === v)?.label ?? v)
      .join(', ');
  };
  return (
    <>
      <dl className="review">
        {steps.flatMap((s) =>
          s.fields
            .filter((f) => answers[f.id] !== undefined && answers[f.id] !== '')
            .map((f) => (
              <div key={f.id}>
                <dt>{f.label}</dt>
                <dd>{label(f, answers[f.id] as string | string[])}</dd>
              </div>
            )),
        )}
      </dl>
      <h3>{text.recipientHeading}</h3>
      <p>{text.recipientIntro}</p>
      <ul>
        {policy.recipients.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
      <p>{text.noPublicationNote}</p>
    </>
  );
}
