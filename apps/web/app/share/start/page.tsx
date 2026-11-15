import { publicPolicies } from '@heard/consent';
import { publicSchema } from '@heard/intake';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { copy } from '../../../lib/copy';
import { intakeEnabled } from '../../../lib/intake-flag';
import { IntakeWizard } from './wizard';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Begin privately' };

export default function StartPage() {
  // Indistinguishable from an unknown page while the feature flag is off.
  if (!intakeEnabled()) notFound();
  const processing = publicPolicies().find(
    (p) => p.purpose === 'private_processing',
  );
  if (!processing) notFound();
  return (
    <section className="reading wizard-page">
      <p className="eyebrow">HEARD · Private submission</p>
      <h1>{copy.pages.share.title}</h1>
      <p className="intro">{copy.pages.share.intro}</p>
      <p className="note">{copy.submission.safetyNote}</p>
      <IntakeWizard
        schema={publicSchema()}
        processingPolicy={processing}
        text={copy.submission}
      />
    </section>
  );
}
