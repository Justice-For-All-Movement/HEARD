import type { Metadata } from 'next';
import Link from 'next/link';
import { copy, routes } from '../../lib/copy';
import { intakeEnabled } from '../../lib/intake-flag';
import { PublicPageBody } from '../../lib/public-page';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: routes.share.title };

export default function SharePage() {
  const enabled = intakeEnabled();
  return (
    <PublicPageBody path="share" intakeEnabled={enabled}>
      {enabled ? (
        <div className="actions">
          <Link className="button" href="/share/start">
            {copy.pages.share.startAction}
          </Link>
        </div>
      ) : null}
    </PublicPageBody>
  );
}
