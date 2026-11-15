import Link from 'next/link';
import type { ReactNode } from 'react';
import { type PublicPath, routes } from './copy';

/** Shared body for preview pages; `children` adds route-specific actions. */
export function PublicPageBody({
  path,
  intakeEnabled = false,
  children,
}: {
  path: PublicPath;
  intakeEnabled?: boolean;
  children?: ReactNode;
}) {
  const page = routes[path];
  return (
    <section className="reading">
      <p className="eyebrow">HEARD · Preview</p>
      <h1>{page.title}</h1>
      <p className="intro">{page.intro}</p>
      {children}
      <aside className="availability" aria-labelledby="availability">
        <h2 id="availability">This service is being built.</h2>
        {intakeEnabled ? (
          <p>
            Private submission is available for testing. Uploads, referrals and
            published case records are not available. Please use only fictional
            information.
          </p>
        ) : (
          <p>
            This preview has no intake forms, uploads, accounts, referrals or
            published case records. Please do not submit personal or sensitive
            information.
          </p>
        )}
        {path === 'rights' ? (
          <p>
            Jurisdiction-specific guides, sources and review dates are not
            available here yet. This preview provides no legal advice.
          </p>
        ) : null}
        {path === 'privacy' ? (
          <p>
            No submission protection, anonymity or end-to-end encryption is
            claimed by this preview. Infrastructure providers may observe
            ordinary web request metadata.
          </p>
        ) : null}
      </aside>
      <Link href="/">
        Return to HEARD <span aria-hidden="true">↗</span>
      </Link>
    </section>
  );
}
