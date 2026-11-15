import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { isPublicPath, routes } from '../../lib/copy';
import { PublicPageBody } from '../../lib/public-page';

type Props = { params: Promise<{ path: string }> };
export const dynamicParams = false;
// `share` has its own route because it depends on the runtime intake flag.
export function generateStaticParams() {
  return Object.keys(routes)
    .filter((path) => path !== 'share')
    .map((path) => ({ path }));
}
export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { path } = await params;
  return { title: isPublicPath(path) ? routes[path].title : 'Page not found' };
}
export default async function PublicPage({ params }: Props) {
  const { path } = await params;
  if (!isPublicPath(path) || path === 'share') notFound();
  return <PublicPageBody path={path} />;
}
