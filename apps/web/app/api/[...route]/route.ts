import { getServerApp } from '../../../lib/server-app';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const handle = (request: Request) => getServerApp().handle(request);
export const GET = handle;
export const POST = handle;
export const PATCH = handle;
export const PUT = handle;
export const DELETE = handle;
