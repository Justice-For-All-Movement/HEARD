import 'server-only';
import { getServerApp } from './server-app';

/** Runtime feature flag, read from the same validated configuration as the API. */
export function intakeEnabled(): boolean {
  return getServerApp().config.intake.enabled;
}
