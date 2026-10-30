import { ApiError } from '../../api/auth'

// TECH-01: one rule for "the write may have been applied" across the site
// editor panels. Each panel keeps its own recovery (exact retry, reload,
// merge); only this classification is shared. Only a 4xx other than 408/429
// is a definite refusal; a network failure, status 0 / malformed response,
// 408, 429, 5xx or any other status may have been applied.
export function writeOutcomeUnknown(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  return error.code === 'invalid_response' || error.status < 400 || error.status >= 500 ||
    error.status === 408 || error.status === 429
}
