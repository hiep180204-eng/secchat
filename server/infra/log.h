#ifndef SECCHAT_INFRA_LOG_H
#define SECCHAT_INFRA_LOG_H

/*
 * infra/log.h — structured logging for SecChat server
 *
 * Behaviour is controlled by two environment variables:
 *
 *   SECCHAT_LOG_JSON=1   → emit JSON lines:
 *                          {"ts":"2026-05-03T08:33:11Z","level":"INFO","msg":"..."}
 *   SECCHAT_LOG_JSON=0   → emit human-readable lines (default):
 *                          [08:33:11] INFO   ...
 *
 *   SECCHAT_LOG_LEVEL    → minimum level to emit (DEBUG|INFO|WARN|ERROR).
 *                          Default: INFO.
 *
 * Thread-safe: log_write() uses a single internal mutex.
 */

#include <stdarg.h>

/* Low-level writer — prefer the macros below. */
void log_write(const char *level, const char *fmt, ...);

/* Convenience macros — same call-site interface as the old inline version. */
#define log_info(...)  log_write("INFO ", __VA_ARGS__)
#define log_warn(...)  log_write("WARN ", __VA_ARGS__)
#define log_error(...) log_write("ERROR", __VA_ARGS__)

#endif /* SECCHAT_INFRA_LOG_H */
