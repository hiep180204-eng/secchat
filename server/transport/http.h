#ifndef SECCHAT_TRANSPORT_HTTP_H
#define SECCHAT_TRANSPORT_HTTP_H

/*
 * transport/http.h — plain-TCP HTTP control plane (port 8889)
 *
 * Exposes three read-only endpoints for monitoring and health checks:
 *
 *   GET /healthz  — always returns 200 OK with body "ok"
 *   GET /readyz   — returns 200 OK when DB is reachable, 503 otherwise
 *   GET /metrics  — returns the live JSON metrics snapshot
 *
 * The server runs on a single background thread; each request gets a
 * small stack-allocated buffer and is handled synchronously.  This is
 * NOT a general-purpose HTTP server — it handles exactly the three
 * endpoints above and drops everything else with 404.
 *
 * Security: binds to 0.0.0.0 on the configured port. In production
 * deployments this port should be firewalled to the internal network.
 */

/* Start the HTTP control-plane listener on `port` in a background thread.
 * Returns 1 on success, 0 if the socket could not be bound.
 * Call once from main() after config_load() and metrics_init(). */
int http_server_start(int port);

#endif /* SECCHAT_TRANSPORT_HTTP_H */
