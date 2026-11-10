# Subscription URL logging

`/sub/<token>` is a bearer credential. The API disables ASP.NET `Microsoft.AspNetCore.Hosting.Diagnostics` request logging because that category records the raw request path. API responses are also sent with `Cache-Control: no-store`.

Before release, configure every reverse proxy, CDN, load balancer, tracing agent, and access-log collector in front of the API to redact `/sub/<token>` paths or disable request-target logging for `/sub/` requests. Do not log the path, query string, or full URL for this route. Verify the effective production logging configuration before exposing subscription URLs; this repository does not change production proxy configuration.
