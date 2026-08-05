As of August 05, 2026

# Introduction
"The HTTP QUERY Method" (Proposed Standard, published June 15, 2026, authors Reschke / Snell / Bishop, from `draft-ietf-httpbis-safe-method-w-body`). It's the first genuinely new HTTP method since `PATCH` (RFC 5789, 2010).

What it does: a safe, idempotent, cacheable request like GET, but carrying the query in the request body like POST. Servers advertise accepted body formats via the new `Accept-Query` response header. It's aimed exactly at search-heavy apps (e-commerce, CMS, GraphQL-style faceted search) where complex queries blow past URL limits or leak sensitive filters into logs.

Why it's interesting for offensive testing — the instant it ships, three attack classes appear that most of the existing stack was never tested against:

1. Injection payloads move into the body (SQLi / NoSQLi / SSTI / OS command injection)
2. WAF blind spot — rule sets inspect POST/PUT bodies and treat GET as low-risk; `QUERY` bodies often ride through unexamined (GET-shaped code path)
3. Cache poisoning is structural — RFC 10008 makes QUERY cacheable but requires the cache key to include the body; naive caches key on URL only
Plus request-smuggling/desync and CPU/memory DoS via expensive query bodies.


# Apache Adoption
<img width="1359" height="469" alt="image" src="https://github.com/user-attachments/assets/a319fc31-d92b-4b45-8afb-00d97414ce47" />
Feature is implemented, it will available in Tomcat 12 when its released;

# Nginx Adoption
<img width="1875" height="943" alt="image" src="https://github.com/user-attachments/assets/77501313-8e46-459f-acea-b7e1e0b43e4e" />
Feature is not implemented yet, 

# Cache Control
<img width="1857" height="681" alt="image" src="https://github.com/user-attachments/assets/1b122c9e-aace-44d8-8319-1b81c2c767a1" />
Even though the whole point of the new `QUERY` method (RFC 10008) is to allow complex read-only requests to be cached, Cloudflare is currently treating it as dynamic traffic for one (or both) of these reasons:

**Default Method Behavior:** By default, CDNs like Cloudflare only cache `GET` requests. Because `QUERY` is very new, Cloudflare might still be treating it like a `POST` request (which is inherently uncacheable by default) unless you explicitly write a Cloudflare Cache Rule to override this behavior.
**Missing `Cache-Control` Headers:** Your backend server did not send a `Cache-Control` header (e.g., `Cache-Control: public, max-age=300`) in its response. Without explicit permission from your server, Cloudflare will always default to `DYNAMIC` to be safe and avoid serving stale data.

To actually cache this response, your backend application needs to return explicit `Cache-Control` headers, and  need to configure a custom Cache Rule in Cloudflare dashboard to tell it to respect the `QUERY` method and cache it based on the request body.
# Useful Links
* HTTP Query Adoption Tracker : https://gist.github.com/desiderantes/2c7e657649cb92672d68e580fb69aa1d
* Try HTTP Query Online : https://httpquery.com/test/
