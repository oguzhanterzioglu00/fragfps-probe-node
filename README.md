# FragFPS probe node

Stateless HTTPS-to-UDP relay for Counter-Strike 1.6 A2S queries. The primary FragFPS host signs every request with HMAC-SHA256. The node accepts only public IPv4 targets, exact ports and authenticated requests.

## Environment

- `PROBE_SHARED_SECRET`: at least 32 random characters; must match the primary site's protected node configuration.
- `PROBE_REGION`: short node region (`eu`, `na`, `sa`, `asia` or `global`).
- `PORT`: HTTP port supplied by the hosting platform.
- `PROBE_MAX_CONCURRENT`: optional concurrent UDP query cap; defaults to 8.

## Primary-site configuration

Create protected `httpdocs/data/probe-nodes.php` on production:

```php
<?php
return [
    ['id' => 'render-eu-1', 'region' => 'eu', 'url' => 'https://your-node.onrender.com', 'secret' => 'same-long-random-secret'],
];
```

The normal deployment excludes this file so node secrets are never overwritten or published.
