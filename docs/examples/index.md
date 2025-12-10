# Examples

Practical examples for using the WAF package.

---

## Index

| Example | Description |
|---------|-------------|
| [API Protection](#api-protection) | Protect REST APIs |
| [Login Protection](#login-protection) | Secure login endpoints |
| [Admin Panel](#admin-panel) | Secure admin areas |
| [Multi-tenant](#multi-tenant) | Tenant-specific rate limits |
| [Webhook Endpoints](#webhook-endpoints) | Secure webhooks |
| [CDN Integration](#cdn-integration) | Behind Cloudflare/AWS |

---

## API Protection

Complete API security setup:

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Middlewares\CorsMiddleware;
use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;
use Lalaz\Waf\Middlewares\HttpMethodMiddleware;

$router->group(['prefix' => '/api/v1', 'middleware' => [
    // Rate limit: 100 requests per minute
    RateLimitMiddleware::perMinute(100),
    
    // Block malicious payloads
    SanitizationMiddleware::forApi(),
    
    // Security headers for API
    HelmetMiddleware::api(),
    
    // CORS for frontend
    CorsMiddleware::strict('https://app.example.com'),
    
    // Limit payload size
    RequestSizeLimiterMiddleware::forApi(),
    
    // RESTful methods only
    HttpMethodMiddleware::restful(),
]], function ($router) {
    $router->get('/users', [UserController::class, 'index']);
    $router->post('/users', [UserController::class, 'store']);
    $router->get('/users/{id}', [UserController::class, 'show']);
    $router->put('/users/{id}', [UserController::class, 'update']);
    $router->delete('/users/{id}', [UserController::class, 'destroy']);
});
```

---

## Login Protection

Protect login endpoints against brute force:

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\IpFilterMiddleware;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\RedisStore;

// Configure rate limiter with Redis for distributed systems
$store = new RedisStore($redis, 'login_rate:');
$limiter = new RateLimiter($store);

// Custom key resolver: rate limit by IP + username
$loginMiddleware = new RateLimitMiddleware(
    limiter: $limiter,
    maxAttempts: 5,
    decaySeconds: 300, // 5 minutes
    keyResolver: function ($request) {
        $body = $request->getParsedBody();
        $ip = $request->getServerParams()['REMOTE_ADDR'];
        $username = $body['username'] ?? 'unknown';
        return "login:{$ip}:{$username}";
    }
);

$router->group(['prefix' => '/auth', 'middleware' => [
    $loginMiddleware,
    SanitizationMiddleware::strict(),
]], function ($router) {
    $router->post('/login', [AuthController::class, 'login']);
    $router->post('/register', [AuthController::class, 'register']);
    $router->post('/forgot-password', [AuthController::class, 'forgotPassword']);
});

// After successful login, clear rate limit
class AuthController
{
    public function login(Request $request): Response
    {
        // ... validate credentials ...
        
        if ($success) {
            // Clear rate limit on success
            $key = "login:{$request->ip()}:{$request->input('username')}";
            $this->rateLimiter->clear($key);
        }
        
        // ...
    }
}
```

---

## Admin Panel

Secure admin area with multiple layers:

```php
use Lalaz\Waf\Middlewares\IpFilterMiddleware;
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;
use Lalaz\Waf\Middlewares\HttpMethodMiddleware;
use Lalaz\Waf\IpFilter\IpList;

// Load admin IPs from database
$adminIps = DB::table('admin_whitelist')->pluck('ip')->toArray();

// Create whitelist with persistence
$whitelist = new IpList(
    ips: $adminIps,
    onAdd: fn($ip) => DB::table('admin_whitelist')->insert(['ip' => $ip]),
    onRemove: fn($ip) => DB::table('admin_whitelist')->where('ip', $ip)->delete(),
);

$router->group(['prefix' => '/admin', 'middleware' => [
    // Only whitelisted IPs
    new IpFilterMiddleware(whitelist: $whitelist, mode: 'whitelist'),
    
    // Only US and Canada
    GeoBlockMiddleware::allowOnly(['US', 'CA']),
    
    // Strict rate limiting
    RateLimitMiddleware::perMinute(30),
    
    // Block all threats
    SanitizationMiddleware::strict(),
    
    // Strict security headers
    HelmetMiddleware::strict(),
]], function ($router) {
    $router->get('/dashboard', [AdminController::class, 'dashboard']);
    $router->get('/users', [AdminController::class, 'users']);
    $router->get('/logs', [AdminController::class, 'logs']);
});
```

---

## Multi-tenant

Different rate limits per tenant:

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\RedisStore;

class TenantRateLimitMiddleware
{
    private RateLimiter $limiter;
    
    public function __construct()
    {
        $store = new RedisStore($redis, 'tenant_rate:');
        $this->limiter = new RateLimiter($store);
    }
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $tenant = $request->getAttribute('tenant');
        $plan = $tenant->plan;
        
        // Different limits per plan
        $limits = [
            'free' => ['max' => 100, 'window' => 3600],      // 100/hour
            'basic' => ['max' => 1000, 'window' => 3600],    // 1000/hour
            'pro' => ['max' => 10000, 'window' => 3600],     // 10000/hour
            'enterprise' => ['max' => 100000, 'window' => 3600], // 100000/hour
        ];
        
        $limit = $limits[$plan] ?? $limits['free'];
        $key = "tenant:{$tenant->id}";
        
        if ($this->limiter->tooManyAttempts($key, $limit['max'], $limit['window'])) {
            return new Response(429, [
                'Retry-After' => $this->limiter->availableIn($key),
                'X-RateLimit-Limit' => $limit['max'],
                'X-RateLimit-Remaining' => 0,
            ], 'Rate limit exceeded. Upgrade your plan for higher limits.');
        }
        
        $this->limiter->hit($key, $limit['window']);
        
        $response = $handler->handle($request);
        
        return $response
            ->withHeader('X-RateLimit-Limit', $limit['max'])
            ->withHeader('X-RateLimit-Remaining', $this->limiter->remaining($key, $limit['max'], $limit['window']));
    }
}
```

---

## Webhook Endpoints

Secure webhook receivers:

```php
use Lalaz\Waf\Middlewares\IpFilterMiddleware;
use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;

// Stripe webhook IPs
$stripeIps = [
    '3.18.12.63',
    '3.130.192.231',
    '13.235.14.237',
    '13.235.122.149',
    '18.211.135.69',
    '35.154.171.200',
    '52.15.183.38',
    '54.187.174.169',
    '54.187.205.235',
    '54.187.216.72',
];

$router->group(['prefix' => '/webhooks', 'middleware' => [
    // Only allow known webhook sources
    IpFilterMiddleware::whitelist($stripeIps),
    
    // Allow larger payloads for webhooks
    RequestSizeLimiterMiddleware::forUploads(),
    
    // Skip threat detection for webhook signature fields
    new SanitizationMiddleware(
        detector: ThreatDetector::all(),
        mode: 'log', // Log only, don't block
        excludedParams: ['signature', 'payload', 'raw_body'],
    ),
]], function ($router) {
    $router->post('/stripe', [WebhookController::class, 'stripe']);
    $router->post('/github', [WebhookController::class, 'github']);
});
```

---

## CDN Integration

Behind Cloudflare or AWS:

```php
use Lalaz\Waf\Middlewares\TrustedProxyMiddleware;
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\IpFilterMiddleware;

// Cloudflare setup
$router->middleware(TrustedProxyMiddleware::forCloudflare());

// AWS ALB setup
$router->middleware(TrustedProxyMiddleware::forAwsAlb());

// Custom proxy setup
$trustedProxyMiddleware = new TrustedProxyMiddleware(
    trustedProxies: [
        '10.0.0.0/8',      // Internal network
        '172.16.0.0/12',   // Private network
        '192.168.0.0/16',  // Private network
    ],
    trustedHeaders: [
        'X-Forwarded-For',
        'X-Forwarded-Proto',
        'X-Forwarded-Host',
        'X-Real-IP',
    ],
);

// Rate limiting will now use the real client IP
$router->group(['middleware' => [
    $trustedProxyMiddleware,
    RateLimitMiddleware::perMinute(60),
]], function ($router) {
    // Routes...
});
```

---

## Complete Application Example

Full application security setup:

```php
// bootstrap/security.php

use Lalaz\Waf\Middlewares\TrustedProxyMiddleware;
use Lalaz\Waf\Middlewares\IpFilterMiddleware;
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\HttpMethodMiddleware;
use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Middlewares\CorsMiddleware;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\RedisStore;
use Lalaz\Waf\IpFilter\IpList;

// Initialize rate limiter with Redis
$rateLimitStore = new RedisStore($container->get('redis'), 'rate:');
$rateLimiter = new RateLimiter($rateLimitStore);

// Load blacklist from database
$blacklist = new IpList(
    ips: DB::table('ip_blacklist')->pluck('ip')->toArray(),
    onAdd: fn($ip) => DB::table('ip_blacklist')->insert([
        'ip' => $ip,
        'created_at' => now(),
    ]),
);

// Global middleware (applied to all routes)
$globalMiddleware = [
    // 1. Resolve real IP from CDN
    TrustedProxyMiddleware::forCloudflare(),
    
    // 2. Block known bad actors
    new IpFilterMiddleware(blacklist: $blacklist, mode: 'blacklist'),
];

// Web middleware (browser requests)
$webMiddleware = [
    GeoBlockMiddleware::allowOnly(['US', 'CA', 'GB', 'DE', 'FR']),
    RateLimitMiddleware::perMinute(60),
    RequestSizeLimiterMiddleware::forApi(),
    SanitizationMiddleware::strict(),
    HelmetMiddleware::strict(),
];

// API middleware (programmatic access)
$apiMiddleware = [
    RateLimitMiddleware::perMinute(100),
    RequestSizeLimiterMiddleware::forApi(),
    HttpMethodMiddleware::restful(),
    SanitizationMiddleware::forApi(),
    HelmetMiddleware::api(),
    CorsMiddleware::strict(config('app.frontend_url')),
];

// Auth middleware (login/register)
$authMiddleware = [
    new RateLimitMiddleware(
        limiter: $rateLimiter,
        maxAttempts: 5,
        decaySeconds: 300,
        keyResolver: fn($req) => 'auth:' . $req->getServerParams()['REMOTE_ADDR'],
    ),
    SanitizationMiddleware::strict(),
];

// Admin middleware (admin panel)
$adminMiddleware = [
    IpFilterMiddleware::whitelist(config('admin.allowed_ips')),
    RateLimitMiddleware::perMinute(30),
    SanitizationMiddleware::strict(),
    HelmetMiddleware::strict(),
];

// Register middleware groups
$router->middlewareGroup('global', $globalMiddleware);
$router->middlewareGroup('web', $webMiddleware);
$router->middlewareGroup('api', $apiMiddleware);
$router->middlewareGroup('auth', $authMiddleware);
$router->middlewareGroup('admin', $adminMiddleware);
```

## Next Steps

- [Concepts](../concepts.md) — Understand the architecture
- [API Reference](../api-reference.md) — Complete API documentation
- [Middlewares](../middlewares/index.md) — All available middlewares
