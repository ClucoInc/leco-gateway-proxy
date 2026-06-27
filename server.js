// ─────────────────────────────────────────────────────────────────────────────
// LECO local gateway proxy — validates Cognito JWT, resolves tenant from
// subdomain or JWT claim, injects X-Tenant-Id / X-User-* / X-Request-Id headers.
// ─────────────────────────────────────────────────────────────────────────────
import express from 'express'
import { randomUUID, timingSafeEqual } from 'crypto'
import { createProxyMiddleware } from 'http-proxy-middleware'
import { createRemoteJWKSet, jwtVerify } from 'jose'

const APPCONFIG_URL = 'http://localhost:2772';
const APPCONFIG_PATH = process.env.APPCONFIG_PATH || '/applications/leco-prod-platform/environments/prod/configurations';

async function getDynamicConfig(profile) {
  try {
    const resp = await fetch(`${APPCONFIG_URL}${APPCONFIG_PATH}/${profile}`);
    return resp.ok ? await resp.json() : {};
  } catch { return {}; }
}

const PORT = Number(process.env.PORT || 8080)
const REGION = process.env.AWS_REGION || 'us-east-1'
const IS_PRODUCTION = process.env.NODE_ENV === 'production'
const POOL = process.env.COGNITO_USER_POOL_ID
const PLATFORM_POOL = process.env.PLATFORM_COGNITO_USER_POOL_ID || POOL
const ISSUER = POOL ? `https://cognito-idp.${REGION}.amazonaws.com/${POOL}` : null
const PLATFORM_ISSUER = PLATFORM_POOL
  ? `https://cognito-idp.${REGION}.amazonaws.com/${PLATFORM_POOL}`
  : null
const JWKS = ISSUER ? createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`)) : null
const PLATFORM_JWKS = PLATFORM_ISSUER
  ? createRemoteJWKSet(new URL(`${PLATFORM_ISSUER}/.well-known/jwks.json`))
  : JWKS
const INTERNAL_AUTH = process.env.INTERNAL_AUTH_SECRET || ''
const BASE_DOMAIN = process.env.BASE_DOMAIN || 'cluco.ai'
const BASE_DOMAIN_PARTS = BASE_DOMAIN.split('.')
const DEFAULT_TENANT_ID = process.env.DEFAULT_TENANT_ID || 'default-tenant'
const TENANT_AUTH_CACHE_MS = +(process.env.AUTH_CONFIG_CACHE_MS || 300000)
const TENANT_STATUS_CACHE_MS = +(process.env.TENANT_STATUS_CACHE_MS || 30000)
const TENANT_RATE_LIMIT_WINDOW_MS = +(process.env.RATE_LIMIT_WINDOW_MS || 60000)
const TENANT_RATE_LIMIT_MAX = Number(process.env.TENANT_RATE_LIMIT_MAX || 600)

const SVC = {
  user: process.env.USER_SERVICE_URL || 'http://user-service:9001',
  case: process.env.CASE_SERVICE_URL || 'http://case-service:9002',
  intake: process.env.INTAKE_SERVICE_URL || 'http://client-intake-service:9003',
  notification: process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:9004',
  demandDraft: process.env.DEMAND_DRAFT_URL || 'http://demand-draft:8003',
  controlPlane: process.env.CONTROL_PLANE_URL || 'http://control-plane:9010',
}

function constantTimeSecretMatch(provided) {
  if (!provided || !INTERNAL_AUTH) return false
  const a = Buffer.from(INTERNAL_AUTH, 'utf8')
  const b = Buffer.from(provided, 'utf8')
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

const app = express()

app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ limit: '10mb', extended: true }))

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

const emailToId = new Map()
const slugToTenantId = new Map()
const tenantAuthConfigCache = new Map()
const tenantJwksByIssuer = new Map()
const tenantStatusCache = new Map()
const tenantRateLimits = new Map()
const customDomainCache = new Map()

async function refreshCustomDomainMappings() {
  try {
    const resp = await fetch(`${SVC.controlPlane}/api/internal/domain-mappings`, {
      headers: { 'X-Internal-Auth': INTERNAL_AUTH },
    })
    if (resp.ok) {
      const mappings = await resp.json()
      customDomainCache.clear()
      const data = mappings.data || mappings
      if (data && typeof data === 'object') {
        for (const [domain, slug] of Object.entries(data)) {
          customDomainCache.set(domain, slug)
        }
      }
    }
  } catch (e) {
    console.warn('[proxy] custom domain refresh failed:', e.message)
  }
}
setInterval(refreshCustomDomainMappings, 5 * 60 * 1000)

function defaultTenantIdOrNull() {
  return IS_PRODUCTION ? null : DEFAULT_TENANT_ID
}

function unwrapApiResponse(payload) {
  return payload?.data ?? payload
}

function extractSubdomain(host) {
  if (!host) return null
  const h = host.split(':')[0]
  const parts = h.split('.')
  if (parts.length > BASE_DOMAIN_PARTS.length && parts.slice(-BASE_DOMAIN_PARTS.length).join('.') === BASE_DOMAIN) {
    return parts[0]
  }
  const customSlug = customDomainCache.get(h)
  if (customSlug) return customSlug
  return null
}

async function resolveTenantId(req, payload) {
  const fromJwt = payload['custom:tenantId']
  if (fromJwt) {
    const configTenantId = req._tenantAuthConfig?.tenantId
    if (configTenantId && configTenantId !== fromJwt) {
      throw new Error(`Tenant ID mismatch: JWT claims ${fromJwt} but auth config expects ${configTenantId}`)
    }
    return fromJwt
  }

  if (req._tenantAuthConfig?.tenantId) return req._tenantAuthConfig.tenantId

  const slug =
    req._tenantAuthConfig?.slug || extractSubdomain(req.headers['x-forwarded-host'] || req.headers.host)
  if (!slug || slug === 'admin' || slug === 'www') {
    const fallback = defaultTenantIdOrNull()
    if (fallback) return fallback
    throw new Error('Tenant slug missing and no production fallback is allowed')
  }

  if (slugToTenantId.has(slug)) return slugToTenantId.get(slug)

  try {
    const resp = await fetch(`${SVC.user}/organizations/slug/${slug}`, {
      headers: { 'X-Internal-Auth': INTERNAL_AUTH },
    })
    if (resp.ok) {
      const data = await resp.json()
      const tenantId = data?.data?.tenantId || data?.tenantId
      if (tenantId) {
        slugToTenantId.set(slug, tenantId)
        return tenantId
      }
    }
  } catch (e) {
    console.warn('[proxy] tenant lookup failed:', e.message)
  }
  const fallback = defaultTenantIdOrNull()
  if (fallback) return fallback
  throw new Error(`Tenant resolution failed for slug "${slug}"`)
}

const userActiveCache = new Map()
const USER_ACTIVE_CACHE_MS = +(process.env.USER_ACTIVE_CACHE_MS || 60000)

async function checkUserActive(userId, tenantId) {
  const cacheKey = `active:${tenantId}:${userId}`
  const cached = userActiveCache.get(cacheKey)
  if (cached && cached.expiresAt > Date.now()) {
    if (!cached.active) throw new Error('User account is deactivated')
    return
  }
  try {
    const resp = await fetch(`${SVC.user}/users/${userId}`, {
      headers: { 'X-Internal-Auth': INTERNAL_AUTH, 'X-Tenant-Id': tenantId },
    })
    if (resp.ok) {
      const data = await resp.json()
      const user = data?.data ?? data
      const active = user?.active !== false
      userActiveCache.set(cacheKey, { active, expiresAt: Date.now() + USER_ACTIVE_CACHE_MS })
      if (!active) throw new Error('User account is deactivated')
    }
  } catch (e) {
    if (e.message === 'User account is deactivated') throw e
    // If the check fails for connectivity reasons, allow the request through
    console.warn('[proxy] active-check failed:', e.message)
  }
}

async function resolveLocalUserId(payload, tenantId) {
  const email = payload.email
  if (!email) throw new Error('token has no email claim')

  // Story 2.6: Prefer appUserId from JWT claim when present (set by PostConfirmation Lambda)
  const jwtAppUserId = payload['custom:appUserId']
  if (jwtAppUserId && jwtAppUserId !== 'undefined' && jwtAppUserId.trim() !== '') {
    const cacheKey = `${tenantId}:${email}`
    emailToId.set(cacheKey, jwtAppUserId)
    return jwtAppUserId
  }

  // Fallback: call user-service create-and-return (for legacy users without the claim)
  const cacheKey = `${tenantId}:${email}`
  if (emailToId.has(cacheKey)) return emailToId.get(cacheKey)
  const resp = await fetch(`${SVC.user}/users/internal/create-and-return`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERNAL_AUTH },
    body: JSON.stringify({
      email,
      firstName: payload.given_name || payload.name || email.split('@')[0],
      lastName: payload.family_name || '-',
      tenantId,
    }),
  })
  if (!resp.ok) throw new Error(`user-service create-and-return ${resp.status}`)
  const data = await resp.json()
  const id = String(data?.data?.id ?? data?.id ?? '')
  if (!id) throw new Error('user-service returned no id')
  emailToId.set(cacheKey, id)
  return id
}

function isPlatformAdmin(payload) {
  const role = payload['custom:role'] || payload['custom:orgRole']
  if (role === 'PLATFORM_ADMIN') return true
  const groups = payload['cognito:groups']
  return Array.isArray(groups) && groups.includes('PLATFORM_ADMIN')
}

function isTenantAdmin(payload) {
  const role = payload['custom:role'] || payload['custom:orgRole']
  if (role === 'TENANT_ADMIN') return true
  const groups = payload['cognito:groups']
  return Array.isArray(groups) && groups.includes('TENANT_ADMIN')
}

async function verifyToken(token, jwks, issuer, expectedAudience) {
  const opts = { issuer }
  if (expectedAudience) {
    opts.audience = expectedAudience
  }
  const { payload } = await jwtVerify(token, jwks, opts)
  return payload
}

async function checkTenantStatus(slug) {
  if (!slug) return
  const cached = tenantStatusCache.get(slug)
  if (cached && cached.expiresAt > Date.now()) {
    if (cached.status && cached.status !== 'ACTIVE') {
      throw new Error(`Tenant ${slug} is ${cached.status}`)
    }
    return
  }
  try {
    const resp = await fetch(`${SVC.controlPlane}/api/tenants/${encodeURIComponent(slug)}/auth-config`, {
      headers: { 'X-Internal-Auth': INTERNAL_AUTH },
    })
    if (resp.ok) {
      const data = unwrapApiResponse(await resp.json())
      tenantStatusCache.set(slug, { status: data?.status || 'ACTIVE', expiresAt: Date.now() + TENANT_STATUS_CACHE_MS })
    } else if (resp.status === 403) {
      const data = await resp.json().catch(() => ({}))
      const body = data?.data ?? data
      const tenantStatus = body?.tenantStatus || 'UNAVAILABLE'
      tenantStatusCache.set(slug, { status: tenantStatus, expiresAt: Date.now() + TENANT_STATUS_CACHE_MS })
      throw new Error(`Tenant ${slug} is ${tenantStatus}`)
    }
  } catch (e) {
    if (e.message?.startsWith('Tenant ')) throw e
    throw new Error('Tenant status check unavailable')
  }
}

function checkTenantRateLimit(tenantId, perTenantMax) {
  const max = perTenantMax || TENANT_RATE_LIMIT_MAX
  const now = Date.now()
  let bucket = tenantRateLimits.get(tenantId)
  if (!bucket || bucket.windowStart + TENANT_RATE_LIMIT_WINDOW_MS < now) {
    bucket = { windowStart: now, count: 0 }
    tenantRateLimits.set(tenantId, bucket)
  }
  bucket.count++
  if (bucket.count > max) {
    throw new Error('Rate limit exceeded')
  }
}

async function fetchTenantAuthConfig(slug) {
  const cached = tenantAuthConfigCache.get(slug)
  if (cached && cached.expiresAt > Date.now()) return cached.value

  const resp = await fetch(`${SVC.controlPlane}/api/tenants/${encodeURIComponent(slug)}/auth-config`, {
    headers: { 'X-Internal-Auth': INTERNAL_AUTH },
  })
  if (!resp.ok) {
    throw new Error(`auth-config fetch failed for "${slug}" (${resp.status})`)
  }

  const data = unwrapApiResponse(await resp.json())
  if (!data?.cognitoPoolId || !data?.region) {
    throw new Error(`auth-config for "${slug}" is missing Cognito pool/region`)
  }

  const normalized = {
    tenantId: data.tenantId || null,
    slug: data.slug || slug,
    status: data.status || 'ACTIVE',
    cognitoPoolId: data.cognitoPoolId,
    cognitoClientId: data.cognitoClientId || null,
    region: data.region,
    signupAllowed: data.signupAllowed !== false,
    inviteOnly: Boolean(data.inviteOnly),
    federationOnly: Boolean(data.federationOnly),
    federatedProviders: Array.isArray(data.federatedProviders) ? data.federatedProviders : [],
    maxApiCallsPerMinute: data.maxApiCallsPerMinute || data.planLimits?.maxApiCallsPerMinute || null,
  }
  tenantAuthConfigCache.set(slug, { value: normalized, expiresAt: Date.now() + TENANT_AUTH_CACHE_MS })
  return normalized
}

function getTenantIssuer(authConfig) {
  if (!authConfig?.region || !authConfig?.cognitoPoolId) return null
  return `https://cognito-idp.${authConfig.region}.amazonaws.com/${authConfig.cognitoPoolId}`
}

function getTenantJwks(issuer) {
  if (!issuer) return null
  if (!tenantJwksByIssuer.has(issuer)) {
    tenantJwksByIssuer.set(issuer, createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`)))
  }
  return tenantJwksByIssuer.get(issuer)
}

async function resolveTenantAuthConfig(req) {
  const slug = extractSubdomain(req.headers['x-forwarded-host'] || req.headers.host)
  if (slug && slug !== 'admin' && slug !== 'www') {
    return fetchTenantAuthConfig(slug)
  }

  if (!IS_PRODUCTION && POOL) {
    return {
      tenantId: defaultTenantIdOrNull(),
      slug: slug || null,
      cognitoPoolId: POOL,
      cognitoClientId: process.env.COGNITO_CLIENT_ID || null,
      region: REGION,
      federatedProviders: [],
    }
  }
  throw new Error('Tenant slug is required for production tenant authentication')
}

function extractRole(payload) {
  return payload['custom:role'] || payload['custom:orgRole'] || 'USER'
}

async function authenticateViaApiKey(req) {
  const apiKey = req.headers['x-api-key'] || ''
  const authHeader = req.headers.authorization || ''
  const rawKey = apiKey || (authHeader.startsWith('Bearer leco_') ? authHeader.slice(7) : null)
  if (!rawKey) return false

  const resp = await fetch(`${SVC.controlPlane}/api/internal/api-keys/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERNAL_AUTH },
    body: JSON.stringify({ rawKey }),
  })
  if (!resp.ok) return false
  const data = await resp.json()
  const keyData = data?.data ?? data
  if (!keyData?.tenantId) return false

  req._requestId = req.headers['x-request-id'] || randomUUID()
  req._tenantId = keyData.tenantId
  req._email = 'api-key:' + (keyData.keyPrefix || 'unknown')
  req._role = 'API_KEY'
  req._localUserId = null
  return true
}

async function authenticateRequest(req) {
  if (await authenticateViaApiKey(req)) return

  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  if (!token) throw new Error('Missing Authorization bearer token')

  const authConfig = await resolveTenantAuthConfig(req)
  const issuer = getTenantIssuer(authConfig)
  const jwks = getTenantJwks(issuer)
  if (!jwks || !issuer) throw new Error('Tenant Cognito not configured')

  const payload = await verifyToken(token, jwks, issuer, authConfig.cognitoClientId)

  const slug = authConfig.slug
  if (slug) await checkTenantStatus(slug)

  req._requestId = req.headers['x-request-id'] || randomUUID()
  req._tenantAuthConfig = authConfig
  req._tenantId = await resolveTenantId(req, payload)

  checkTenantRateLimit(req._tenantId, authConfig.maxApiCallsPerMinute)

  req._localUserId = await resolveLocalUserId(payload, req._tenantId)
  req._email = payload.email || ''
  req._role = extractRole(payload)

  // Auto-accept pending invitation on first authenticated request (fire-and-forget).
  if (req._email) {
    fetch(`${SVC.controlPlane}/api/internal/invitations/accept-by-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERNAL_AUTH },
      body: JSON.stringify({ email: req._email }),
    }).catch(() => {})
  }

  // Story 2.8: Enforce active flag — reject deactivated users
  await checkUserActive(req._localUserId, req._tenantId)
}

async function authenticate(req, res, next) {
  try {
    await authenticateRequest(req)
    next()
  } catch (e) {
    console.error('[proxy] auth failed:', e.message)
    if (e.message === 'User account is deactivated') {
      return res.status(403).json({ message: 'Your account has been deactivated', code: 'USER_DEACTIVATED' })
    }
    if (e.message?.startsWith('Tenant ')) {
      return res.status(403).json({ message: 'Account is not active', code: 'TENANT_UNAVAILABLE' })
    }
    if (e.message === 'Rate limit exceeded') {
      return res.status(429).json({ message: 'Too many requests' })
    }
    if (e.message === 'Tenant status check unavailable') {
      return res.status(503).json({ message: 'Service temporarily unavailable' })
    }
    const status = e.message?.includes('Missing Authorization') ? 401 : 401
    return res.status(status).json({ message: 'Invalid or expired token' })
  }
}

async function tenantAdminOnly(req, res, next) {
  try {
    await authenticateRequest(req)
    if (req._role !== 'TENANT_ADMIN') {
      return res.status(403).json({ message: 'TENANT_ADMIN role required' })
    }
    next()
  } catch (e) {
    console.error('[proxy] tenant admin auth failed:', e.message)
    if (e.message === 'User account is deactivated') {
      return res.status(403).json({ message: 'Your account has been deactivated', code: 'USER_DEACTIVATED' })
    }
    if (e.message?.startsWith('Tenant ')) {
      return res.status(403).json({ message: 'Account is not active', code: 'TENANT_UNAVAILABLE' })
    }
    if (e.message === 'Rate limit exceeded') {
      return res.status(429).json({ message: 'Too many requests' })
    }
    if (e.message === 'Tenant status check unavailable') {
      return res.status(503).json({ message: 'Service temporarily unavailable' })
    }
    return res.status(401).json({ message: 'Invalid or expired token' })
  }
}

async function platformAdminOnly(req, res, next) {
  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  if (!token) return res.status(401).json({ message: 'Missing Authorization bearer token' })
  if (!PLATFORM_JWKS || !PLATFORM_ISSUER) {
    return res.status(503).json({ message: 'Platform Cognito not configured' })
  }
  try {
    const payload = await verifyToken(token, PLATFORM_JWKS, PLATFORM_ISSUER)
    if (!isPlatformAdmin(payload)) {
      return res.status(403).json({ message: 'PLATFORM_ADMIN role required' })
    }
    req._requestId = req.headers['x-request-id'] || randomUUID()
    req._email = payload.email || ''
    req._role = 'PLATFORM_ADMIN'
    next()
  } catch (e) {
    console.error('[proxy] platform auth failed:', e.message)
    return res.status(401).json({ message: 'Invalid or expired token' })
  }
}

function controlPlaneProxy() {
  return createProxyMiddleware({
    target: SVC.controlPlane,
    changeOrigin: true,
    proxyTimeout: 120000,
    timeout: 120000,
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Internal-Auth', INTERNAL_AUTH)
      proxyReq.setHeader('X-Request-Id', req._requestId || randomUUID())
      if (req._email) proxyReq.setHeader('X-Platform-Admin-Email', req._email)
      if (req._role) proxyReq.setHeader('X-Platform-Admin-Role', req._role)
      const auth = req.headers.authorization
      if (auth) proxyReq.setHeader('Authorization', auth)
    },
    onError: (err, _req, res) => {
      console.error('[proxy] control-plane error:', err.message)
      if (!res.headersSent) res.status(502).json({ message: 'Control plane unavailable' })
    },
  })
}

function gateway(target, stripRe) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathRewrite: { [stripRe]: '' },
    proxyTimeout: 3600000,
    timeout: 3600000,
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Internal-Auth', INTERNAL_AUTH)
      proxyReq.setHeader('X-Request-Id', req._requestId || randomUUID())
      if (req._tenantId) proxyReq.setHeader('X-Tenant-Id', req._tenantId)
      if (req._localUserId) {
        proxyReq.setHeader('X-User-Id', req._localUserId)
        proxyReq.setHeader('X-User-Email', req._email || '')
        proxyReq.setHeader('X-User-Role', req._role || 'USER')
      }
    },
    onError: (err, _req, res) => {
      console.error('[proxy] upstream error:', err.message)
      if (!res.headersSent) res.status(502).json({ message: 'Upstream unavailable' })
    },
  })
}

const CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean)

function isAllowedOrigin(origin) {
  if (!origin) return false
  if (!IS_PRODUCTION) return true
  if (CORS_ALLOWED_ORIGINS.length > 0) {
    return CORS_ALLOWED_ORIGINS.some(allowed => {
      if (allowed.startsWith('https://*.')) {
        const suffix = allowed.slice('https://'.length)
        return origin.endsWith(suffix) || origin === `https://${suffix.slice(1)}`
      }
      return origin === allowed
    })
  }
  return origin.endsWith('.' + BASE_DOMAIN) || origin === 'https://' + BASE_DOMAIN
}

app.use((req, res, next) => {
  req._requestId = req.headers['x-request-id'] || randomUUID()
  const origin = req.headers.origin
  if (origin && isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Access-Control-Allow-Credentials', 'true')
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Request-Id')
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204)
  }
  console.log(`[proxy] ${req.method} ${req.url} rid=${req._requestId}`)
  next()
})

app.get('/health', (_req, res) => res.json({ status: 'ok' }))

// Public tenant auth bootstrap (no JWT)
app.get('/api/tenants/:slug/auth-config', controlPlaneProxy())

// Internal usage ingestion (usage-agent)
app.post('/api/usage', (req, res, next) => {
  const secret = req.headers['x-internal-auth']
  if (!constantTimeSecretMatch(secret)) {
    return res.status(401).json({ message: 'Invalid internal auth' })
  }
  next()
}, controlPlaneProxy())

// Internal provisioning callback
app.post('/api/internal/provisioning/callback', (req, res, next) => {
  const secret = req.headers['x-internal-auth']
  if (!constantTimeSecretMatch(secret)) {
    return res.status(401).json({ message: 'Invalid internal auth' })
  }
  next()
}, controlPlaneProxy())

// Stripe webhook (no platform JWT)
app.post('/api/billing/stripe/webhook', controlPlaneProxy())

// Platform admin routes (PLATFORM_ADMIN JWT required)
const platformRoutes = [
  '/api/tenants',
  '/api/health',
  '/api/billing',
  '/api/audit',
  '/api/provisioning',
]
for (const prefix of platformRoutes) {
  app.use(prefix, platformAdminOnly, controlPlaneProxy())
}

app.use('/api/ai/autocomplete', authenticate, gateway(SVC.demandDraft, '^/api/ai/autocomplete'))
app.use('/api/intake', gateway(SVC.intake, '^/api'))
app.use('/api/demand-draft', authenticate, gateway(SVC.demandDraft, '^/api/demand-draft'))

app.use('/api/users', authenticate, gateway(SVC.user, '^/api'))
app.use(['/api/cases', '/api/documents', '/api/drafts', '/api/ai', '/api/calendar'],
  authenticate, gateway(SVC.case, '^/api'))
app.use('/api/notifications', authenticate, gateway(SVC.notification, '^/api'))
// Tenant-admin user management → control plane (TenantOpsController). The
// user-service /admin/* endpoints are not present in all service image
// versions, so route firm-user management through the control plane like the
// dashboard/invitations routes do (it syncs the firm's users from Cognito).
app.get('/api/admin/users', tenantAdminOnly, async (req, res) => {
  try {
    const r = await cpFetch(`/api/tenants/${req._tenantId}/users`)
    res.status(r.ok ? 200 : r.status).json({ data: Array.isArray(r.data) ? r.data : [] })
  } catch (e) {
    console.error('[proxy] admin users list error:', e.message)
    res.status(502).json({ message: 'Unable to load users' })
  }
})

app.post('/api/admin/users', tenantAdminOnly, async (req, res) => {
  // "Add user" === create an invitation (Cognito sends the invite email).
  try {
    const r = await cpFetch(`/api/tenants/${req._tenantId}/invitations`, {
      method: 'POST', body: JSON.stringify(req.body || {}),
    })
    res.status(r.ok ? 200 : r.status).json({ data: r.data })
  } catch (e) {
    console.error('[proxy] admin create user error:', e.message)
    res.status(502).json({ message: 'Unable to create user' })
  }
})

app.delete('/api/admin/users', tenantAdminOnly, async (req, res) => {
  try {
    const userId = req.query.id
    if (!userId) return res.status(400).json({ message: 'user id required' })
    const r = await cpFetch(`/api/tenants/${req._tenantId}/users/${userId}/status`, {
      method: 'PUT', body: JSON.stringify({ status: 'DEACTIVATED' }),
    })
    res.status(r.ok ? 200 : r.status).json({ data: r.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to deactivate user' })
  }
})

app.put('/api/admin/users/:userId/reactivate', tenantAdminOnly, async (req, res) => {
  try {
    const r = await cpFetch(`/api/tenants/${req._tenantId}/users/${req.params.userId}/status`, {
      method: 'PUT', body: JSON.stringify({ status: 'ACTIVE' }),
    })
    res.status(r.ok ? 200 : r.status).json({ data: r.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to reactivate user' })
  }
})

app.put('/api/admin/users/:userId/role', tenantAdminOnly, async (req, res) => {
  try {
    const r = await cpFetch(`/api/tenants/${req._tenantId}/users/${req.params.userId}/status`, {
      method: 'PUT', body: JSON.stringify({ role: req.body?.role }),
    })
    res.status(r.ok ? 200 : r.status).json({ data: r.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to update role' })
  }
})

// ── Tenant admin routes delegating to control plane ─────────────────────────

async function cpFetch(path, opts = {}) {
  const url = `${SVC.controlPlane}${path}`
  const headers = { 'Content-Type': 'application/json', 'X-Internal-Auth': INTERNAL_AUTH, ...opts.headers }
  const resp = await fetch(url, { ...opts, headers })
  const body = await resp.json().catch(() => ({}))
  return { ok: resp.ok, status: resp.status, data: body?.data ?? body }
}

app.get('/api/admin/dashboard', tenantAdminOnly, async (req, res) => {
  try {
    const tenantId = req._tenantId
    const [tenantRes, quotaRes, alertsRes] = await Promise.all([
      cpFetch(`/api/tenants/${tenantId}`),
      cpFetch(`/api/tenants/${tenantId}/quota`),
      cpFetch(`/api/tenants/${tenantId}/quota/alerts`),
    ])
    const tenant = tenantRes.data || {}
    const quota = quotaRes.data || {}
    const usage = quota.usage || {}
    const alerts = Array.isArray(alertsRes.data) ? alertsRes.data : []
    res.json({ data: {
      firmName: tenant.name || '—',
      slug: tenant.slug,
      status: tenant.status,
      planName: tenant.plan || 'FREE',
      activeUsers: usage.users ?? 0,
      totalUsers: usage.seats ?? usage.users ?? 0,
      trialEndsAt: tenant.trialEndsAt || null,
      limits: quota.limits || {},
      usage: {
        users: usage.users ?? 0,
        seats: usage.seats ?? 0,
        cases: usage.cases ?? 0,
        storageBytes: usage.storage ?? 0,
        storageGb: usage.storage ? +(usage.storage / (1024 * 1024 * 1024)).toFixed(2) : 0,
        aiJobs: usage.ai_api_calls ?? 0,
      },
      alerts,
    }})
  } catch (e) {
    console.error('[proxy] admin dashboard error:', e.message)
    res.status(502).json({ message: 'Unable to load dashboard' })
  }
})

app.get('/api/admin/usage', tenantAdminOnly, async (req, res) => {
  try {
    const quotaRes = await cpFetch(`/api/tenants/${req._tenantId}/quota`)
    const q = quotaRes.data || {}
    const usage = q.usage || {}
    res.json({ data: {
      limits: q.limits || {},
      current: {
        users: usage.users ?? 0,
        cases: usage.cases ?? 0,
        storageGb: usage.storage ? +(usage.storage / (1024 * 1024 * 1024)).toFixed(2) : 0,
        aiJobs: usage.ai_api_calls ?? 0,
      },
      plan: q.plan || 'FREE',
      withinLimits: q.withinLimits || {},
    }})
  } catch (e) {
    res.status(502).json({ message: 'Unable to load usage' })
  }
})

app.get('/api/admin/billing', tenantAdminOnly, async (req, res) => {
  try {
    const [invoicesRes, subRes, tenantRes] = await Promise.all([
      cpFetch(`/api/billing/tenants/${req._tenantId}/invoices`),
      cpFetch(`/api/billing/tenants/${req._tenantId}/subscription`),
      cpFetch(`/api/tenants/${req._tenantId}`),
    ])
    const tenant = tenantRes.data || {}
    res.json({ data: {
      planName: tenant.plan || 'FREE',
      billingCycle: 'monthly',
      invoices: Array.isArray(invoicesRes.data) ? invoicesRes.data : [],
      subscription: subRes.data || null,
      trialEndsAt: tenant.trialEndsAt || null,
    }})
  } catch (e) {
    res.status(502).json({ message: 'Unable to load billing' })
  }
})

app.use('/api/admin/billing/checkout', express.json())
app.post('/api/admin/billing/checkout', tenantAdminOnly, async (req, res) => {
  try {
    const checkoutRes = await cpFetch(`/api/billing/tenants/${req._tenantId}/checkout-session`, {
      method: 'POST',
      body: JSON.stringify(req.body),
    })
    if (!checkoutRes.ok) return res.status(checkoutRes.status).json(checkoutRes.data)
    res.json({ data: checkoutRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to create checkout session' })
  }
})

app.use('/api/admin/billing/portal', express.json())
app.post('/api/admin/billing/portal', tenantAdminOnly, async (req, res) => {
  try {
    const portalRes = await cpFetch(`/api/billing/tenants/${req._tenantId}/portal-session`, {
      method: 'POST',
      body: JSON.stringify(req.body || { returnUrl: req.headers.referer || (process.env.APP_BASE_URL || `https://app.${BASE_DOMAIN}`) + '/admin/billing' }),
    })
    if (!portalRes.ok) return res.status(portalRes.status).json(portalRes.data)
    res.json({ data: portalRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to create portal session' })
  }
})

app.get('/api/admin/audit', tenantAdminOnly, async (req, res) => {
  try {
    const params = new URLSearchParams()
    params.set('tenantId', req._tenantId)
    if (req.query.action) params.set('action', req.query.action)
    if (req.query.from) params.set('from', req.query.from)
    if (req.query.to) params.set('to', req.query.to)
    const auditRes = await cpFetch(`/api/audit?${params}`)
    res.json({ data: Array.isArray(auditRes.data) ? auditRes.data : [] })
  } catch (e) {
    res.status(502).json({ message: 'Unable to load audit log' })
  }
})

app.get('/api/admin/settings', tenantAdminOnly, async (req, res) => {
  try {
    const [tenantRes, brandingRes] = await Promise.all([
      cpFetch(`/api/tenants/${req._tenantId}`),
      cpFetch(`/api/tenants/${req._tenantId}/branding`),
    ])
    const tenant = tenantRes.data || {}
    const settings = tenant.settings || {}
    res.json({ data: {
      firmName: tenant.name || '',
      slug: tenant.slug || '',
      plan: tenant.plan || 'FREE',
      address: settings.address || '',
      customDomain: settings.customDomain || tenant.sesDomain || '',
      primaryColor: (brandingRes.data || {}).primaryColor || '#1e3a5f',
      logoUrl: (brandingRes.data || {}).logoUrl || '',
      mfaRequired: Boolean(settings.mfaRequired),
      sessionTimeoutMinutes: settings.sessionTimeoutMinutes || 60,
      inviteOnly: Boolean(settings.inviteOnly),
      federationOnly: Boolean(settings.federationOnly),
      allowedEmailDomains: settings.allowedEmailDomains || [],
    }})
  } catch (e) {
    res.status(502).json({ message: 'Unable to load settings' })
  }
})

app.use('/api/admin/settings', express.json())
app.put('/api/admin/settings', tenantAdminOnly, async (req, res) => {
  try {
    const body = req.body || {}
    const settingsUpdate = {}
    if (body.address !== undefined) settingsUpdate.address = body.address
    if (body.customDomain !== undefined) settingsUpdate.customDomain = body.customDomain
    if (body.mfaRequired !== undefined) settingsUpdate.mfaRequired = body.mfaRequired
    if (body.sessionTimeoutMinutes !== undefined) settingsUpdate.sessionTimeoutMinutes = body.sessionTimeoutMinutes
    if (body.inviteOnly !== undefined) settingsUpdate.inviteOnly = body.inviteOnly
    if (body.federationOnly !== undefined) settingsUpdate.federationOnly = body.federationOnly
    if (body.allowedEmailDomains !== undefined) settingsUpdate.allowedEmailDomains = body.allowedEmailDomains
    const settingsRes = await cpFetch(`/api/tenants/${req._tenantId}/settings`, {
      method: 'PUT',
      body: JSON.stringify(settingsUpdate),
    })
    if (body.firmName) {
      await cpFetch(`/api/tenants/${req._tenantId}`, {
        method: 'PUT',
        body: JSON.stringify({ name: body.firmName }),
      })
    }
    if (body.primaryColor || body.logoUrl || body.companyName || body.supportEmail) {
      const brandingUpdate = {}
      if (body.primaryColor) brandingUpdate.primaryColor = body.primaryColor
      if (body.logoUrl) brandingUpdate.logoUrl = body.logoUrl
      if (body.companyName) brandingUpdate.companyName = body.companyName
      if (body.supportEmail) brandingUpdate.supportEmail = body.supportEmail
      await cpFetch(`/api/tenants/${req._tenantId}/branding`, {
        method: 'PUT',
        body: JSON.stringify(brandingUpdate),
      })
    }
    res.json({ data: settingsRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to save settings' })
  }
})

app.get('/api/admin/integrations', tenantAdminOnly, async (req, res) => {
  try {
    const [identRes, tenantRes] = await Promise.all([
      cpFetch(`/api/tenants/${req._tenantId}/identity`),
      cpFetch(`/api/tenants/${req._tenantId}`),
    ])
    const data = identRes.data || {}
    const tenant = tenantRes.data || {}
    const settings = tenant.settings || {}
    res.json({ data: {
      ssoEnabled: (data.federatedProviders || []).length > 0,
      samlConfig: data.samlConfig || {},
      federatedProviders: data.federatedProviders || [],
      cognitoPoolId: data.cognitoPoolId || null,
      cognitoRegion: data.cognitoRegion || null,
      idpMetadataUrl: (data.samlConfig || {}).metadataUrl || '',
      webhookUrl: settings.webhookUrl || '',
    }})
  } catch (e) {
    res.status(502).json({ message: 'Unable to load integrations' })
  }
})

app.use('/api/admin/integrations', express.json())
app.put('/api/admin/integrations', tenantAdminOnly, async (req, res) => {
  try {
    const body = req.body || {}
    if (body.idpMetadataUrl || body.providerName) {
      const samlRes = await cpFetch(`/api/tenants/${req._tenantId}/identity/saml`, {
        method: 'PUT',
        body: JSON.stringify({
          providerName: body.providerName || 'SAML',
          metadataUrl: body.idpMetadataUrl || '',
        }),
      })
      if (!samlRes.ok) return res.status(samlRes.status).json(samlRes.data)
    }
    const settingsUpdate = {}
    if (body.ssoEnabled !== undefined) settingsUpdate.federationOnly = Boolean(body.ssoEnabled)
    if (body.webhookUrl !== undefined) settingsUpdate.webhookUrl = body.webhookUrl
    if (Object.keys(settingsUpdate).length > 0) {
      await cpFetch(`/api/tenants/${req._tenantId}/settings`, {
        method: 'PUT',
        body: JSON.stringify(settingsUpdate),
      })
    }
    res.json({ data: { success: true } })
  } catch (e) {
    res.status(502).json({ message: 'Unable to save integrations' })
  }
})

// ── Tenant admin API key management ─────────────────────────────────────────
app.get('/api/admin/api-keys', tenantAdminOnly, async (req, res) => {
  try {
    const keysRes = await cpFetch(`/api/tenants/${req._tenantId}/api-keys`)
    res.json({ data: Array.isArray(keysRes.data) ? keysRes.data : [] })
  } catch (e) {
    res.status(502).json({ message: 'Unable to load API keys' })
  }
})

app.use('/api/admin/api-keys', express.json())
app.post('/api/admin/api-keys', tenantAdminOnly, async (req, res) => {
  try {
    const keyRes = await cpFetch(`/api/tenants/${req._tenantId}/api-keys`, {
      method: 'POST',
      body: JSON.stringify(req.body),
    })
    if (!keyRes.ok) return res.status(keyRes.status).json(keyRes.data)
    res.json({ data: keyRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to create API key' })
  }
})

app.delete('/api/admin/api-keys/:keyId', tenantAdminOnly, async (req, res) => {
  try {
    const keyRes = await cpFetch(`/api/tenants/${req._tenantId}/api-keys/${req.params.keyId}`, {
      method: 'DELETE',
    })
    res.json({ data: keyRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to revoke API key' })
  }
})

app.get('/api/admin/invitations', tenantAdminOnly, async (req, res) => {
  try {
    const invRes = await cpFetch(`/api/tenants/${req._tenantId}/invitations`)
    res.json({ data: Array.isArray(invRes.data) ? invRes.data : [] })
  } catch (e) {
    res.status(502).json({ message: 'Unable to load invitations' })
  }
})

app.use('/api/admin/invitations', express.json())
app.post('/api/admin/invitations', tenantAdminOnly, async (req, res) => {
  try {
    const invRes = await cpFetch(`/api/tenants/${req._tenantId}/invitations`, {
      method: 'POST',
      body: JSON.stringify({ ...req.body, invitedBy: req._email }),
    })
    if (!invRes.ok) return res.status(invRes.status).json(invRes.data)
    res.json({ data: invRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to create invitation' })
  }
})

app.delete('/api/admin/invitations/:invId', tenantAdminOnly, async (req, res) => {
  try {
    const invRes = await cpFetch(`/api/tenants/${req._tenantId}/invitations/${req.params.invId}`, {
      method: 'DELETE',
    })
    res.json({ data: invRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to revoke invitation' })
  }
})

app.post('/api/admin/invitations/:invId/resend', tenantAdminOnly, async (req, res) => {
  try {
    const invRes = await cpFetch(`/api/tenants/${req._tenantId}/invitations/${req.params.invId}/resend`, {
      method: 'POST',
    })
    res.json({ data: invRes.data })
  } catch (e) {
    res.status(502).json({ message: 'Unable to resend invitation' })
  }
})

app.use((_req, res) => res.status(404).json({ message: 'No route' }))

const CACHE_CLEANUP_MS = 10 * 60 * 1000
setInterval(() => {
  const now = Date.now()
  for (const [key, bucket] of tenantRateLimits) {
    if (bucket.windowStart + TENANT_RATE_LIMIT_WINDOW_MS < now) {
      tenantRateLimits.delete(key)
    }
  }
  for (const [key, entry] of tenantStatusCache) {
    if (entry.expiresAt < now) tenantStatusCache.delete(key)
  }
  for (const [key, entry] of tenantAuthConfigCache) {
    if (entry.expiresAt < now) tenantAuthConfigCache.delete(key)
  }
  if (emailToId.size > 10_000) emailToId.clear()
  if (slugToTenantId.size > 1_000) slugToTenantId.clear()
  for (const [key, entry] of userActiveCache) {
    if (entry.expiresAt < now) userActiveCache.delete(key)
  }
}, CACHE_CLEANUP_MS)

app.listen(PORT, () => {
  console.log(`[proxy] listening on :${PORT}`)
  console.log(`[proxy] Cognito issuer: ${ISSUER || 'not configured'}`)
  console.log(`[proxy] Platform Cognito issuer: ${PLATFORM_ISSUER || 'not configured'}`)
  console.log(`[proxy] default tenant fallback: ${defaultTenantIdOrNull() || 'disabled'}`)

  refreshCustomDomainMappings().catch(() => {})

  if (IS_PRODUCTION) {
    const missing = []
    if (!PLATFORM_POOL) missing.push('PLATFORM_COGNITO_USER_POOL_ID')
    if (!INTERNAL_AUTH) missing.push('INTERNAL_AUTH_SECRET')
    if (missing.length > 0) {
      console.error(`[proxy] FATAL: Missing required env vars in production: ${missing.join(', ')}`)
      process.exit(1)
    }
  }
})
