"""
50-service registry for the synthetic generator.
~30% of services are seeded with known-vulnerable dependency versions
so the pipeline fires end-to-end without requiring scenario injection.
"""

SERVICES = [
    # ── Payments team (PCI DSS scope) ─────────────────────────────────────────
    {"service_id": "checkout-api", "team": "payments", "ecosystem": "pypi", "is_customer_facing": True, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": True, "description": "Customer checkout flow", "code_owners": ["@payments-team"]},
    {"service_id": "payment-processor", "team": "payments", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": True, "description": "Payment gateway integration", "code_owners": ["@payments-team"]},
    {"service_id": "invoice-generator", "team": "payments", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": True, "description": "Invoice generation and storage", "code_owners": ["@payments-team"]},
    {"service_id": "fraud-detector", "team": "payments", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Real-time fraud scoring", "code_owners": ["@payments-team"]},
    {"service_id": "billing-scheduler", "team": "payments", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Subscription billing cron", "code_owners": ["@payments-team"]},

    # ── Auth team ─────────────────────────────────────────────────────────────
    {"service_id": "auth-service", "team": "auth", "ecosystem": "pypi", "is_customer_facing": True, "pci_scope": True, "hipaa_scope": True, "soc2_scope": True, "pii_handler": True, "description": "Authentication and JWT issuance", "code_owners": ["@auth-team"]},
    {"service_id": "session-manager", "team": "auth", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Session state management", "code_owners": ["@auth-team"]},
    {"service_id": "permissions-api", "team": "auth", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "RBAC permissions service", "code_owners": ["@auth-team"]},

    # ── Platform team ─────────────────────────────────────────────────────────
    {"service_id": "api-gateway", "team": "platform", "ecosystem": "npm", "is_customer_facing": True, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Public API gateway", "code_owners": ["@platform-team"]},
    {"service_id": "config-service", "team": "platform", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Centralised config management", "code_owners": ["@platform-team"]},
    {"service_id": "secrets-manager", "team": "platform", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Secrets rotation and access", "code_owners": ["@platform-team"]},
    {"service_id": "log-aggregator", "team": "platform", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Centralised log collection", "code_owners": ["@platform-team"]},
    {"service_id": "metrics-collector", "team": "platform", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Prometheus metrics aggregator", "code_owners": ["@platform-team"]},

    # ── Product team ──────────────────────────────────────────────────────────
    {"service_id": "user-api", "team": "product", "ecosystem": "pypi", "is_customer_facing": True, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": True, "description": "User profile and settings", "code_owners": ["@product-team"]},
    {"service_id": "notification-worker", "team": "product", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": True, "description": "Email and push notifications", "code_owners": ["@product-team"]},
    {"service_id": "search-api", "team": "product", "ecosystem": "pypi", "is_customer_facing": True, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Full-text search service", "code_owners": ["@product-team"]},
    {"service_id": "recommendations-api", "team": "product", "ecosystem": "pypi", "is_customer_facing": True, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "ML-backed recommendations", "code_owners": ["@product-team"]},

    # ── Frontend team (npm) ───────────────────────────────────────────────────
    {"service_id": "storefront", "team": "frontend", "ecosystem": "npm", "is_customer_facing": True, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Customer-facing Next.js storefront", "code_owners": ["@frontend-team"]},
    {"service_id": "admin-portal", "team": "frontend", "ecosystem": "npm", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Internal admin dashboard", "code_owners": ["@frontend-team"]},
    {"service_id": "mobile-bff", "team": "frontend", "ecosystem": "npm", "is_customer_facing": True, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Backend-for-frontend for mobile app", "code_owners": ["@frontend-team"]},

    # ── Data team ─────────────────────────────────────────────────────────────
    {"service_id": "data-pipeline", "team": "data", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": True, "description": "ETL pipeline to data warehouse", "code_owners": ["@data-team"]},
    {"service_id": "reporting-service", "team": "data", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": True, "pii_handler": False, "description": "Business intelligence reporting", "code_owners": ["@data-team"]},
    {"service_id": "ml-training-worker", "team": "data", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "ML model training jobs", "code_owners": ["@data-team"]},
    {"service_id": "feature-store-api", "team": "data", "ecosystem": "pypi", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Real-time ML feature serving", "code_owners": ["@data-team"]},

    # ── Legacy (Java/Maven) ───────────────────────────────────────────────────
    {"service_id": "legacy-billing", "team": "payments", "ecosystem": "maven", "is_customer_facing": False, "pci_scope": True, "hipaa_scope": False, "soc2_scope": True, "pii_handler": True, "description": "Legacy Java billing system — migration in progress", "code_owners": ["@payments-team"]},
    {"service_id": "document-processor", "team": "platform", "ecosystem": "maven", "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False, "soc2_scope": False, "pii_handler": False, "description": "Legacy document transformation service", "code_owners": ["@platform-team"]},
]

# Pad to 50 services with additional product/platform services.
SERVICES += [
    {"service_id": f"service-{i:02d}", "team": "product", "ecosystem": "pypi",
     "is_customer_facing": False, "pci_scope": False, "hipaa_scope": False,
     "soc2_scope": False, "pii_handler": False,
     "description": f"Generic product service {i}", "code_owners": ["@product-team"]}
    for i in range(len(SERVICES), 50)
]
