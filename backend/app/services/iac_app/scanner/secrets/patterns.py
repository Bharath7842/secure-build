"""Known secret regex patterns (Trivy/Gitleaks-style)."""

from __future__ import annotations

import re

SECRET_PATTERNS: dict[str, str] = {
    # ── AWS ─────────────────────────────────────────────────────────────
    "AWS_ACCESS_KEY": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS_SECRET_KEY": r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
    "AWS_SESSION_TOKEN": r"(?i)aws[_-]?session[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})",
    "AWS_MWS_KEY": r"(?i)mws[_-]?(access[_-]?key|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9]{48})",

    # ── GCP ─────────────────────────────────────────────────────────────
    "GCP_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "GCP_SA_KEY": r'"type"\s*:\s*"service_account"',
    "GCP_OAUTH_TOKEN": r"ya29\.[0-9A-Za-z\-_]+",
    "GCP_IAP_KEY": r"(?i)iap[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{32,})",

    # ── Azure ───────────────────────────────────────────────────────────
    "AZURE_STORAGE_KEY": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "AZURE_CLIENT_SECRET": r"(?i)(?:azure_)?client_secret\s*[=:]\s*['\"]?([A-Za-z0-9\-._~+/]{32,})",
    "AZURE_CONNECTION_STRING": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
    "AZURE_SAS_TOKEN": r"(?i)sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}-\d{2}-\d{2}",

    # ── GitHub ──────────────────────────────────────────────────────────
    "GITHUB_PAT": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "GITHUB_OAUTH": r"gho_[A-Za-z0-9_]{36,}",
    "GITHUB_APP_TOKEN": r"(?:ghu|ghs)_[A-Za-z0-9_]{36,}",
    "GITHUB_REFRESH_TOKEN": r"ghr_[A-Za-z0-9_]{36,}",

    # ── GitLab ──────────────────────────────────────────────────────────
    "GITLAB_PAT": r"glpat-[A-Za-z0-9\-_]{20,}",
    "GITLAB_PAT_V2": r"glpat-[A-Za-z0-9\-_]{20,}",
    "GITLAB_RUNNER_TOKEN": r"glrt-[A-Za-z0-9\-_]{20,}",
    "GITLABPipelineToken": r"glptt-[A-Za-z0-9\-_]{40,}",
    "GITLAB_FEED_TOKEN": r"glft-[A-Za-z0-9\-_]{20,}",

    # ── Slack ───────────────────────────────────────────────────────────
    "SLACK_TOKEN": r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+",
    "SLACK_WEBHOOK": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
    "SLACK_BOT_TOKEN": r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}",
    "SLACK_USER_TOKEN": r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}",
    "SLACK_APP_TOKEN": r"xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}",

    # ── Stripe ──────────────────────────────────────────────────────────
    "STRIPE_KEY": r"[sr]k_live_[A-Za-z0-9]{24,}",
    "STRIPE_RESTRICTED_KEY": r"rk_live_[A-Za-z0-9]{24,}",
    "STRIPE_SECRET_KEY": r"sk_live_[A-Za-z0-9]{24,}",
    "STRIPE_WEBHOOK_SECRET": r"whsec_[A-Za-z0-9]{32,}",

    # ── Twilio ──────────────────────────────────────────────────────────
    "TWILIO_API_KEY": r"SK[0-9a-fA-F]{32}",
    "TWILIO_AUTH_TOKEN": r"(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9]{32})",

    # ── SendGrid ────────────────────────────────────────────────────────
    "SENDGRID_API_KEY": r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}",
    "SENDGRID_PASSWORD": r"(?i)sendgrid[_-]?password\s*[=:]\s*['\"]?([^\s'\"]{8,})",

    # ── Mailgun ─────────────────────────────────────────────────────────
    "MAILGUN_API_KEY": r"key-[0-9a-zA-Z]{32}",
    "MAILGUN_PRIVATE_KEY": r"(?i)mailgun[_-]?private[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{32,})",

    # ── Heroku ──────────────────────────────────────────────────────────
    "HEROKU_API_KEY": r"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    "HEROKU_OAUTH": r"(?i)heroku[_-]?oauth\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",

    # ── DigitalOcean ────────────────────────────────────────────────────
    "DIGITALOCEAN_TOKEN": r"dop_v1_[a-f0-9]{64}",
    "DIGITALOCEAN_PAT": r"doo_v1_[a-f0-9]{64}",
    "DIGITALOCEAN_OAUTH": r"(?i)digitalocean[_-]?access[_-]?token\s*[=:]\s*['\"]?([a-f0-9]{64})",

    # ── Atlassian ───────────────────────────────────────────────────────
    "ATLASSIAN_API_TOKEN": r"(?i)atlassian[_-]?api[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9]{24})",
    "JIRA_API_TOKEN": r"(?i)jira[_-]?api[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9]{24})",

    # ── Datadog ─────────────────────────────────────────────────────────
    "DATADOG_API_KEY": r"(?i)dd[_-]?api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{32})",
    "DATADOG_APP_KEY": r"(?i)dd[_-]?app[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{40})",

    # ── New Relic ───────────────────────────────────────────────────────
    "NEWRELIC_API_KEY": r"NRAK-[A-Z0-9]{27}",
    "NEWRELIC_INGEST_KEY": r"NRI-[A-Za-z0-9\-]{32,}",
    "NEWRELIC_LICENSE_KEY": r"(?i)new[_-]?relic[_-]?license[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9]{40})",

    # ── PagerDuty ───────────────────────────────────────────────────────
    "PAGERDUTY_TOKEN": r"(?i)pagerduty[_-]?(api[_-]?key|token)\s*[=:]\s*['\"]?([A-Za-z0-9]{20})",

    # ── Terraform Cloud ─────────────────────────────────────────────────
    "TERRAFORM_CLOUD_TOKEN": r"(?i)atlasv1\.[A-Za-z0-9\-._]{20,}",
    "TFE_TOKEN": r"(?i)tfe[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{14,}\.[A-Za-z0-9\-._]{6,})",

    # ── HashiCorp Vault ─────────────────────────────────────────────────
    "VAULT_TOKEN": r"(?i)vault[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{20,})",
    "VAULT_APPROLE": r"(?i)vault[_-]?approle[_-]?(secret[_-]?id|role[_-]?id)\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{20,})",

    # ── Database Connection Strings ─────────────────────────────────────
    "DATABASE_URL": r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"]{10,}",
    "MYSQL_CONNECTION": r"(?i)Server=[^;]+;Database=[^;]+;Uid=[^;]+;Pwd=[^;]+",
    "POSTGRES_CONNECTION": r"(?i)Host=[^;]+;Port=[^;]+;Database=[^;]+;Username=[^;]+;Password=[^;]+",
    "MONGODB_URI": r"mongodb\+srv://[^\s'\"]+",
    "REDIS_URL": r"redis://[^\s'\"]+",

    # ── JWT Tokens ──────────────────────────────────────────────────────
    "JWT_TOKEN": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",

    # ── SSH/Private Keys ────────────────────────────────────────────────
    "RSA_PRIVATE_KEY": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC_PRIVATE_KEY": r"-----BEGIN EC PRIVATE KEY-----",
    "DSA_PRIVATE_KEY": r"-----BEGIN DSA PRIVATE KEY-----",
    "OPENSSH_PRIVATE_KEY": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP_PRIVATE_KEY": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PKCS8_PRIVATE_KEY": r"-----BEGIN PRIVATE KEY-----",
    "SSH_RSA_PUBLIC_KEY": r"ssh-rsa [A-Za-z0-9+/]{100,}",
    "SSH_ED25519_KEY": r"ssh-ed25519 [A-Za-z0-9+/]{100,}",

    # ── Generic Secrets ─────────────────────────────────────────────────
    "GENERIC_API_KEY": r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{20,})",
    "GENERIC_SECRET": r"(?i)(secret|password|token|credential)\s*[=:]\s*['\"]?([A-Za-z0-9\-._~+/]{12,})",
    "GENERIC_BEARER_TOKEN": r"(?i)(?:bearer|authorization)\s*[=:]\s*['\"]?Bearer\s+([A-Za-z0-9\-._~+/]{20,})",
    "GENERIC_PRIVATE_KEY": r"(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9\-._+/]{20,})",

    # ── NPM/PyPI/Other Package Registries ───────────────────────────────
    "NPM_TOKEN": r"npm_[A-Za-z0-9]{36}",
    "PYPI_TOKEN": r"pypi-[A-Za-z0-9\-_]{50,}",
    "RUBYGEMS_API_KEY": r"(?i)rubygems[_-]?api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9]{48})",
    "DOCKERHUB_PASSWORD": r"(?i)docker[_-]?password\s*[=:]\s*['\"]?([^\s'\"]{8,})",

    # ── Cryptocurrency ──────────────────────────────────────────────────
    "ETHEREUM_PRIVATE_KEY": r"(?i)(?:ethereum|eth)[-_]?private[_-]?key\s*[=:]\s*['\"]?([0-9a-fA-F]{64})",
    "BITCOIN_PRIVATE_KEY": r"(?i)bitcoin[_-]?private[_-]?key\s*[=:]\s*['\"]?([5KL][1-9A-HJ-NP-Za-km-z]{50,52})",

    # ── Social/OAuth Tokens ─────────────────────────────────────────────
    "FACEBOOK_SECRET": r"(?i)fb[_-]?secret\s*[=:]\s*['\"]?([a-f0-9]{32})",
    "TWITTER_BEARER_TOKEN": r"(?i)twitter[_-]?bearer[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9]{35,})",
    "DISCORD_TOKEN": r"(?i)discord[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{50,})",
    "TELEGRAM_TOKEN": r"(?i)(?:telegram|tg)[-_]?bot[_-]?token\s*[=:]\s*['\"]?([0-9]{8,}:[A-Za-z0-9_-]{35})",

    # ── VPN/Certificate Keys ────────────────────────────────────────────
    "VPN_SHARED_SECRET": r"(?i)(?:vpn|ipsec)[-_]?shared[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9+/]{20,})",
    "TLS_CERTIFICATE": r"-----BEGIN CERTIFICATE-----",
}

COMPILED_PATTERNS = {
    name: re.compile(pattern)
    for name, pattern in SECRET_PATTERNS.items()
}

PLACEHOLDER_MARKERS = (
    "changeme",
    "changeme!",
    "your-key-here",
    "your_key",
    "xxx",
    "todo",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "sample",
    "notasecret",
    "redacted",
    "${",
    "{{",
    "<%",
)

RULE_META = {
    # AWS
    "AWS_ACCESS_KEY": ("CRITICAL", "Hardcoded AWS access key ID"),
    "AWS_SECRET_KEY": ("CRITICAL", "Hardcoded AWS secret access key"),
    "AWS_SESSION_TOKEN": ("CRITICAL", "Hardcoded AWS session token"),
    "AWS_MWS_KEY": ("CRITICAL", "Hardcoded AWS MWS key"),
    # GCP
    "GCP_API_KEY": ("CRITICAL", "Hardcoded Google API key"),
    "GCP_SA_KEY": ("CRITICAL", "Google service account key material"),
    "GCP_OAUTH_TOKEN": ("CRITICAL", "Hardcoded Google OAuth token"),
    "GCP_IAP_KEY": ("HIGH", "Hardcoded Google IAP secret"),
    # Azure
    "AZURE_STORAGE_KEY": ("CRITICAL", "Hardcoded Azure storage connection string"),
    "AZURE_CLIENT_SECRET": ("HIGH", "Hardcoded Azure client secret"),
    "AZURE_CONNECTION_STRING": ("CRITICAL", "Hardcoded Azure connection string"),
    "AZURE_SAS_TOKEN": ("HIGH", "Hardcoded Azure SAS token"),
    # GitHub
    "GITHUB_PAT": ("CRITICAL", "Hardcoded GitHub personal access token"),
    "GITHUB_OAUTH": ("CRITICAL", "Hardcoded GitHub OAuth token"),
    "GITHUB_APP_TOKEN": ("CRITICAL", "Hardcoded GitHub App token"),
    "GITHUB_REFRESH_TOKEN": ("HIGH", "Hardcoded GitHub refresh token"),
    # GitLab
    "GITLAB_PAT": ("CRITICAL", "Hardcoded GitLab personal access token"),
    "GITLAB_PAT_V2": ("CRITICAL", "Hardcoded GitLab personal access token"),
    "GITLAB_RUNNER_TOKEN": ("CRITICAL", "Hardcoded GitLab runner token"),
    "GITLABPipelineToken": ("CRITICAL", "Hardcoded GitLab pipeline token"),
    "GITLAB_FEED_TOKEN": ("HIGH", "Hardcoded GitLab feed token"),
    # Slack
    "SLACK_TOKEN": ("HIGH", "Hardcoded Slack token"),
    "SLACK_WEBHOOK": ("HIGH", "Hardcoded Slack webhook URL"),
    "SLACK_BOT_TOKEN": ("HIGH", "Hardcoded Slack bot token"),
    "SLACK_USER_TOKEN": ("HIGH", "Hardcoded Slack user token"),
    "SLACK_APP_TOKEN": ("HIGH", "Hardcoded Slack app token"),
    # Stripe
    "STRIPE_KEY": ("CRITICAL", "Hardcoded live Stripe key"),
    "STRIPE_RESTRICTED_KEY": ("CRITICAL", "Hardcoded Stripe restricted key"),
    "STRIPE_SECRET_KEY": ("CRITICAL", "Hardcoded Stripe secret key"),
    "STRIPE_WEBHOOK_SECRET": ("HIGH", "Hardcoded Stripe webhook secret"),
    # Twilio
    "TWILIO_API_KEY": ("HIGH", "Hardcoded Twilio API key"),
    "TWILIO_AUTH_TOKEN": ("HIGH", "Hardcoded Twilio auth token"),
    # SendGrid
    "SENDGRID_API_KEY": ("CRITICAL", "Hardcoded SendGrid API key"),
    "SENDGRID_PASSWORD": ("HIGH", "Hardcoded SendGrid password"),
    # Mailgun
    "MAILGUN_API_KEY": ("HIGH", "Hardcoded Mailgun API key"),
    "MAILGUN_PRIVATE_KEY": ("HIGH", "Hardcoded Mailgun private key"),
    # Heroku
    "HEROKU_API_KEY": ("HIGH", "Hardcoded Heroku API key"),
    "HEROKU_OAUTH": ("HIGH", "Hardcoded Heroku OAuth token"),
    # DigitalOcean
    "DIGITALOCEAN_TOKEN": ("CRITICAL", "Hardcoded DigitalOcean token"),
    "DIGITALOCEAN_PAT": ("CRITICAL", "Hardcoded DigitalOcean PAT"),
    "DIGITALOCEAN_OAUTH": ("HIGH", "Hardcoded DigitalOcean OAuth token"),
    # Atlassian
    "ATLASSIAN_API_TOKEN": ("HIGH", "Hardcoded Atlassian API token"),
    "JIRA_API_TOKEN": ("HIGH", "Hardcoded Jira API token"),
    # Datadog
    "DATADOG_API_KEY": ("HIGH", "Hardcoded Datadog API key"),
    "DATADOG_APP_KEY": ("HIGH", "Hardcoded Datadog application key"),
    # New Relic
    "NEWRELIC_API_KEY": ("HIGH", "Hardcoded New Relic API key"),
    "NEWRELIC_INGEST_KEY": ("HIGH", "Hardcoded New Relic ingest key"),
    "NEWRELIC_LICENSE_KEY": ("HIGH", "Hardcoded New Relic license key"),
    # PagerDuty
    "PAGERDUTY_TOKEN": ("HIGH", "Hardcoded PagerDuty token"),
    # Terraform
    "TERRAFORM_CLOUD_TOKEN": ("CRITICAL", "Hardcoded Terraform Cloud token"),
    "TFE_TOKEN": ("CRITICAL", "Hardcoded Terraform Enterprise token"),
    # Vault
    "VAULT_TOKEN": ("CRITICAL", "Hardcoded HashiCorp Vault token"),
    "VAULT_APPROLE": ("HIGH", "Hardcoded Vault AppRole secret"),
    # Database
    "DATABASE_URL": ("CRITICAL", "Hardcoded database connection string"),
    "MYSQL_CONNECTION": ("CRITICAL", "Hardcoded MySQL connection string"),
    "POSTGRES_CONNECTION": ("CRITICAL", "Hardcoded PostgreSQL connection string"),
    "MONGODB_URI": ("CRITICAL", "Hardcoded MongoDB connection URI"),
    "REDIS_URL": ("HIGH", "Hardcoded Redis connection URL"),
    # JWT
    "JWT_TOKEN": ("HIGH", "Hardcoded JWT token"),
    # SSH/Private Keys
    "RSA_PRIVATE_KEY": ("CRITICAL", "RSA private key checked into source"),
    "EC_PRIVATE_KEY": ("CRITICAL", "EC private key checked into source"),
    "DSA_PRIVATE_KEY": ("CRITICAL", "DSA private key checked into source"),
    "OPENSSH_PRIVATE_KEY": ("CRITICAL", "OpenSSH private key checked into source"),
    "PGP_PRIVATE_KEY": ("CRITICAL", "PGP private key checked into source"),
    "PKCS8_PRIVATE_KEY": ("CRITICAL", "PKCS8 private key checked into source"),
    "SSH_RSA_PUBLIC_KEY": ("MEDIUM", "SSH RSA public key (may expose infrastructure)"),
    "SSH_ED25519_KEY": ("MEDIUM", "SSH Ed25519 key (may expose infrastructure)"),
    # Generic
    "GENERIC_API_KEY": ("HIGH", "Hardcoded API key"),
    "GENERIC_SECRET": ("HIGH", "Hardcoded secret or password"),
    "GENERIC_BEARER_TOKEN": ("HIGH", "Hardcoded bearer token"),
    "GENERIC_PRIVATE_KEY": ("HIGH", "Hardcoded private key"),
    # Package Registries
    "NPM_TOKEN": ("HIGH", "Hardcoded NPM token"),
    "PYPI_TOKEN": ("HIGH", "Hardcoded PyPI token"),
    "RUBYGEMS_API_KEY": ("HIGH", "Hardcoded RubyGems API key"),
    "DOCKERHUB_PASSWORD": ("HIGH", "Hardcoded DockerHub password"),
    # Cryptocurrency
    "ETHEREUM_PRIVATE_KEY": ("CRITICAL", "Hardcoded Ethereum private key"),
    "BITCOIN_PRIVATE_KEY": ("CRITICAL", "Hardcoded Bitcoin private key"),
    # Social/OAuth
    "FACEBOOK_SECRET": ("HIGH", "Hardcoded Facebook app secret"),
    "TWITTER_BEARER_TOKEN": ("HIGH", "Hardcoded Twitter bearer token"),
    "DISCORD_TOKEN": ("HIGH", "Hardcoded Discord token"),
    "TELEGRAM_TOKEN": ("HIGH", "Hardcoded Telegram bot token"),
    # VPN/Certificate
    "VPN_SHARED_SECRET": ("HIGH", "Hardcoded VPN shared secret"),
    "TLS_CERTIFICATE": ("MEDIUM", "TLS certificate (may expose private key)"),
    # Entropy
    "HIGH_ENTROPY": ("MEDIUM", "High-entropy string that may be a secret"),
}
