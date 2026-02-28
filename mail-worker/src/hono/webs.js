import app from './hono';
import '../security/security'

import '../api/email-api';
import '../api/user-api';
import '../api/login-api';
import '../api/setting-api';
import '../api/account-api';
import '../api/star-api';
import '../api/test-api';
import '../api/r2-api';
import '../api/my-api';
import '../api/role-api'
import '../api/all-email-api'
import '../api/init-api'
import '../api/analysis-api'
import '../api/reg-key-api'
import '../api/public-api'
import '../api/oauth-api'

// Bot Module - Telegram bot functionality (webhooks, commands, notifications)
import '../bot/bot-api';

// Webhook Module - Email service webhooks and event logging
import '../webhook/webhook-api';

// Note: For backward compatibility, the old API files still exist as thin wrappers:
// - telegram-api.js re-exports from bot/
// - resend-api.js and webhook-event-api.js re-export from webhook/

export default app;