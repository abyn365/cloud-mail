import app from '../hono/hono';
import botService from './bot-service';

// Note: botService is re-exported from ../service/telegram-service.js
// which contains all the bot functionality including:
// - Webhook handling (handleBotWebhook)
// - Command resolution (resolveCommand)
// - Notification sending methods
// - IP security lookups
// - Event logging

// Email content preview endpoints
app.get('/telegram/getEmail/:token', async (c) => {
    const content = await botService.getEmailContent(c, c.req.param());
    c.header('Cache-Control', 'public, max-age=604800, immutable');
    return c.html(content)
});

app.get('/telegram/getBanEmail/:token', async (c) => {
    const content = await botService.getBanEmailContent(c, c.req.param());
    c.header('Cache-Control', 'no-store');
    return c.html(content)
});

// Bot webhook management endpoints
app.get('/telegram/webhook/setup', async (c) => {
    const result = await botService.setWebhook(c);
    return c.json(result, result.ok ? 200 : 400);
});

app.get('/telegram/webhook/info', async (c) => {
    const result = await botService.getWebhookInfo(c);
    return c.json(result, result.ok ? 200 : 400);
});

app.get('/telegram/webhook/delete', async (c) => {
    const result = await botService.deleteWebhook(c);
    return c.json(result, result.ok ? 200 : 400);
});

// Bot webhook receiver
app.post('/telegram/webhook', async (c) => {
    const body = await c.req.json();
    await botService.handleBotWebhook(c, body);
    return c.json({ ok: true });
});
