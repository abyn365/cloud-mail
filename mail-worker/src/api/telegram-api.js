import app from '../hono/hono';
import telegramService from '../service/telegram-service';

app.get('/telegram/getEmail/:token', async (c) => {
	const content = await telegramService.getEmailContent(c, c.req.param());
	c.header('Cache-Control', 'public, max-age=604800, immutable');
	return c.html(content)
});



app.get('/telegram/webhook/setup', async (c) => {
	const result = await telegramService.setWebhook(c);
	return c.json(result, result.ok ? 200 : 400);
});

app.get('/telegram/webhook/info', async (c) => {
	const result = await telegramService.getWebhookInfo(c);
	return c.json(result, result.ok ? 200 : 400);
});

app.get('/telegram/webhook/delete', async (c) => {
	const result = await telegramService.deleteWebhook(c);
	return c.json(result, result.ok ? 200 : 400);
});

app.post('/telegram/webhook', async (c) => {
	const body = await c.req.json();
	await telegramService.handleBotWebhook(c, body);
	return c.json({ ok: true });
});
