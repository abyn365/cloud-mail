import app from './hono/webs';
import { email } from './email/email';
import userService from './service/user-service';
import verifyRecordService from './service/verify-record-service';
import emailService from './service/email-service';
import kvObjService from './service/kv-obj-service';
import oauthService from "./service/oauth-service";

export default {
	async fetch(req, env, ctx) {
		const url = new URL(req.url)
		if (url.pathname.startsWith('/api/')) {
			url.pathname = url.pathname.replace('/api', '')
			req = new Request(url.toString(), req)
			return app.fetch(req, env, ctx);
		}
		if (['/static/','/attachments/'].some(p => url.pathname.startsWith(p))) {
			return await kvObjService.toObjResp({ env }, url.pathname.substring(1));
		}
		return env.assets.fetch(req);
	},
	email: email,
	async scheduled(c, env, ctx) {
		await verifyRecordService.clearRecord({ env })
		await userService.resetDaySendCount({ env })
		await emailService.completeReceiveAll({ env })
		await oauthService.clearNoBindOathUser({ env })

		// Clean up old logs (>36 hours) to keep security dashboard clear
		try {
			await env.db.batch([
				env.db.prepare(`
					DELETE FROM webhook_event_log
					WHERE create_time <= datetime('now', '-36 hour')
				`),
				env.db.prepare(`
					DELETE FROM ban_email_log
					WHERE create_time <= datetime('now', '-24 hour')
				`)
			]);
		} catch (e) {
			// ban_email_log may not exist yet if no blacklisted email has arrived
			try {
				await env.db.prepare(`
					DELETE FROM webhook_event_log
					WHERE create_time <= datetime('now', '-36 hour')
				`).run();
			} catch (_) {}
		}
	},
};
