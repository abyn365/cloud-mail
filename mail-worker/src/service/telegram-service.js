import orm from '../entity/orm';
import email from '../entity/email';
import role from '../entity/role';
import user from '../entity/user';
import regKey from '../entity/reg-key';
import settingService from './setting-service';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';
dayjs.extend(utc);
dayjs.extend(timezone);
import { eq, desc } from 'drizzle-orm';
import account from '../entity/account';
import jwtUtils from '../utils/jwt-utils';
import timezoneUtils from '../utils/timezone-utils';
import emailMsgTemplate, {
	loginMsgTemplate,
	registerMsgTemplate,
	sendEmailMsgTemplate,
	softDeleteEmailMsgTemplate,
	hardDeleteEmailMsgTemplate,
	addAddressMsgTemplate,
	deleteAddressMsgTemplate,
	roleChangeMsgTemplate,
	userStatusChangeMsgTemplate,
	passwordResetMsgTemplate,
	userSelfDeleteMsgTemplate,
	adminDeleteUserMsgTemplate,
	failedLoginMsgTemplate,
	quotaWarningMsgTemplate,
	regKeyManageMsgTemplate,
	ipSecurityMsgTemplate,
	adminCreateUserMsgTemplate,
	roleManageMsgTemplate
} from '../template/email-msg';
import emailTextTemplate from '../template/email-text';
import emailHtmlTemplate from '../template/email-html';
import domainUtils from '../utils/domain-uitls';
import analysisDao from '../dao/analysis-dao';

const EVENT_LEVEL = {
	INFO: 'info',
	WARN: 'warn',
	ERROR: 'error'
};

const telegramService = {

	async getEmailContent(c, params) {
		const { token } = params;
		const result = await jwtUtils.verifyToken(c, token);
		if (!result) return emailTextTemplate('Access denied');
		const emailRow = await orm(c).select().from(email).where(eq(email.emailId, result.emailId)).get();
		if (!emailRow) return emailTextTemplate('The email does not exist');
		if (emailRow.content) {
			const { r2Domain } = await settingService.query(c);
			return emailHtmlTemplate(emailRow.content || '', r2Domain);
		}
		return emailTextTemplate(emailRow.text || '');
	},

	async getBotToken(c) {
		const envToken = c.env.BOT_TOKEN || c.env.bot_token || c.env.TG_BOT_TOKEN || c.env.tgBotToken;
		if (envToken) {
			return envToken;
		}
		try {
			const setting = await settingService.query(c);
			return setting.tgBotToken;
		} catch (e) {
			console.error('Failed to load tgBotToken from setting:', e.message);
			return null;
		}
	},

	async shouldSendWebhookPush(c) {
		const pushEnabled = String(c.env.TG_EVENT_PUSH || c.env.tg_event_push || '').toLowerCase();
		return pushEnabled === '1' || pushEnabled === 'true' || pushEnabled === 'yes';
	},

	async sendTelegramMessage(c, message, reply_markup = null) {
		if (!await this.shouldSendWebhookPush(c)) return;
		const { tgChatId } = await settingService.query(c);
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken || !tgChatId) return;
		const tgChatIds = tgChatId.split(',');
		await Promise.all(tgChatIds.map(async chatId => {
			try {
				const payload = {
					chat_id: chatId.trim(),
					parse_mode: 'HTML',
					text: message
				};
				if (reply_markup) payload.reply_markup = reply_markup;
				const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify(payload)
				});
				if (!res.ok) {
					const errorText = `Failed to send Telegram notification status: ${res.status} response: ${await res.text()}`;
					console.error(errorText);
					await this.logSystemEvent(c, 'telegram.send.error', EVENT_LEVEL.ERROR, errorText, { chatId: chatId.trim() });
				}
			} catch (e) {
				console.error('Failed to send Telegram notification:', e.message);
				await this.logSystemEvent(c, 'telegram.send.error', EVENT_LEVEL.ERROR, e.message, { chatId: chatId.trim() });
			}
		}));
	},

	async logSystemEvent(c, eventType, level, message, meta = null) {
		try {
			const safeMessage = String(message || '').slice(0, 3800);
			const metaJson = meta ? JSON.stringify(meta).slice(0, 2000) : null;
			await c.env.db.batch([
				c.env.db.prepare(`
					INSERT INTO webhook_event_log (event_type, level, message, meta)
					VALUES (?, ?, ?, ?)
				`).bind(eventType, level, safeMessage, metaJson),
				c.env.db.prepare(`
					DELETE FROM webhook_event_log
					WHERE create_time <= datetime('now', '-36 hour')
				`)
			]);
		} catch (e) {
			console.error('Failed to write webhook_event_log:', e.message);
		}
	},

	async emitWebhookEvent(c, eventType, message, level = EVENT_LEVEL.INFO, meta = null, replyMarkup = null) {
		await this.logSystemEvent(c, eventType, level, message, meta);
		await this.sendTelegramMessage(c, message, replyMarkup);
	},


	async attachRolePermInfo(c, roleInfo) {
		if (!roleInfo) return roleInfo;
		if (roleInfo.roleId === undefined || roleInfo.roleId === null) {
			roleInfo.canSendEmail = true;
			roleInfo.canAddAddress = true;
			return roleInfo;
		}

		try {
			const { results } = await c.env.db.prepare(`
				SELECT p.perm_key as permKey
				FROM role_perm rp
				LEFT JOIN perm p ON p.perm_id = rp.perm_id
				WHERE rp.role_id = ?
			`).bind(roleInfo.roleId).all();
			const permSet = new Set((results || []).map(item => item.permKey));
			roleInfo.canSendEmail = permSet.has('email:send');
			roleInfo.canAddAddress = permSet.has('account:add');
		} catch (e) {
			console.error('Failed to load role permission info:', e.message);
			roleInfo.canSendEmail = roleInfo.canSendEmail ?? true;
			roleInfo.canAddAddress = roleInfo.canAddAddress ?? true;
		}
		return roleInfo;
	},

	async setIpDetailContext(c, userInfo, ipField = 'activeIp', targetField = 'ipDetail') {
		const ip = userInfo?.[ipField];
		if (!ip) return;
		userInfo[targetField] = await this.queryIpSecurity(c, ip);
	},

	async queryIpSecurity(c, ip) {
		if (!ip) return null;

		try {
			const cache = await c.env.db.prepare('SELECT data, update_time FROM ip_security_cache WHERE ip = ?').bind(ip).first();
			if (cache?.data) {
				const cacheTime = cache.update_time ? dayjs.utc(cache.update_time) : null;
				const cacheExpired = !cacheTime || dayjs.utc().diff(cacheTime, 'hour') >= 48;
				if (!cacheExpired) {
					return JSON.parse(cache.data);
				}
				await c.env.db.prepare('DELETE FROM ip_security_cache WHERE ip = ?').bind(ip).run();
			}
		} catch (e) {
			console.error('Failed to read ip cache:', e.message);
			await this.logSystemEvent(c, 'security.ip_cache.read_error', EVENT_LEVEL.ERROR, e.message, { ip });
		}

		const apiKey = c.env.vpnapi_key || c.env.VPNAPI_KEY;
		if (!apiKey) return { ip };

		const today = dayjs().utc().format('YYYY-MM-DD');
		try {
			const usage = await c.env.db.prepare('SELECT count FROM ip_security_usage WHERE usage_date = ?').bind(today).first();
			if ((usage?.count || 0) >= 1000) {
				return { ip, limited: true };
			}
		} catch (e) {
			console.error('Failed to read ip usage:', e.message);
			await this.logSystemEvent(c, 'security.ip_usage.read_error', EVENT_LEVEL.ERROR, e.message, { ip });
		}

		let detail = { ip };
		try {
			const res = await fetch(`https://vpnapi.io/api/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`);
			if (!res.ok) {
				const errorText = `Failed to query vpnapi.io status: ${res.status} response: ${await res.text()}`;
				console.error(errorText);
				await this.logSystemEvent(c, 'security.vpnapi.error', EVENT_LEVEL.ERROR, errorText, { ip });
				return detail;
			}
			detail = await res.json();
		} catch (e) {
			console.error('Failed to query vpnapi.io:', e.message);
			await this.logSystemEvent(c, 'security.vpnapi.error', EVENT_LEVEL.ERROR, e.message, { ip });
			return detail;
		}

		try {
			const now = dayjs().utc().format('YYYY-MM-DD HH:mm:ss');
			await c.env.db.batch([
				c.env.db.prepare('INSERT INTO ip_security_cache (ip, data, update_time) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET data = excluded.data, update_time = excluded.update_time').bind(ip, JSON.stringify(detail), now),
				c.env.db.prepare('INSERT INTO ip_security_usage (usage_date, count, update_time) VALUES (?, 1, ?) ON CONFLICT(usage_date) DO UPDATE SET count = count + 1, update_time = excluded.update_time').bind(today, now)
			]);
		} catch (e) {
			console.error('Failed to write ip cache:', e.message);
			await this.logSystemEvent(c, 'security.ip_cache.write_error', EVENT_LEVEL.ERROR, e.message, { ip });
		}

		return detail;
	},

	async sendEmailToBot(c, emailData) {
		const { customDomain, tgMsgTo, tgMsgFrom, tgMsgText } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: emailData.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404';
		const message = emailMsgTemplate(emailData, tgMsgTo, tgMsgFrom, tgMsgText, null);
		await this.emitWebhookEvent(c, 'email.received', message, EVENT_LEVEL.INFO, { emailId: emailData?.emailId, webAppUrl, from: emailData?.sendEmail, to: emailData?.toEmail }, { inline_keyboard: [[{ text: 'Check', web_app: { url: webAppUrl } }]] });
	},

	async sendIpSecurityNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const ipDetail = await this.queryIpSecurity(c, userInfo.activeIp);
		await this.logSystemEvent(c, 'security.ip_changed', EVENT_LEVEL.WARN, `Recent IP updated for ${userInfo?.email || '-'}`, { userId: userInfo?.userId, email: userInfo?.email, ip: userInfo?.activeIp, vpn: ipDetail?.security?.vpn || false, proxy: ipDetail?.security?.proxy || false, tor: ipDetail?.security?.tor || false, relay: ipDetail?.security?.relay || false });
		const message = ipSecurityMsgTemplate(userInfo, ipDetail);
		await this.emitWebhookEvent(c, 'security.ip_changed', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email, ip: userInfo?.activeIp, vpn: ipDetail?.security?.vpn || false, proxy: ipDetail?.security?.proxy || false, tor: ipDetail?.security?.tor || false, relay: ipDetail?.security?.relay || false });
		await this.sendSecurityEventAlert(c, `IP changed: <code>${userInfo?.activeIp || '-'}</code>`, `User: ${userInfo?.email || '-'} (#${userInfo?.userId || '-'})`);
	},

	async sendRegKeyManageNotification(c, action, regKeyInfo, actorInfo, extraInfo = {}) {
		if (actorInfo?.activeIp) {
			actorInfo.timezone = await timezoneUtils.getTimezone(c, actorInfo.activeIp);
			await this.setIpDetailContext(c, actorInfo);
		}
		regKeyInfo.roleInfo = await this.attachRolePermInfo(c, regKeyInfo.roleInfo);
		if (actorInfo?.role) actorInfo.role = await this.attachRolePermInfo(c, actorInfo.role);
		const message = regKeyManageMsgTemplate(action, regKeyInfo, actorInfo, extraInfo);
		await this.emitWebhookEvent(c, 'regkey.manage', message, EVENT_LEVEL.INFO, { action, code: regKeyInfo?.code, actor: actorInfo?.email || '-' });
	},

	async sendLoginNotification(c, userInfo) {
		let message = '';
		try {
			userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
			await this.setIpDetailContext(c, userInfo);
			userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
			message = loginMsgTemplate(userInfo);
		} catch (e) {
			console.error('Failed to enrich login webhook payload, fallback to basic message:', e.message);
			message = loginMsgTemplate({
				...userInfo,
				timezone: null,
				ipDetail: null,
				role: userInfo?.role || null
			});
		}

		await this.emitWebhookEvent(c, 'auth.login.success', message, EVENT_LEVEL.INFO, { userId: userInfo?.userId, email: userInfo?.email, ip: userInfo?.activeIp });
	},

	async sendRegisterNotification(c, userInfo, accountCount, roleInfo = null) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.createIp);
		await this.setIpDetailContext(c, userInfo, 'createIp');
		roleInfo = await this.attachRolePermInfo(c, roleInfo);
		const message = registerMsgTemplate(userInfo, accountCount, roleInfo);
		await this.emitWebhookEvent(c, 'auth.register', message, EVENT_LEVEL.INFO, { userId: userInfo?.userId, email: userInfo?.email });
	},

	async sendAdminCreateUserNotification(c, newUserInfo, roleInfo, adminUser) {
		adminUser.timezone = await timezoneUtils.getTimezone(c, adminUser.activeIp);
		await this.setIpDetailContext(c, newUserInfo, 'createIp');
		await this.setIpDetailContext(c, adminUser);
		roleInfo = await this.attachRolePermInfo(c, roleInfo);
		adminUser.role = await this.attachRolePermInfo(c, adminUser.role);
		const message = adminCreateUserMsgTemplate(newUserInfo, roleInfo, adminUser);
		await this.emitWebhookEvent(c, 'admin.user.create', message, EVENT_LEVEL.INFO, { userId: newUserInfo?.userId, email: newUserInfo?.email, admin: adminUser?.email || '-' });
	},

	async sendEmailSentNotification(c, emailInfo, userInfo) {
		const { customDomain } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: emailInfo.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404';
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = sendEmailMsgTemplate(emailInfo, userInfo);
		await this.emitWebhookEvent(c, 'email.sent', message, EVENT_LEVEL.INFO, { emailId: emailInfo?.emailId, userId: userInfo?.userId, from: emailInfo?.sendEmail, to: emailInfo?.toEmail, webAppUrl }, { inline_keyboard: [[{ text: 'Check', web_app: { url: webAppUrl } }]] });
	},

	async sendEmailSoftDeleteNotification(c, emailIds, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = softDeleteEmailMsgTemplate(emailIds, userInfo);
		await this.emitWebhookEvent(c, 'email.delete.soft', message, EVENT_LEVEL.INFO, { emailIds, userId: userInfo?.userId });
	},

	async sendEmailHardDeleteNotification(c, emailIds, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = hardDeleteEmailMsgTemplate(emailIds, userInfo);
		await this.emitWebhookEvent(c, 'email.delete.hard', message, EVENT_LEVEL.WARN, { emailIds, userId: userInfo?.userId });
	},

	async sendAddAddressNotification(c, addressInfo, userInfo, totalAddresses) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = addAddressMsgTemplate(addressInfo, userInfo, totalAddresses);
		await this.emitWebhookEvent(c, 'account.address.add', message, EVENT_LEVEL.INFO, { email: addressInfo?.email, userId: userInfo?.userId });
	},

	async sendDeleteAddressNotification(c, addressEmail, userInfo, remainingAddresses) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = deleteAddressMsgTemplate(addressEmail, userInfo, remainingAddresses);
		await this.emitWebhookEvent(c, 'account.address.delete', message, EVENT_LEVEL.WARN, { email: addressEmail, userId: userInfo?.userId });
	},

	async sendRoleChangeNotification(c, userInfo, oldRole, newRole, changedBy) {
		changedBy.timezone = await timezoneUtils.getTimezone(c, changedBy.activeIp);
		await this.setIpDetailContext(c, userInfo);
		await this.setIpDetailContext(c, changedBy);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		changedBy.role = await this.attachRolePermInfo(c, changedBy.role);
		oldRole = await this.attachRolePermInfo(c, oldRole);
		newRole = await this.attachRolePermInfo(c, newRole);
		const message = roleChangeMsgTemplate(userInfo, oldRole, newRole, changedBy);
		await this.emitWebhookEvent(c, 'admin.user.role_change', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, from: oldRole?.name, to: newRole?.name, by: changedBy?.email || '-' });
	},

	async sendUserStatusChangeNotification(c, userInfo, oldStatus, newStatus, changedBy) {
		changedBy.timezone = await timezoneUtils.getTimezone(c, changedBy.activeIp);
		await this.setIpDetailContext(c, userInfo);
		await this.setIpDetailContext(c, changedBy);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		changedBy.role = await this.attachRolePermInfo(c, changedBy.role);
		const message = userStatusChangeMsgTemplate(userInfo, oldStatus, newStatus, changedBy);
		await this.emitWebhookEvent(c, 'admin.user.status_change', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, oldStatus, newStatus, by: changedBy?.email || '-' });
	},

	async sendPasswordResetNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = passwordResetMsgTemplate(userInfo);
		await this.emitWebhookEvent(c, 'auth.password.reset', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email });
	},

	async sendUserSelfDeleteNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = userSelfDeleteMsgTemplate(userInfo);
		await this.emitWebhookEvent(c, 'user.self_delete', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email });
	},

	async sendAdminDeleteUserNotification(c, deletedUser, adminUser) {
		adminUser.timezone = await timezoneUtils.getTimezone(c, adminUser.activeIp);
		await this.setIpDetailContext(c, deletedUser);
		await this.setIpDetailContext(c, adminUser);
		deletedUser.role = await this.attachRolePermInfo(c, deletedUser.role);
		adminUser.role = await this.attachRolePermInfo(c, adminUser.role);
		const message = adminDeleteUserMsgTemplate(deletedUser, adminUser);
		await this.emitWebhookEvent(c, 'admin.user.delete', message, EVENT_LEVEL.WARN, { deletedUserId: deletedUser?.userId, admin: adminUser?.email || '-' });
	},


	async sendRoleManageNotification(c, action, roleInfo, actorInfo, extra = '') {
		actorInfo.timezone = await timezoneUtils.getTimezone(c, actorInfo.activeIp);
		await this.setIpDetailContext(c, actorInfo);
		actorInfo.role = await this.attachRolePermInfo(c, actorInfo.role);

		if (roleInfo?.roleId !== undefined && roleInfo?.roleId !== null) {
			const roleRow = await orm(c).select().from(role).where(eq(role.roleId, roleInfo.roleId)).get();
			roleInfo = await this.attachRolePermInfo(c, roleRow || roleInfo);
		}

		const message = roleManageMsgTemplate(action, roleInfo, actorInfo, extra);
		await this.emitWebhookEvent(c, 'admin.role.manage', message, EVENT_LEVEL.INFO, { action, roleId: roleInfo?.roleId, actor: actorInfo?.email || '-' });
	},

	async sendFailedLoginNotification(c, email, ip, attempts, device, os, browser) {
		const userTimezone = await timezoneUtils.getTimezone(c, ip);
		const ipDetail = await this.queryIpSecurity(c, ip);
		const message = failedLoginMsgTemplate(email, ip, attempts, device, os, browser, userTimezone, ipDetail);
		await this.emitWebhookEvent(c, 'auth.login.failed', message, EVENT_LEVEL.WARN, { email, ip, attempts, device, os, browser, vpn: ipDetail?.security?.vpn || false, proxy: ipDetail?.security?.proxy || false, tor: ipDetail?.security?.tor || false });
		await this.sendSecurityEventAlert(c, `Failed login: ${email || '-'}`, `IP: <code>${ip || '-'}</code> | Attempts: ${attempts || 0}`);
	},

	async sendQuotaWarningNotification(c, userInfo, quotaType) {
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = quotaWarningMsgTemplate(userInfo, quotaType);
		await this.emitWebhookEvent(c, 'quota.warning', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email, quotaType });
	},

	async parseAllowedChatIds(c) {
		const envValue = c.env.CHAT_ID || c.env.TG_CHAT_ID || c.env.tgChatId;
		let raw = envValue;
		if (!raw) {
			try {
				const setting = await settingService.query(c);
				raw = setting?.tgChatId;
			} catch (e) {
				console.error('Failed to load tgChatId from setting:', e.message);
			}
		}
		return String(raw || '')
			.split(',')
			.map(item => item.trim())
			.filter(Boolean);
	},

	async isAllowedChat(c, chatId, userId) {
		const allowed = await this.parseAllowedChatIds(c);
		if (allowed.length === 0) {
			return false;
		}
		const chatIdStr = String(chatId);
		const userIdStr = userId !== undefined && userId !== null ? String(userId) : null;
		return allowed.includes(chatIdStr) || (userIdStr && allowed.includes(userIdStr));
	},


	buildWebhookUrl(c) {
		const url = new URL(c.req.url);
		url.pathname = '/api/telegram/webhook';
		url.search = '';
		url.hash = '';
		return url.toString();
	},

	async getWebhookInfo(c) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) {
			return { ok: false, description: 'Bot token is empty' };
		}
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/getWebhookInfo`);
		const data = await res.json().catch(() => ({ ok: false, description: 'Invalid Telegram response' }));
		return data;
	},

	async setWebhook(c) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) {
			return { ok: false, description: 'Bot token is empty' };
		}
		const webhookUrl = this.buildWebhookUrl(c);
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/setWebhook`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ url: webhookUrl, allowed_updates: ['message', 'edited_message', 'channel_post', 'callback_query'] })
		});
		const data = await res.json().catch(() => ({ ok: false, description: 'Invalid Telegram response' }));
		return { ...data, webhookUrl };
	},

	async deleteWebhook(c) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) {
			return { ok: false, description: 'Bot token is empty' };
		}
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/deleteWebhook`);
		const data = await res.json().catch(() => ({ ok: false, description: 'Invalid Telegram response' }));
		return data;
	},
	async sendTelegramReply(c, chatId, message, replyMarkup = null) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) return;
		const payload = {
			chat_id: String(chatId),
			parse_mode: 'HTML',
			text: message,
		};
		if (replyMarkup) payload.reply_markup = replyMarkup;
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		});
		if (!res.ok) {
			console.error(`Failed to send Telegram bot reply status: ${res.status} response: ${await res.text()}`);
		}
	},

	async editTelegramReply(c, chatId, messageId, message, replyMarkup = null) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) return;
		const payload = {
			chat_id: String(chatId),
			message_id: messageId,
			parse_mode: 'HTML',
			text: message,
		};
		if (replyMarkup) payload.reply_markup = replyMarkup;
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/editMessageText`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		});
		if (!res.ok) {
			console.error(`Failed to edit Telegram bot reply status: ${res.status} response: ${await res.text()}`);
			return false;
		}
		return true;
	},

	async answerCallbackQuery(c, callbackQueryId) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken || !callbackQueryId) return;
		await fetch(`https://api.telegram.org/bot${tgBotToken}/answerCallbackQuery`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ callback_query_id: callbackQueryId })
		});
	},

	buildMainMenu() {
		return {
			inline_keyboard: [
				[{ text: '📊 Status', callback_data: 'cmd:status' }, { text: '🛡️ Role', callback_data: 'cmd:role' }],
				[{ text: '📨 Mail', callback_data: 'cmd:mail:1' }, { text: '👥 Users', callback_data: 'cmd:users:1' }],
				[{ text: '🔐 Security', callback_data: 'cmd:security' }, { text: '🌐 Whois', callback_data: 'cmd:whois:help' }],
				[{ text: '📈 Stats', callback_data: 'cmd:stats:7d' }, { text: '🎟️ Invite', callback_data: 'cmd:invite:1' }],
				[{ text: '🧭 System', callback_data: 'cmd:system' }, { text: '🗂 Events', callback_data: 'cmd:events:1' }],
				[{ text: '🔎 Searchs', callback_data: 'cmd:searchs' }, { text: '🆔 Chat ID', callback_data: 'cmd:chatid' }],
				[{ text: '❓ Help', callback_data: 'cmd:help' }]
			]
		};
	},

	buildPager(command, page, hasNext) {
		const buttons = [];
		if (page > 1) buttons.push({ text: '⬅️ Prev', callback_data: `cmd:${command}:${page - 1}` });
		buttons.push({ text: `📄 ${page}`, callback_data: 'cmd:noop' });
		if (hasNext) buttons.push({ text: 'Next ➡️', callback_data: `cmd:${command}:${page + 1}` });
		return { inline_keyboard: [buttons, [{ text: '🏠 Menu', callback_data: 'cmd:menu' }]] };
	},

	buildDetailMenu({ backText, backCallbackData, previewUrl }) {
		const rows = [];
		if (previewUrl) {
			rows.push([{ text: '🔎 Open Email Preview', web_app: { url: previewUrl } }]);
		}
		rows.push([
			{ text: backText || '⬅️ Back to List', callback_data: backCallbackData || 'cmd:menu' },
			{ text: '🏠 Menu', callback_data: 'cmd:menu' }
		]);
		return { inline_keyboard: rows };
	},


	buildSearchMenu() {
		return {
			inline_keyboard: [
				[{ text: '👤 User/Address', callback_data: 'cmd:searchhelp:user' }, { text: '📨 Email ID', callback_data: 'cmd:searchhelp:email' }],
				[{ text: '🎟 Invite Code', callback_data: 'cmd:searchhelp:invite' }, { text: '🛡 Role', callback_data: 'cmd:searchhelp:role' }],
				[{ text: '🌐 IP Lookup', callback_data: 'cmd:whois:help' }],
				[{ text: '🏠 Menu', callback_data: 'cmd:menu' }]
			]
		};
	},

	async sendSecurityEventAlert(c, title, detail = '', callbackData = 'cmd:security') {
		const allowed = await this.parseAllowedChatIds(c);
		if (!allowed.length) return;
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) return;
		const text = `🚨 <b>Security Event</b>\n${title}${detail ? `\n${detail}` : ''}`;
		const replyMarkup = { inline_keyboard: [[{ text: '🔐 Open Security', callback_data: callbackData }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] };
		await Promise.all(allowed.map(async chatId => {
			const payload = { chat_id: chatId, parse_mode: 'HTML', text, reply_markup: replyMarkup };
			await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload)
			});
		}));
	},

	formatSearchHelp(scope = 'general') {
		if (scope === 'user') {
			return `🔎 <b>/search user</b>\nContoh:\n• <code>/search user 2</code>\n• <code>/search user abyn@abyn.xyz</code>\n• <code>/search user abyn@abyn.xyz/2</code>\n\nMenampilkan detail user/address + aktivitas terbaru di webhook_event_log.`;
		}
		if (scope === 'email') {
			return `🔎 <b>/search email</b>\nContoh: <code>/search email 121</code>\nMenampilkan detail email sesuai email id.`;
		}
		if (scope === 'invite') {
			return `🔎 <b>/search invite</b>\nContoh:\n• <code>/search invite 6</code>\n• <code>/search invite SLEfZUtS</code>`;
		}
		if (scope === 'role') {
			return `🔎 <b>/search role</b>\nContoh:\n• <code>/search role 1</code>\n• <code>/search role normal users</code>`;
		}
		return `🔎 <b>/searchs</b>\nGunakan menu search atau command: \n• <code>/search user &lt;userId|email|email/userId&gt;</code>\n• <code>/search email &lt;emailId&gt;</code>\n• <code>/search invite &lt;inviteId|code&gt;</code>\n• <code>/search role &lt;roleId|name&gt;</code>\n• <code>/search ip &lt;ip&gt;</code> (setara <code>/whois</code>)`;
	},

	async queryRecentActivity(c, { userId = null, address = null, accountId = null, ip = null }, limit = 5) {
		const conditions = [];
		const params = [];
		if (userId) {
			conditions.push("COALESCE(json_extract(meta, '$.userId'), 0) = ?");
			params.push(Number(userId));
		}
		if (address) {
			conditions.push('(message LIKE ? OR meta LIKE ?)');
			params.push(`%${address}%`, `%${address}%`);
		}
		if (accountId) {
			conditions.push('(message LIKE ? OR meta LIKE ?)');
			params.push(`%account_id ${accountId}%`, `%"accountId":${accountId}%`);
		}
		if (ip) {
			conditions.push('(message LIKE ? OR COALESCE(json_extract(meta, "$.ip"), "") = ?)');
			params.push(`%${ip}%`, ip);
		}
		if (!conditions.length) return [];
		const sql = `
			SELECT log_id as logId, event_type as eventType, level, message, create_time as createTime
			FROM webhook_event_log
			WHERE ${conditions.join(' OR ')}
			ORDER BY log_id DESC
			LIMIT ?
		`;
		const rows = await c.env.db.prepare(sql).bind(...params, limit).all();
		return rows?.results || [];
	},

	formatActivityBlock(items = []) {
		if (!items.length) return 'Aktivitas terbaru: -';
		const lines = items.map(item => {
			const oneLine = String(item.message || '').split('\n').find(Boolean) || '-';
			return `• #${item.logId} [${item.level}] ${item.eventType} | ${item.createTime}\n  ${oneLine.slice(0, 140)}`;
		});
		return `Aktivitas terbaru:\n${lines.join('\n')}`;
	},

	parseRangeDays(rangeArg = '7d') {
		const value = String(rangeArg || '7d').trim().toLowerCase();
		const match = /^(\d{1,2})d$/.exec(value);
		if (!match) return 7;
		return Math.max(1, Math.min(30, Number(match[1])));
	},

	async formatSecurityCommand(c) {
		const { results } = await c.env.db.prepare(`
			SELECT ip, update_time, data
			FROM ip_security_cache
			WHERE
				COALESCE(json_extract(data, '$.security.vpn'), 0) = 1
				OR COALESCE(json_extract(data, '$.security.proxy'), 0) = 1
				OR COALESCE(json_extract(data, '$.security.tor'), 0) = 1
				OR COALESCE(json_extract(data, '$.security.relay'), 0) = 1
			ORDER BY update_time DESC
			LIMIT 10
		`).all();
		if (!results?.length) {
			return { text: `🔐 <b>/security</b>
No risky IP found in cache.`, replyMarkup: this.buildMainMenu() };
		}
		const lines = results.map((row, idx) => {
			let detail = {};
			try { detail = JSON.parse(row.data || '{}'); } catch (_) {}
			const sec = detail.security || {};
			const location = detail.location || {};
			return `${idx + 1}. <code>${row.ip || '-'}</code> | vpn=${sec.vpn ? 'Y' : 'N'} proxy=${sec.proxy ? 'Y' : 'N'} tor=${sec.tor ? 'Y' : 'N'} relay=${sec.relay ? 'Y' : 'N'}
   Loc: ${location.country || '-'} / ${location.city || '-'} | Updated: ${row.update_time || '-'}`;
		}).join('\n');
		const failedRows = await c.env.db.prepare(`
			SELECT log_id as logId, message, create_time as createTime
			FROM webhook_event_log
			WHERE event_type = 'auth.login.failed'
			ORDER BY log_id DESC
			LIMIT 5
		`).all();
		const failedItems = failedRows?.results || [];
		const failedPreview = failedItems.map(item => {
			const oneLine = String(item.message || '').split('\n').slice(0, 2).join(' ').trim();
			return `• #${item.logId} ${oneLine}\n  At: ${item.createTime || '-'}`;
		}).join('\n');
		const securityButtons = failedItems.map(item => ([{ text: `🧾 Security Event #${item.logId}`, callback_data: `cmd:securityevent:${item.logId}` }]));
		const replyMarkup = securityButtons.length > 0
			? { inline_keyboard: [...securityButtons, [{ text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
			: this.buildMainMenu();
		return { text: `🔐 <b>/security</b>

${lines}

⚠️ <b>Recent failed login events</b>
${failedPreview || '-'}

Tip: tap Security Event button or use <code>/security event &lt;id&gt;</code>.` , replyMarkup };
	},

	async formatSecurityEventDetailCommand(c, eventIdArg) {
		return await this.formatEventDetailCommand(c, eventIdArg, { fromSecurity: true });
	},

	async formatWhoisCommand(c, ipArg) {
		const ip = String(ipArg || '').trim();
		if (!ip || ip === 'help') {
			return {
				text: `🌐 <b>/whois</b>
Usage: <code>/whois 1.1.1.1</code>`,
				replyMarkup: this.buildMainMenu()
			};
		}
		const detail = await this.queryIpSecurity(c, ip);
		const sec = detail?.security || {};
		const loc = detail?.location || {};
		const net = detail?.network || {};
		const relatedUsersRows = await c.env.db.prepare(`
			SELECT user_id as userId, email, type, status, active_ip as activeIp, create_ip as createIp
			FROM user
			WHERE is_del = 0 AND (active_ip = ? OR create_ip = ?)
			ORDER BY user_id DESC
			LIMIT 10
		`).bind(ip, ip).all();
		const relatedUsers = relatedUsersRows?.results || [];
		const userLines = relatedUsers.map(item => `• #${item.userId} ${item.email} | role=${item.type} status=${item.status} | active=${item.activeIp || '-'} create=${item.createIp || '-'}`).join('\n');
		return {
			text: `🌐 <b>/whois</b>

IP: <code>${ip}</code>
VPN/Proxy/Tor/Relay: ${sec.vpn ? 'Y' : 'N'}/${sec.proxy ? 'Y' : 'N'}/${sec.tor ? 'Y' : 'N'}/${sec.relay ? 'Y' : 'N'}
Location: ${loc.city || '-'}, ${loc.region || '-'}, ${loc.country || '-'} (${loc.country_code || '-'})
ASN Org: ${net.autonomous_system_organization || '-'}
ASN: ${net.autonomous_system_number || '-'}

👥 <b>Accounts with this IP</b>
${userLines || '-'}`,
			replyMarkup: this.buildMainMenu()
		};
	},

	async formatStatsCommand(c, rangeArg = '7d') {
		const days = this.parseRangeDays(rangeArg);
		const offset = `-${days - 1} day`;
		const [regRows, receiveRows, sendRows] = await Promise.all([
			c.env.db.prepare(`SELECT DATE(create_time) as day, COUNT(*) as total FROM user WHERE DATE(create_time) BETWEEN DATE('now', ?) AND DATE('now') GROUP BY DATE(create_time) ORDER BY day ASC`).bind(offset).all(),
			c.env.db.prepare(`SELECT DATE(create_time) as day, COUNT(*) as total FROM email WHERE type = 0 AND DATE(create_time) BETWEEN DATE('now', ?) AND DATE('now') GROUP BY DATE(create_time) ORDER BY day ASC`).bind(offset).all(),
			c.env.db.prepare(`SELECT DATE(create_time) as day, COUNT(*) as total FROM email WHERE type = 1 AND DATE(create_time) BETWEEN DATE('now', ?) AND DATE('now') GROUP BY DATE(create_time) ORDER BY day ASC`).bind(offset).all()
		]);
		const regMap = new Map((regRows.results || []).map(r => [r.day, Number(r.total)]));
		const recvMap = new Map((receiveRows.results || []).map(r => [r.day, Number(r.total)]));
		const sendMap = new Map((sendRows.results || []).map(r => [r.day, Number(r.total)]));
		const lines = [];
		let regTotal = 0;
		let recvTotal = 0;
		let sendTotal = 0;
		for (let i = days - 1; i >= 0; i--) {
			const day = dayjs.utc().subtract(i, 'day').format('YYYY-MM-DD');
			const reg = regMap.get(day) || 0;
			const recv = recvMap.get(day) || 0;
			const send = sendMap.get(day) || 0;
			regTotal += reg; recvTotal += recv; sendTotal += send;
			lines.push(`${day}: U=${reg} | R=${recv} | S=${send}`);
		}
		return {
			text: `📈 <b>/stats ${days}d</b>

Total Reg: ${regTotal}
Total Receive: ${recvTotal}
Total Send: ${sendTotal}

${lines.join('\n')}`,
			replyMarkup: this.buildMainMenu()
		};
	},

	async formatEventsCommand(c, page = 1) {
		const pageSize = 5;
		try {
			const currentPage = Math.max(1, Number(page) || 1);
			const rows = await c.env.db.prepare(`
				SELECT log_id as logId, event_type as eventType, level, message, create_time as createTime
				FROM webhook_event_log
				ORDER BY log_id DESC
				LIMIT ? OFFSET ?
			`).bind(pageSize + 1, (currentPage - 1) * pageSize).all();
			const items = rows.results || [];
			if (!items.length) {
				return { text: `🗂 <b>/events</b>
No webhook event logs yet.`, replyMarkup: this.buildMainMenu() };
			}
			const hasNext = items.length > pageSize;
			const visible = hasNext ? items.slice(0, pageSize) : items;
			const body = visible.map(item => {
				const lines = String(item.message || '').split('\n').filter(Boolean);
				const preview = lines.slice(0, 3).join('\n');
				const truncated = lines.length > 3 ? '\n…' : '';
				return `#${item.logId} [${item.level}] ${item.eventType}\n${preview}${truncated}\nAt: ${item.createTime}`;
			}).join('\n\n');
			const eventButtons = visible.map(item => [{ text: `🧾 #${item.logId} ${item.eventType}`, callback_data: `cmd:event:${item.logId}:${currentPage}` }]);
			const pagerMarkup = this.buildPager('events', currentPage, hasNext);
			const replyMarkup = {
				inline_keyboard: [...eventButtons, ...(pagerMarkup?.inline_keyboard || [])]
			};
			return { text: `🗂 <b>/events</b> (page ${currentPage})

${body}

Tip: tap event buttons below or use <code>/event &lt;id&gt;</code> for full detail + preview link.`, replyMarkup };
		} catch (e) {
			return { text: `🗂 <b>/events</b>
Unable to query event log: ${e.message}`, replyMarkup: this.buildMainMenu() };
		}
	},

	async formatEventDetailCommand(c, idArg, options = {}) {
		const logId = Number(idArg || 0);
		const fromSecurity = Boolean(options?.fromSecurity);
		const backPage = Math.max(1, Number(options?.backPage || 1));
		if (!logId) {
			return { text: `🧾 <b>/event</b>
Usage: <code>/event 123</code>`, replyMarkup: this.buildDetailMenu({ backText: '🗂 Events List', backCallbackData: 'cmd:events:1' }) };
		}
		const row = await c.env.db.prepare(`
			SELECT log_id as logId, event_type as eventType, level, message, meta, create_time as createTime
			FROM webhook_event_log
			WHERE log_id = ?
		`).bind(logId).first();
		if (!row) {
			return { text: `🧾 <b>/event</b>
Event #${logId} not found.`, replyMarkup: this.buildDetailMenu({ backText: fromSecurity ? '🔐 Security List' : '🗂 Events List', backCallbackData: fromSecurity ? 'cmd:security' : `cmd:events:${backPage}` }) };
		}
		let meta = {};
		try { meta = row.meta ? JSON.parse(row.meta) : {}; } catch (_) {}
		const previewUrl = meta?.webAppUrl;
		const detail = `🧾 <b>/event ${row.logId}</b>

Type: ${row.eventType}
Level: ${row.level}
At: ${row.createTime}
Message: ${row.message}

Meta: <code>${JSON.stringify(meta || {}, null, 2).slice(0, 1200)}</code>`;
		const replyMarkup = this.buildDetailMenu({
			backText: fromSecurity ? '🔐 Security List' : '🗂 Events List',
			backCallbackData: fromSecurity ? 'cmd:security' : `cmd:events:${backPage}`,
			previewUrl
		});
		return { text: detail, replyMarkup };
	},

	async formatMailCommand(c, page = 1) {
		const pageSize = 10;
		const currentPage = Math.max(1, Number(page) || 1);
		const rows = await orm(c).select({
			emailId: email.emailId,
			sendEmail: email.sendEmail,
			toEmail: email.toEmail,
			subject: email.subject,
			type: email.type,
			isDel: email.isDel,
			createTime: email.createTime,
		}).from(email).orderBy(desc(email.emailId)).limit(pageSize + 1).offset((currentPage - 1) * pageSize);

		if (rows.length === 0) return { text: `📭 <b>/mail</b>
No email data.`, replyMarkup: this.buildMainMenu() };
		const hasNext = rows.length > pageSize;
		const visibleRows = hasNext ? rows.slice(0, pageSize) : rows;
		const body = visibleRows.map(item => `🆔 <code>${item.emailId}</code> | ${item.type === 0 ? 'RECV' : 'SEND'} | del=${item.isDel}
From: <code>${item.sendEmail || '-'}</code>
To: <code>${item.toEmail || '-'}</code>
Subj: ${item.subject || '-'}
At: ${item.createTime}`).join('\n\n');
		const mailButtons = visibleRows.map(item => [{ text: `✉️ #${item.emailId} ${item.subject || '(no subject)'}`.slice(0, 64), callback_data: `cmd:mailid:${item.emailId}:${currentPage}` }]);
		const pagerMarkup = this.buildPager('mail', currentPage, hasNext);
		const replyMarkup = {
			inline_keyboard: [...mailButtons, ...(pagerMarkup?.inline_keyboard || [])]
		};
		return { text: `📨 <b>/mail</b> (page ${currentPage})

${body}

Tip: tap mail buttons below or use <code>/mail &lt;emailId&gt;</code> for detail + preview.`, replyMarkup };
	},

	async formatMailDetailCommand(c, emailIdArg, pageArg = 1) {
		const emailId = Number(emailIdArg || 0);
		const backPage = Math.max(1, Number(pageArg || 1));
		if (!emailId) {
			return { text: `📨 <b>/mail</b>\nUsage: <code>/mail 120</code> (detail) or <code>/mail 1</code> (page).`, replyMarkup: this.buildDetailMenu({ backText: '📨 Mail List', backCallbackData: 'cmd:mail:1' }) };
		}
		const row = await orm(c).select({
			emailId: email.emailId,
			sendEmail: email.sendEmail,
			toEmail: email.toEmail,
			subject: email.subject,
			text: email.text,
			type: email.type,
			createTime: email.createTime,
			userId: email.userId
		}).from(email).where(eq(email.emailId, emailId)).get();
		if (!row) {
			return { text: `📨 <b>/mail</b>\nEmail #${emailId} not found.`, replyMarkup: this.buildDetailMenu({ backText: '📨 Mail List', backCallbackData: `cmd:mail:${backPage}` }) };
		}
		const { customDomain } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: row.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : null;
		const meta = {
			emailId: row.emailId,
			userId: row.userId,
			from: row.sendEmail,
			to: row.toEmail,
			webAppUrl: webAppUrl || ''
		};
		const detail = `🧾 <b>/mail ${row.emailId}</b>

Type: ${row.type === 0 ? 'email.received' : 'email.sent'}
Level: info
At: ${row.createTime}
Message: ${row.type === 0 ? '📥 Email Received' : '📤 Email Sent'}

📧 From: ${row.sendEmail || '-'}
📨 To: ${row.toEmail || '-'}
📝 Subject: ${row.subject || '-'}
🆔 Email ID: ${row.emailId}
💬 Preview: ${(row.text || '').slice(0, 120) || '-'}

Meta: <code>${JSON.stringify(meta, null, 2)}</code>`;
		const replyMarkup = this.buildDetailMenu({ backText: '📨 Mail List', backCallbackData: `cmd:mail:${backPage}`, previewUrl: webAppUrl });
		return { text: detail, replyMarkup };
	},

	async formatUsersCommand(c, page = 1) {
		const pageSize = 5;
		const currentPage = Math.max(1, Number(page) || 1);
		const rows = await orm(c).select({
			userId: user.userId,
			email: user.email,
			status: user.status,
			isDel: user.isDel,
			type: user.type,
			activeIp: user.activeIp,
			sendCount: user.sendCount,
			createTime: user.createTime,
		}).from(user).orderBy(desc(user.userId)).limit(pageSize + 1).offset((currentPage - 1) * pageSize);
		if (rows.length === 0) return { text: `👤 <b>/users</b>
No user data.`, replyMarkup: this.buildMainMenu() };
		const hasNext = rows.length > pageSize;
		const visibleRows = hasNext ? rows.slice(0, pageSize) : rows;
		const visibleUserIds = visibleRows.map(item => item.userId);
		let receiveCountMap = new Map();
		if (visibleUserIds.length > 0) {
			const placeholders = visibleUserIds.map(() => '?').join(',');
			const { results } = await c.env.db.prepare(`
				SELECT user_id as userId, COUNT(*) as receiveCount
				FROM email
				WHERE type = 0 AND is_del = 0 AND user_id IN (${placeholders})
				GROUP BY user_id
			`).bind(...visibleUserIds).all();
			receiveCountMap = new Map((results || []).map(row => [row.userId, row.receiveCount]));
		}
		const roleRows = await orm(c).select().from(role);
		const map = new Map(roleRows.map(r => [r.roleId, r.name]));
		const bodyParts = [];
		for (const item of visibleRows) {
			const ipDetail = await this.queryIpSecurity(c, item.activeIp);
			const security = ipDetail?.security || {};
			const location = ipDetail?.location || {};
			bodyParts.push(`🆔 <code>${item.userId}</code> ${item.email}
Role: ${map.get(item.type) || (item.type === 0 ? 'admin' : 'unknown')} | Status: ${item.status} | Deleted: ${item.isDel}
Send Count: ${item.sendCount || 0} | Receive Count: ${receiveCountMap.get(item.userId) || 0}
Created: ${item.createTime || '-'}
IP: <code>${item.activeIp || '-'}</code>
VPNAPI: vpn=${security.vpn ? 'Y' : 'N'} proxy=${security.proxy ? 'Y' : 'N'} tor=${security.tor ? 'Y' : 'N'}
Loc: ${location.country || '-'} / ${location.city || '-'}`);
		}
		return { text: `👥 <b>/users</b> (page ${currentPage})

${bodyParts.join('\n\n')}`, replyMarkup: this.buildPager('users', currentPage, hasNext) };
	},

	async formatRoleCommand(c) {
		const rows = await orm(c).select().from(role);
		if (rows.length === 0) return `🛡️ <b>/role</b>
No role data.`;
		const roleRows = await Promise.all(rows.map(async item => this.attachRolePermInfo(c, { ...item })));
		const body = roleRows.map(item => {
			const sendDisplay = !item.canSendEmail
				? 'Unauthorized'
				: ((item.sendCount || 0) === 0 ? 'Unlimited' : `${item.sendType || '-'} / ${item.sendCount ?? '-'}`);
			const addressDisplay = !item.canAddAddress
				? 'Unauthorized'
				: ((item.accountCount || 0) === 0 ? 'Unlimited' : `${item.accountCount ?? '-'}`);
			return `🆔 <code>${item.roleId}</code> ${item.name}
Send: ${sendDisplay}
Address limit: ${addressDisplay}
Permission: send=${item.canSendEmail ? 'Yes' : 'No'} | add-address=${item.canAddAddress ? 'Yes' : 'No'}
Default: ${item.isDefault ? 'Yes' : 'No'}
Ban email: ${item.banEmail || '-'}
Avail domain: ${item.availDomain || '-'}`;
		}).join('\n\n');
		return `🛡️ <b>/role</b>

${body}`;
	},

	async formatInviteCommand(c, page = 1) {
		const pageSize = 10;
		const currentPage = Math.max(1, Number(page) || 1);
		const rows = await orm(c).select({
			regKeyId: regKey.regKeyId,
			code: regKey.code,
			count: regKey.count,
			roleId: regKey.roleId,
			expireTime: regKey.expireTime,
			createTime: regKey.createTime,
		}).from(regKey).orderBy(desc(regKey.regKeyId)).limit(pageSize + 1).offset((currentPage - 1) * pageSize);
		if (rows.length === 0) return { text: `🎟️ <b>/invite</b>
No invite code data.`, replyMarkup: this.buildMainMenu() };
		const hasNext = rows.length > pageSize;
		const visibleRows = hasNext ? rows.slice(0, pageSize) : rows;
		const body = visibleRows.map(item => `🆔 <code>${item.regKeyId}</code> <code>${item.code}</code>`).join('\n');
		const inviteButtons = visibleRows.map(item => [{ text: `🎟️ Detail #${item.regKeyId} ${item.code}`.slice(0, 64), callback_data: `cmd:inviteid:${item.regKeyId}:${currentPage}` }]);
		const pagerMarkup = this.buildPager('invite', currentPage, hasNext);
		const replyMarkup = { inline_keyboard: [...inviteButtons, ...(pagerMarkup?.inline_keyboard || [])] };
		return { text: `🎟️ <b>/invite</b> (page ${currentPage})

${body}`, replyMarkup };
	},

	async formatInviteDetailCommand(c, inviteIdArg, pageArg = 1) {
		const inviteId = Number(inviteIdArg || 0);
		const backPage = Math.max(1, Number(pageArg || 1));
		if (!inviteId) {
			return { text: `🎟️ <b>/invite</b>\nUsage: <code>/invite 6</code>`, replyMarkup: this.buildDetailMenu({ backText: '🎟 Invite List', backCallbackData: 'cmd:invite:1' }) };
		}
		const item = await orm(c).select({
			regKeyId: regKey.regKeyId,
			code: regKey.code,
			count: regKey.count,
			roleId: regKey.roleId,
			userId: regKey.userId,
			expireTime: regKey.expireTime,
			createTime: regKey.createTime,
		}).from(regKey).where(eq(regKey.regKeyId, inviteId)).get();
		if (!item) {
			return { text: `🎟️ <b>/invite</b>\nInvite #${inviteId} not found.`, replyMarkup: this.buildDetailMenu({ backText: '🎟 Invite List', backCallbackData: `cmd:invite:${backPage}` }) };
		}
		const roleInfo = await orm(c).select({ roleId: role.roleId, name: role.name }).from(role).where(eq(role.roleId, item.roleId)).get();
		let usedBy = '-';
		if (item.userId && Number(item.userId) > 0) {
			const usedUser = await orm(c).select({ userId: user.userId, email: user.email, createTime: user.createTime }).from(user).where(eq(user.userId, item.userId)).get();
			usedBy = usedUser ? `#${usedUser.userId} ${usedUser.email} (created: ${usedUser.createTime || '-'})` : `user_id ${item.userId}`;
		}
		const text = `🎟️ <b>/invite (page ${backPage})</b>

🆔 ${item.regKeyId} ${item.code}
Role: ${roleInfo?.name || item.roleId}
Remaining: ${item.count} | Expire: ${item.expireTime || '-'}
Created: ${item.createTime || '-'}
Used by: ${usedBy}`;
		return { text, replyMarkup: this.buildDetailMenu({ backText: '🎟 Invite List', backCallbackData: `cmd:invite:${backPage}` }) };
	},

	async formatStatusCommand(c) {
		const numberCount = await analysisDao.numberCount(c);
		const allowed = await this.parseAllowedChatIds(c);
		const botEnabled = Boolean((await settingService.query(c)).tgBotToken);
		return `📊 <b>/status</b>

Users: ${numberCount.userTotal}
Accounts: ${numberCount.accountTotal}
Receive Emails: ${numberCount.receiveTotal}
Send Emails: ${numberCount.sendTotal}

🤖 Bot enabled: ${botEnabled ? 'Yes' : 'No'}
🔐 Allowed CHAT_ID: ${allowed.length > 0 ? allowed.join(', ') : '(empty)'}`;
	},

	async formatSystemCommand(c) {
		try {
			const [cacheCount, staleCount, webhookInfo, recentSystemLogs] = await Promise.all([
			c.env.db.prepare('SELECT COUNT(*) as total FROM ip_security_cache').first(),
			c.env.db.prepare("SELECT COUNT(*) as total FROM ip_security_cache WHERE update_time <= datetime('now', '-2 day')").first(),
			this.getWebhookInfo(c),
			c.env.db.prepare(`
				SELECT level, event_type as eventType, message, create_time as createTime
				FROM webhook_event_log
				WHERE event_type LIKE 'email.%' OR level = 'error'
				ORDER BY log_id DESC
				LIMIT 3
			`).all()
		]);
		const webhookUrl = webhookInfo?.result?.url || '-';
			const pending = webhookInfo?.result?.pending_update_count ?? '-';
			const lastError = webhookInfo?.result?.last_error_message || '-';
			const pushMode = await this.shouldSendWebhookPush(c) ? 'Push + Log' : 'Log only (default, no spam)';
			const logs = (recentSystemLogs?.results || []).map((row, index) => {
				const firstLine = String(row.message || '').split('\n').find(Boolean) || '-';
				const shortLine = firstLine.length > 180 ? `${firstLine.slice(0, 177)}...` : firstLine;
				return `${index + 1}. [${row.createTime || '-'}] [${row.level || '-'}] ${row.eventType}: ${shortLine}`;
			}).join('\n');
		return `🧭 <b>/system</b>

IP Cache Rows: ${cacheCount?.total || 0}
Stale (≥2 days): ${staleCount?.total || 0}

Webhook URL: <code>${webhookUrl}</code>
Pending Updates: ${pending} (queued updates waiting delivery)
Last Error: ${lastError}
Webhook Notify Mode: ${pushMode}

📜 Recent Email/Error Logs (3):
${logs || 'No logs yet.'}`;
		} catch (e) {
			return `🧭 <b>/system</b>\nUnable to query system logs: ${e.message}`;
		}
	},



	async formatSearchsCommand(c) {
		return { text: this.formatSearchHelp('general'), replyMarkup: this.buildSearchMenu() };
	},

	async formatSearchCommand(c, typeArg, queryArgs = []) {
		const type = String(typeArg || '').toLowerCase();
		const query = String((queryArgs || []).join(' ').trim());
		if (!type) return { text: this.formatSearchHelp('general'), replyMarkup: this.buildSearchMenu() };
		if (type === 'ip') return await this.formatWhoisCommand(c, query);
		if (type === 'email') {
			const emailId = String(query || '').replace(/email\s*id/gi, '').trim();
			return await this.formatMailDetailCommand(c, emailId, 1);
		}
		if (type === 'invite') {
			if (!query) return { text: this.formatSearchHelp('invite'), replyMarkup: this.buildSearchMenu() };
			let row = null;
			if (/^\d+$/.test(query)) row = await orm(c).select({ regKeyId: regKey.regKeyId }).from(regKey).where(eq(regKey.regKeyId, Number(query))).get();
			if (!row) {
				const byCode = await c.env.db.prepare('SELECT rege_key_id as regKeyId FROM reg_key WHERE code = ? LIMIT 1').bind(query).first();
				if (byCode) row = byCode;
			}
			if (!row?.regKeyId) return { text: `🔎 <b>/search invite</b>\nInvite tidak ditemukan untuk: <code>${query}</code>`, replyMarkup: this.buildSearchMenu() };
			return await this.formatInviteDetailCommand(c, row.regKeyId, 1);
		}
		if (type === 'role') {
			if (!query) return { text: this.formatSearchHelp('role'), replyMarkup: this.buildSearchMenu() };
			let roleRow = null;
			if (/^\d+$/.test(query)) roleRow = await orm(c).select().from(role).where(eq(role.roleId, Number(query))).get();
			if (!roleRow) {
				const roleRows = await c.env.db.prepare('SELECT role_id as roleId FROM role WHERE LOWER(name) = LOWER(?) LIMIT 1').bind(query).all();
				if (roleRows?.results?.[0]?.roleId !== undefined) roleRow = await orm(c).select().from(role).where(eq(role.roleId, roleRows.results[0].roleId)).get();
			}
			if (!roleRow) return { text: `🔎 <b>/search role</b>\nRole tidak ditemukan: <code>${query}</code>`, replyMarkup: this.buildSearchMenu() };
			const roleInfo = await this.attachRolePermInfo(c, { ...roleRow });
			const sendDisplay = !roleInfo.canSendEmail
				? 'Unauthorized'
				: ((roleInfo.sendCount || 0) === 0 ? 'Unlimited' : `${roleInfo.sendType || '-'} / ${roleInfo.sendCount ?? '-'}`);
			const addressDisplay = !roleInfo.canAddAddress
				? 'Unauthorized'
				: ((roleInfo.accountCount || 0) === 0 ? 'Unlimited' : `${roleInfo.accountCount ?? '-'}`);
			return {
				text: `🔎 <b>Search Result: Role</b>\n\n🆔 <code>${roleInfo.roleId}</code> ${roleInfo.name}\nSend: ${sendDisplay}\nAddress limit: ${addressDisplay}`,
				replyMarkup: this.buildSearchMenu()
			};
		}
		if (type === 'user' || type === 'account' || type === 'address') {
			if (!query) return { text: this.formatSearchHelp('user'), replyMarkup: this.buildSearchMenu() };
			const [addressPartRaw, accountPartRaw] = query.split('/');
			const addressPart = String(addressPartRaw || '').trim();
			const accountPart = String(accountPartRaw || '').replace(/akun\s*id/gi, '').trim();
			let matchedUser = null;
			let matchedAccount = null;
			if (/^\d+$/.test(addressPart)) {
				matchedUser = await orm(c).select().from(user).where(eq(user.userId, Number(addressPart))).get();
				if (!matchedUser) {
					matchedAccount = await orm(c).select({ accountId: account.accountId, email: account.email, userId: account.userId }).from(account).where(eq(account.accountId, Number(addressPart))).get();
				}
			} else if (addressPart) {
				const userRows = await c.env.db.prepare('SELECT user_id as userId FROM user WHERE LOWER(email) = LOWER(?) LIMIT 1').bind(addressPart).all();
				if (userRows?.results?.[0]?.userId) matchedUser = await orm(c).select().from(user).where(eq(user.userId, userRows.results[0].userId)).get();
				if (!matchedUser) {
					const accountRows = await c.env.db.prepare('SELECT account_id as accountId, user_id as userId, email FROM account WHERE LOWER(email) = LOWER(?) AND is_del = 0 LIMIT 1').bind(addressPart).all();
					if (accountRows?.results?.[0]) matchedAccount = accountRows.results[0];
				}
			}
			if (accountPart && /^\d+$/.test(accountPart)) {
				matchedAccount = await orm(c).select({ accountId: account.accountId, email: account.email, userId: account.userId }).from(account).where(eq(account.accountId, Number(accountPart))).get();
			}
			if (!matchedUser && matchedAccount?.userId) matchedUser = await orm(c).select().from(user).where(eq(user.userId, matchedAccount.userId)).get();
			if (!matchedUser) return { text: `🔎 <b>/search user</b>\nData tidak ditemukan untuk: <code>${query}</code>`, replyMarkup: this.buildSearchMenu() };
			const recent = await this.queryRecentActivity(c, { userId: matchedUser.userId, address: matchedUser.email, accountId: matchedAccount?.accountId || null, ip: matchedUser.activeIp }, 5);
			const detail = `🔎 <b>Search Result: User</b>\n\nUser: #${matchedUser.userId} ${matchedUser.email}\nStatus: ${matchedUser.status} | Role ID: ${matchedUser.type}\nActive IP: <code>${matchedUser.activeIp || '-'}</code>\nAddress Match: ${matchedAccount ? `${matchedAccount.email} (account_id ${matchedAccount.accountId})` : '-'}\n\n${this.formatActivityBlock(recent)}`;
			return { text: detail, replyMarkup: this.buildSearchMenu() };
		}
		return { text: this.formatSearchHelp('general'), replyMarkup: this.buildSearchMenu() };
	},
	async resolveCommand(c, command, args, chatId, userId) {
		const pageArg = Number(args?.[0] || 1);
		if (command === '/searchs' && args?.[0]) {
			return { text: this.formatSearchHelp(args[0]), replyMarkup: this.buildSearchMenu() };
		}
		switch (command) {
			case '/start':
			case '/help':
				return {
					text: `🤖 <b>Cloud Mail Bot Command Center</b>

Use buttons below or type commands manually:

📊 <b>/status</b> — system counters + bot state
👥 <b>/users [page]</b> — users + send/receive + IP intelligence
📨 <b>/mail [page|emailId]</b> — recent emails with pager or detail by email id
🛡️ <b>/role</b> — role quota + authorization flags
🔐 <b>/security</b> — suspicious IP snapshot + recent failed-login events
🌐 <b>/whois &lt;ip&gt;</b> — live/cache IP intelligence lookup
📈 <b>/stats [range]</b> — timeline stats, e.g. <code>/stats 7d</code>
🧭 <b>/system</b> — webhook health + recent email/error logs
🗂 <b>/events [page]</b> — browse webhook/system event log
🧾 <b>/event &lt;id&gt;</b> — open one event detail + preview link
🎟️ <b>/invite [page]</b> — invitation codes
🔎 <b>/searchs</b> — quick search menu
🔎 <b>/search ...</b> — search user/email/invite/role/ip
🆔 <b>/chatid</b> — your current chat_id/user_id

<b>Examples:</b>
• <code>/users 2</code>
• <code>/whois 1.1.1.1</code>
• <code>/stats 3d</code>
• <code>/events 1</code>
• <code>/event 42</code>
• <code>/search user abyn@abyn.xyz/akun id 2</code>
• <code>/search email 121</code>`,
					replyMarkup: this.buildMainMenu()
				};
			case '/mail':
				if (args?.[0] === 'page') {
					return await this.formatMailCommand(c, Number(args?.[1] || 1));
				}
				if (/^\d+$/.test(String(args?.[0] || '')) && Number(args[0]) > 0 && Number(args[0]) <= 50) {
					return await this.formatMailCommand(c, Number(args[0]));
				}
				if (args?.[0]) {
					return await this.formatMailDetailCommand(c, args[0], args?.[1]);
				}
				return await this.formatMailCommand(c, pageArg);
			case '/users':
				return await this.formatUsersCommand(c, pageArg);
			case '/role':
				return { text: await this.formatRoleCommand(c), replyMarkup: this.buildMainMenu() };
			case '/invite':
				if (args?.[0] === 'detail') {
					return await this.formatInviteDetailCommand(c, args?.[1], args?.[2]);
				}
				if (args?.[0] && /^\d+$/.test(String(args[0])) && Number(args[0]) > 50) {
					return await this.formatInviteDetailCommand(c, args[0], 1);
				}
				return await this.formatInviteCommand(c, pageArg);
			case '/status':
				return { text: await this.formatStatusCommand(c), replyMarkup: this.buildMainMenu() };
			case '/chatid':
				return { text: `🆔 chat_id: <code>${chatId}</code>\n👤 user_id: <code>${userId || '-'}</code>`, replyMarkup: this.buildMainMenu() };
			case '/system':
				return { text: await this.formatSystemCommand(c), replyMarkup: this.buildMainMenu() };
			case '/security':
				if (args?.[0] === 'event') {
					return await this.formatSecurityEventDetailCommand(c, args?.[1]);
				}
				return await this.formatSecurityCommand(c);
			case '/whois':
				return await this.formatWhoisCommand(c, args?.[0]);
			case '/stats':
				return await this.formatStatsCommand(c, args?.[0] || '7d');
			case '/events':
				if (args?.[0] === 'page') {
					return await this.formatEventsCommand(c, Number(args?.[1] || 1));
				}
				if (args?.[0]) {
					return await this.formatEventDetailCommand(c, args[0]);
				}
				return await this.formatEventsCommand(c, pageArg);
			case '/event':
				return await this.formatEventDetailCommand(c, args?.[0], { backPage: args?.[1] });
			case '/searchs':
				return await this.formatSearchsCommand(c);
			case '/search':
				return await this.formatSearchCommand(c, args?.[0], args?.slice(1));
			default:
				return await this.resolveCommand(c, '/help', [], chatId, userId);
		}
	},

	async handleBotWebhook(c, body) {
		const callback = body?.callback_query;
		if (callback?.data) {
			const chatId = callback?.message?.chat?.id;
			const userId = callback?.from?.id;
			if (!chatId) return;
			await this.answerCallbackQuery(c, callback.id);
			if (!await this.isAllowedChat(c, chatId, userId)) return;
			if (callback.data === 'cmd:noop') return;
			if (callback.data === 'cmd:menu' || callback.data === 'cmd:help') {
				const result = await this.resolveCommand(c, '/help', [], chatId, userId);
				const edited = await this.editTelegramReply(c, chatId, callback.message.message_id, result.text, result.replyMarkup);
				if (!edited) await this.sendTelegramReply(c, chatId, result.text, result.replyMarkup);
				return;
			}

			let command = '/help';
			let args = [];
			const pagingMatch = /^cmd:(mail|users|invite|events):(\d+)$/.exec(callback.data);
			if (pagingMatch) {
				command = `/${pagingMatch[1]}`;
				if (pagingMatch[1] === 'mail' || pagingMatch[1] === 'events') {
					args = ['page', pagingMatch[2]];
				} else {
					args = [pagingMatch[2]];
				}
			} else if (/^cmd:inviteid:(\d+):(\d+)$/.test(callback.data)) {
				const inviteDetailMatch = /^cmd:inviteid:(\d+):(\d+)$/.exec(callback.data);
				command = '/invite';
				args = ['detail', inviteDetailMatch[1], inviteDetailMatch[2]];
			} else if (/^cmd:searchhelp:(user|email|invite|role)$/.test(callback.data)) {
				const searchHelpMatch = /^cmd:searchhelp:(user|email|invite|role)$/.exec(callback.data);
				command = '/searchs';
				args = [searchHelpMatch[1]];
			} else if (/^cmd:mailid:(\d+):(\d+)$/.test(callback.data)) {
				const mailDetailMatch = /^cmd:mailid:(\d+):(\d+)$/.exec(callback.data);
				command = '/mail';
				args = [mailDetailMatch[1], mailDetailMatch[2]];
			} else if (/^cmd:mailid:(\d+)$/.test(callback.data)) {
				const mailDetailMatch = /^cmd:mailid:(\d+)$/.exec(callback.data);
				command = '/mail';
				args = [mailDetailMatch[1], '1'];
			} else if (/^cmd:securityevent:(\d+)$/.test(callback.data)) {
				const securityEventDetailMatch = /^cmd:securityevent:(\d+)$/.exec(callback.data);
				command = '/security';
				args = ['event', securityEventDetailMatch[1]];
			} else if (/^cmd:event:(\d+):(\d+)$/.test(callback.data)) {
				const eventDetailMatch = /^cmd:event:(\d+):(\d+)$/.exec(callback.data);
				command = '/event';
				args = [eventDetailMatch[1], eventDetailMatch[2]];
			} else if (/^cmd:event:(\d+)$/.test(callback.data)) {
				const eventDetailMatch = /^cmd:event:(\d+)$/.exec(callback.data);
				command = '/event';
				args = [eventDetailMatch[1], '1'];
			} else if (callback.data === 'cmd:stats:7d') {
				command = '/stats';
				args = ['7d'];
			} else if (callback.data === 'cmd:whois:help') {
				command = '/whois';
				args = ['help'];
			} else {
				const single = /^cmd:(status|role|chatid|system|security|searchs)$/.exec(callback.data);
				if (single) command = `/${single[1]}`;
			}
			const result = await this.resolveCommand(c, command, args, chatId, userId);
			const edited = await this.editTelegramReply(c, chatId, callback.message.message_id, result.text, result.replyMarkup);
			if (!edited) await this.sendTelegramReply(c, chatId, result.text, result.replyMarkup);
			return;
		}

		const message = body?.message || body?.edited_message || body?.channel_post;
		const text = message?.text?.trim();
		const chatId = message?.chat?.id;
		const userId = message?.from?.id;
		if (!text || !chatId) {
			return;
		}

		if (!await this.isAllowedChat(c, chatId, userId)) {
			const allowed = await this.parseAllowedChatIds(c);
			const msg = allowed.length === 0
				? '⛔ Unauthorized\nReason: CHAT_ID allowlist is empty.'
				: `⛔ Unauthorized\nAllowed: ${allowed.join(', ')}\nCurrent chat_id: ${chatId}${userId ? `\nCurrent user_id: ${userId}` : ''}`;
			await this.sendTelegramReply(c, chatId, msg);
			await this.logSystemEvent(c, 'telegram.command.unauthorized', EVENT_LEVEL.WARN, 'Unauthorized command attempt', { chatId, userId, text });
			return;
		}

		const args = text.split(/\s+/).filter(Boolean);
		const rawCommand = args.shift();
		const command = rawCommand.includes('@') ? rawCommand.split('@')[0] : rawCommand;
		console.log(`Telegram bot command received chat_id=${chatId} user_id=${userId || '-'} command=${command}`);
		await this.logSystemEvent(c, 'telegram.command.received', EVENT_LEVEL.INFO, command, { chatId, userId, args });

		const result = await this.resolveCommand(c, command, args, chatId, userId);
		let reply = result.text;
		if (reply.length > 3800) {
			reply = `${reply.slice(0, 3800)}\n\n...truncated`;
		}
		await this.sendTelegramReply(c, chatId, reply, result.replyMarkup);
	},


};

export default telegramService;
