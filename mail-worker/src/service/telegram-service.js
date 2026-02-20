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

	// ─── HELPERS ──────────────────────────────────────────────────────────────

	isAdminUser(c, userEmail) {
		return c.env.admin && userEmail && userEmail.toLowerCase() === c.env.admin.toLowerCase();
	},

	async getEffectiveRoleDisplay(c, userRow) {
		if (!userRow) return null;
		if (this.isAdminUser(c, userRow.email)) {
			return {
				roleId: 0,
				name: 'Admin',
				sendType: 'unlimited',
				sendCount: 0,
				accountCount: 0,
				canSendEmail: true,
				canAddAddress: true,
				isAdmin: true
			};
		}
		const roleRow = await this.getRoleById(c, userRow.type);
		if (!roleRow) return null;
		return await this.attachRolePermInfo(c, { ...roleRow });
	},

	async getRoleById(c, roleId) {
		try {
			return await orm(c).select().from(role).where(eq(role.roleId, roleId)).get();
		} catch (e) {
			return null;
		}
	},

	formatSendLimit(roleInfo) {
		if (!roleInfo) return 'Unknown';
		if (roleInfo.isAdmin) return 'Unlimited (Admin)';
		if (roleInfo.canSendEmail === false) return 'Unauthorized';
		if (roleInfo.sendType === 'ban') return '🚫 Banned';
		if (roleInfo.sendType === 'internal') return '📨 Internal only';
		if (roleInfo.sendType === 'day') {
			return roleInfo.sendCount > 0 ? `${roleInfo.sendCount}/day` : 'Unlimited';
		}
		if (roleInfo.sendType === 'count') {
			return roleInfo.sendCount > 0 ? `${roleInfo.sendCount} total` : 'Unlimited';
		}
		return 'Unlimited';
	},

	formatAddressLimit(roleInfo) {
		if (!roleInfo) return 'Unknown';
		if (roleInfo.isAdmin) return 'Unlimited (Admin)';
		if (roleInfo.canAddAddress === false) return 'Unauthorized';
		return roleInfo.accountCount > 0 ? `${roleInfo.accountCount}` : 'Unlimited';
	},

	escapeHtml(value) {
		return String(value ?? '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#39;');
	},

	normalizeBlacklistTarget(rawTarget) {
		const target = String(rawTarget || '').trim().toLowerCase();
		if (!target) return null;
		const emailPattern = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
		const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
		if (emailPattern.test(target)) return target;
		if (domainPattern.test(target)) return target;
		return null;
	},

	// ─── CORE TG ──────────────────────────────────────────────────────────────

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

	async getBanEmailContent(c, params) {
		const { token } = params;
		const result = await jwtUtils.verifyToken(c, token);
		if (!result?.banLogId) return emailTextTemplate('Access denied or token invalid');
		try {
			const row = await c.env.db.prepare(`
				SELECT id, sender_email as senderEmail, to_email as toEmail, matched_rule as matchedRule,
					subject, text_preview as textPreview, html_content as htmlContent, create_time as createTime
				FROM ban_email_log WHERE id = ?
			`).bind(Number(result.banLogId)).first();
			if (!row) return emailTextTemplate('Blocked email not found (may have been auto-deleted after 24h)');
			const { r2Domain } = await settingService.query(c);
			const header = `<!-- BLACKLISTED EMAIL PREVIEW -->\n<div style="background:#fee2e2;border:2px solid #ef4444;padding:12px 16px;font-family:sans-serif;margin-bottom:16px;border-radius:6px">
<b>🚫 BLACKLISTED SENDER — Admin Preview Only</b><br>
From: <code>${row.senderEmail}</code><br>
To: <code>${row.toEmail}</code><br>
Subject: <b>${row.subject || '(no subject)'}</b><br>
Matched rule: <code>${row.matchedRule}</code><br>
Blocked at: ${row.createTime} UTC<br>
<small style="color:#991b1b">⚠️ This record auto-deletes 24h after block time.</small>
</div>`;
			if (row.htmlContent) {
				return emailHtmlTemplate(header + row.htmlContent, r2Domain);
			}
			return emailTextTemplate(`${row.subject || '(no subject)'}\n\nFrom: ${row.senderEmail}\nTo: ${row.toEmail}\nMatched rule: ${row.matchedRule}\nBlocked at: ${row.createTime}\n\n---\n\n${row.textPreview || '(no text content)'}`);
		} catch (e) {
			console.error('getBanEmailContent error:', e);
			return emailTextTemplate('Error loading preview: ' + e.message);
		}
	},

	async getBotToken(c) {
		const envToken = c.env.BOT_TOKEN || c.env.bot_token || c.env.TG_BOT_TOKEN || c.env.tgBotToken;
		if (envToken) return envToken;
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
		if (roleInfo.isAdmin) return roleInfo;
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

	async queryIpSecurity(c, ip, { noCache = false } = {}) {
		if (!ip) return null;
		try {
			const cache = await c.env.db.prepare('SELECT data, update_time FROM ip_security_cache WHERE ip = ?').bind(ip).first();
			if (cache?.data) {
				const cacheTime = cache.update_time ? dayjs.utc(cache.update_time) : null;
				const cacheExpired = !cacheTime || dayjs.utc().diff(cacheTime, 'hour') >= 48;
				if (!cacheExpired) return JSON.parse(cache.data);
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
			if ((usage?.count || 0) >= 1000) return { ip, limited: true };
		} catch (e) {
			console.error('Failed to read ip usage:', e.message);
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
			return detail;
		}
		if (!noCache) {
			try {
				const now = dayjs().utc().format('YYYY-MM-DD HH:mm:ss');
				await c.env.db.batch([
					c.env.db.prepare('INSERT INTO ip_security_cache (ip, data, update_time) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET data = excluded.data, update_time = excluded.update_time').bind(ip, JSON.stringify(detail), now),
					c.env.db.prepare('INSERT INTO ip_security_usage (usage_date, count, update_time) VALUES (?, 1, ?) ON CONFLICT(usage_date) DO UPDATE SET count = count + 1, update_time = excluded.update_time').bind(today, now)
				]);
			} catch (e) {
				console.error('Failed to write ip cache:', e.message);
			}
		}
		return detail;
	},

	// ─── NOTIFICATION SENDERS ────────────────────────────────────────────────

	async sendEmailToBot(c, emailData) {
		const { customDomain, tgMsgTo, tgMsgFrom, tgMsgText } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: emailData.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404';
		const message = emailMsgTemplate(emailData, tgMsgTo, tgMsgFrom, tgMsgText, null);
		await this.emitWebhookEvent(c, 'email.received', message, EVENT_LEVEL.INFO, { emailId: emailData?.emailId, webAppUrl, from: emailData?.sendEmail, to: emailData?.toEmail }, { inline_keyboard: [[{ text: 'Check', web_app: { url: webAppUrl } }]] });
	},

	async sendIpSecurityNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const ipDetail = await this.queryIpSecurity(c, userInfo.activeIp);
		const message = ipSecurityMsgTemplate(userInfo, ipDetail);
		await this.emitWebhookEvent(c, 'security.ip_changed', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email, ip: userInfo?.activeIp, vpn: ipDetail?.security?.vpn || false });
		await this.sendSecurityEventAlert(c, `IP changed: <code>${userInfo?.activeIp || '-'}</code>`, `User: ${userInfo?.email || '-'} (#${userInfo?.userId || '-'})`);
		const risk = ipDetail?.security || {};
		if (risk.vpn || risk.proxy || risk.tor || risk.relay) {
			await this.sendSecurityEventAlert(
				c,
				`Risky IP detected: <code>${userInfo?.activeIp || '-'}</code>`,
				`User: ${userInfo?.email || '-'} (#${userInfo?.userId || '-'})\nvpn=${risk.vpn ? 'Y' : 'N'} proxy=${risk.proxy ? 'Y' : 'N'} tor=${risk.tor ? 'Y' : 'N'} relay=${risk.relay ? 'Y' : 'N'}`,
				'cmd:security'
			);
		}
	},

	async sendRegKeyManageNotification(c, action, regKeyInfo, actorInfo, extraInfo = {}) {
		if (actorInfo?.activeIp) {
			actorInfo.timezone = await timezoneUtils.getTimezone(c, actorInfo.activeIp);
			await this.setIpDetailContext(c, actorInfo);
		}
		regKeyInfo.roleInfo = await this.attachRolePermInfo(c, regKeyInfo.roleInfo);
		if (actorInfo) actorInfo.role = await this.getEffectiveRoleDisplay(c, actorInfo);
		const message = regKeyManageMsgTemplate(action, regKeyInfo, actorInfo, extraInfo);
		await this.emitWebhookEvent(c, 'regkey.manage', message, EVENT_LEVEL.INFO, { action, code: regKeyInfo?.code, actor: actorInfo?.email || '-' });
	},

	async sendLoginNotification(c, userInfo) {
		let message = '';
		try {
			userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
			await this.setIpDetailContext(c, userInfo);
			userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
			message = loginMsgTemplate(userInfo);
		} catch (e) {
			console.error('Failed to enrich login webhook payload:', e.message);
			message = loginMsgTemplate({ ...userInfo, timezone: null, ipDetail: null });
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
		adminUser.role = await this.getEffectiveRoleDisplay(c, adminUser);
		const message = adminCreateUserMsgTemplate(newUserInfo, roleInfo, adminUser);
		await this.emitWebhookEvent(c, 'admin.user.create', message, EVENT_LEVEL.INFO, { userId: newUserInfo?.userId, email: newUserInfo?.email, admin: adminUser?.email || '-' });
	},

	async sendEmailSentNotification(c, emailInfo, userInfo) {
		const { customDomain } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: emailInfo.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404';
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = sendEmailMsgTemplate(emailInfo, userInfo);
		await this.emitWebhookEvent(c, 'email.sent', message, EVENT_LEVEL.INFO, { emailId: emailInfo?.emailId, userId: userInfo?.userId, from: emailInfo?.sendEmail, to: emailInfo?.toEmail, webAppUrl }, { inline_keyboard: [[{ text: 'Check', web_app: { url: webAppUrl } }]] });
	},

	async sendEmailSoftDeleteNotification(c, emailIds, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = softDeleteEmailMsgTemplate(emailIds, userInfo);
		await this.emitWebhookEvent(c, 'email.delete.soft', message, EVENT_LEVEL.INFO, { emailIds, userId: userInfo?.userId });
	},

	async sendEmailHardDeleteNotification(c, emailIds, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = hardDeleteEmailMsgTemplate(emailIds, userInfo);
		await this.emitWebhookEvent(c, 'email.delete.hard', message, EVENT_LEVEL.WARN, { emailIds, userId: userInfo?.userId });
	},

	async sendAddAddressNotification(c, addressInfo, userInfo, totalAddresses) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = addAddressMsgTemplate(addressInfo, userInfo, totalAddresses);
		await this.emitWebhookEvent(c, 'account.address.add', message, EVENT_LEVEL.INFO, { email: addressInfo?.email, userId: userInfo?.userId });
	},

	async sendDeleteAddressNotification(c, addressEmail, userInfo, remainingAddresses) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = deleteAddressMsgTemplate(addressEmail, userInfo, remainingAddresses);
		await this.emitWebhookEvent(c, 'account.address.delete', message, EVENT_LEVEL.WARN, { email: addressEmail, userId: userInfo?.userId });
	},

	async sendRoleChangeNotification(c, userInfo, oldRole, newRole, changedBy) {
		changedBy.timezone = await timezoneUtils.getTimezone(c, changedBy.activeIp);
		await this.setIpDetailContext(c, userInfo);
		await this.setIpDetailContext(c, changedBy);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		changedBy.role = await this.getEffectiveRoleDisplay(c, changedBy);
		oldRole = await this.attachRolePermInfo(c, oldRole);
		newRole = await this.attachRolePermInfo(c, newRole);
		const message = roleChangeMsgTemplate(userInfo, oldRole, newRole, changedBy);
		await this.emitWebhookEvent(c, 'admin.user.role_change', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, from: oldRole?.name, to: newRole?.name, by: changedBy?.email || '-' });
	},

	async sendUserStatusChangeNotification(c, userInfo, oldStatus, newStatus, changedBy) {
		changedBy.timezone = await timezoneUtils.getTimezone(c, changedBy.activeIp);
		await this.setIpDetailContext(c, userInfo);
		await this.setIpDetailContext(c, changedBy);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		changedBy.role = await this.getEffectiveRoleDisplay(c, changedBy);
		const message = userStatusChangeMsgTemplate(userInfo, oldStatus, newStatus, changedBy);
		await this.emitWebhookEvent(c, 'admin.user.status_change', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, oldStatus, newStatus, by: changedBy?.email || '-' });
	},

	async sendPasswordResetNotification(c, userInfo) {
		return await this.sendPasswordChangeNotification(c, userInfo, 'reset');
	},

	async sendUserSelfDeleteNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = userSelfDeleteMsgTemplate(userInfo);
		await this.emitWebhookEvent(c, 'user.self_delete', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email });
	},

	async sendAdminDeleteUserNotification(c, deletedUser, adminUser) {
		adminUser.timezone = await timezoneUtils.getTimezone(c, adminUser.activeIp);
		await this.setIpDetailContext(c, deletedUser);
		await this.setIpDetailContext(c, adminUser);
		deletedUser.role = await this.getEffectiveRoleDisplay(c, deletedUser);
		adminUser.role = await this.getEffectiveRoleDisplay(c, adminUser);
		const message = adminDeleteUserMsgTemplate(deletedUser, adminUser);
		await this.emitWebhookEvent(c, 'admin.user.delete', message, EVENT_LEVEL.WARN, { deletedUserId: deletedUser?.userId, admin: adminUser?.email || '-' });
	},

	async sendRoleManageNotification(c, action, roleInfo, actorInfo, extra = '') {
		actorInfo.timezone = await timezoneUtils.getTimezone(c, actorInfo.activeIp);
		await this.setIpDetailContext(c, actorInfo);
		actorInfo.role = await this.getEffectiveRoleDisplay(c, actorInfo);
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
		await this.emitWebhookEvent(c, 'auth.login.failed', message, EVENT_LEVEL.WARN, { email, ip, attempts, device, os, browser, vpn: ipDetail?.security?.vpn || false });
		await this.sendSecurityEventAlert(c, `Failed login: ${email || '-'}`, `IP: <code>${ip || '-'}</code> | Attempts: ${attempts || 0}`);
	},

	async sendQuotaWarningNotification(c, userInfo, quotaType) {
		userInfo.role = await this.getEffectiveRoleDisplay(c, userInfo);
		const message = quotaWarningMsgTemplate(userInfo, quotaType);
		await this.emitWebhookEvent(c, 'quota.warning', message, EVENT_LEVEL.WARN, { userId: userInfo?.userId, email: userInfo?.email, quotaType });
	},

	// ─── BOT INFRA ────────────────────────────────────────────────────────────

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
		return String(raw || '').split(',').map(item => item.trim()).filter(Boolean);
	},

	async isAllowedChat(c, chatId, userId) {
		const allowed = await this.parseAllowedChatIds(c);
		if (allowed.length === 0) return false;
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
		if (!tgBotToken) return { ok: false, description: 'Bot token is empty' };
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/getWebhookInfo`);
		return res.json().catch(() => ({ ok: false, description: 'Invalid Telegram response' }));
	},

	async setWebhook(c) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) return { ok: false, description: 'Bot token is empty' };
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
		if (!tgBotToken) return { ok: false, description: 'Bot token is empty' };
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/deleteWebhook`);
		return res.json().catch(() => ({ ok: false, description: 'Invalid Telegram response' }));
	},

	async sendTelegramReply(c, chatId, message, replyMarkup = null) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) return null;
		const payload = { chat_id: String(chatId), parse_mode: 'HTML', text: message };
		if (replyMarkup) payload.reply_markup = replyMarkup;
		const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		});
		const data = await res.json().catch(() => null);
		if (!res.ok) {
			console.error(`Failed to send Telegram bot reply status: ${res.status} response: ${JSON.stringify(data)}`);
			return null;
		}
		return data?.result || null;
	},

	async editTelegramReply(c, chatId, messageId, message, replyMarkup = null) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken) return;
		const payload = { chat_id: String(chatId), message_id: messageId, parse_mode: 'HTML', text: message };
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

	async ensureChatStateTable(c) {
		await c.env.db.prepare(`
			CREATE TABLE IF NOT EXISTS tg_chat_state (
				chat_id TEXT PRIMARY KEY,
				last_bot_message_id INTEGER,
				update_time TEXT DEFAULT (datetime('now'))
			)
		`).run();
	},

	async getLastBotMessageId(c, chatId) {
		try {
			await this.ensureChatStateTable(c);
			const row = await c.env.db.prepare('SELECT last_bot_message_id as messageId FROM tg_chat_state WHERE chat_id = ?').bind(String(chatId)).first();
			return row?.messageId || null;
		} catch (e) {
			console.error('Failed to load tg_chat_state:', e.message);
			return null;
		}
	},

	async saveLastBotMessageId(c, chatId, messageId) {
		if (!chatId || !messageId) return;
		try {
			await this.ensureChatStateTable(c);
			await c.env.db.prepare(`
				INSERT INTO tg_chat_state (chat_id, last_bot_message_id, update_time)
				VALUES (?, ?, datetime('now'))
				ON CONFLICT(chat_id) DO UPDATE SET
					last_bot_message_id = excluded.last_bot_message_id,
					update_time = excluded.update_time
			`).bind(String(chatId), Number(messageId)).run();
		} catch (e) {
			console.error('Failed to save tg_chat_state:', e.message);
		}
	},

	async sendOrEditSingleChatMessage(c, chatId, message, replyMarkup = null) {
		const previousMessageId = await this.getLastBotMessageId(c, chatId);
		if (previousMessageId) {
			const edited = await this.editTelegramReply(c, chatId, previousMessageId, message, replyMarkup);
			if (edited) return { messageId: previousMessageId, edited: true };
		}
		const sent = await this.sendTelegramReply(c, chatId, message, replyMarkup);
		const messageId = sent?.message_id;
		if (messageId) await this.saveLastBotMessageId(c, chatId, messageId);
		return { messageId: messageId || null, edited: false };
	},

	async deleteTelegramMessage(c, chatId, messageId) {
		const tgBotToken = await this.getBotToken(c);
		if (!tgBotToken || !chatId || !messageId) return;
		try {
			await fetch(`https://api.telegram.org/bot${tgBotToken}/deleteMessage`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ chat_id: String(chatId), message_id: messageId })
			});
		} catch (e) {
			// Ignore silently
		}
	},

	// ─── MENU BUILDERS ────────────────────────────────────────────────────────

	buildMainMenu() {
		return {
			inline_keyboard: [
				[{ text: '📊 Status', callback_data: 'cmd:status' }, { text: '🔐 Security', callback_data: 'cmd:security' }],
				[{ text: '🧭 System', callback_data: 'cmd:system' }, { text: '🗂 Events', callback_data: 'cmd:events:1' }],
				[{ text: '👥 Users', callback_data: 'cmd:users:1' }, { text: '📨 Mail', callback_data: 'cmd:mail:1' }],
				[{ text: '📈 Stats', callback_data: 'cmd:stats:7d' }, { text: '📬 Recent', callback_data: 'cmd:recent' }],
				[{ text: '🎟️ Invite', callback_data: 'cmd:invite:1' }, { text: '🔎 Search', callback_data: 'cmd:search' }],
				[{ text: '🌐 Whois', callback_data: 'cmd:whois:help' }, { text: '🆔 Chat ID', callback_data: 'cmd:chatid' }],
				[{ text: '🛡️ Role', callback_data: 'cmd:role' }, { text: '❓ Help', callback_data: 'cmd:help' }]
			]
		};
	},

	severityLabel(value, warnThreshold, dangerThreshold, reverse = false) {
		const safeValue = Number(value || 0);
		if (reverse) {
			if (safeValue <= dangerThreshold) return '🔴';
			if (safeValue <= warnThreshold) return '🟡';
			return '🟢';
		}
		if (safeValue >= dangerThreshold) return '🔴';
		if (safeValue >= warnThreshold) return '🟡';
		return '🟢';
	},

	async collectAtGlanceMetrics(c) {
		const numberCount = await analysisDao.numberCount(c);
		const allowed = await this.parseAllowedChatIds(c);
		const setting = await settingService.query(c);
		const botEnabled = Boolean(setting.tgBotToken);

		const [{ cnt: failed24h = 0 } = {}] = [await c.env.db.prepare(`
			SELECT COUNT(*) as cnt
			FROM webhook_event_log
			WHERE event_type = 'auth.login.failed'
			  AND create_time >= datetime('now', '-24 hour')
		`).first()];

		const [{ cnt: blocked24h = 0 } = {}] = [await c.env.db.prepare(`
			SELECT COUNT(*) as cnt
			FROM webhook_event_log
			WHERE event_type IN ('security.blacklist.blocked', 'security.outbound.blocked')
			  AND create_time >= datetime('now', '-24 hour')
		`).first()];

		const [{ cnt: systemError24h = 0 } = {}] = [await c.env.db.prepare(`
			SELECT COUNT(*) as cnt
			FROM webhook_event_log
			WHERE level = 'error'
			  AND create_time >= datetime('now', '-24 hour')
		`).first()];

		return {
			numberCount,
			allowed,
			botEnabled,
			pushEnabled: await this.shouldSendWebhookPush(c),
			failed24h,
			blocked24h,
			systemError24h,
			nowUtc: dayjs.utc().format('YYYY-MM-DD HH:mm:ss')
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
		if (previewUrl) rows.push([{ text: '🔎 Open Email Preview', web_app: { url: previewUrl } }]);
		rows.push([
			{ text: backText || '⬅️ Back to List', callback_data: backCallbackData || 'cmd:menu' },
			{ text: '🏠 Menu', callback_data: 'cmd:menu' }
		]);
		return { inline_keyboard: rows };
	},

	mapUserStatusLabel(status) {
		if (Number(status) === 0) return '0 (Active)';
		if (Number(status) === 1) return '1 (Banned)';
		return `${status} (Unknown)`;
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

	// ─── COMMAND FORMATTERS ───────────────────────────────────────────────────

	formatSearchHelp(scope = 'general') {
		if (scope === 'user') return `🔎 <b>/search user</b>\nExample:\n• <code>/search user 2</code>\n• <code>/search user user@example.com</code>\n• <code>/search user user@example.com/2</code>`;
		if (scope === 'email') return `🔎 <b>/search email</b>\nExample: <code>/search email 121</code>`;
		if (scope === 'invite') return `🔎 <b>/search invite</b>\nExample:\n• <code>/search invite 6</code>\n• <code>/search invite CODE123</code>`;
		if (scope === 'role') return `🔎 <b>/search role</b>\nExample:\n• <code>/search role 1</code>\n• <code>/search role normal users</code>`;
		return `🔎 <b>/search</b>\nUse menu or command:\n• <code>/search user &lt;userId|email&gt;</code>\n• <code>/search email &lt;emailId&gt;</code>\n• <code>/search invite &lt;id|code&gt;</code>\n• <code>/search role &lt;id|name&gt;</code>\n• <code>/search ip &lt;ip&gt;</code>`;
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
		if (!items.length) return 'Recent activity: -';
		const lines = items.map(item => {
			const oneLine = String(item.message || '').split('\n').find(Boolean) || '-';
			return `• #${item.logId} [${item.level}] ${item.eventType} | ${item.createTime}\n  ${oneLine.slice(0, 140)}`;
		});
		return `Recent activity:\n${lines.join('\n')}`;
	},

	parseRangeDays(rangeArg = '7d') {
		const value = String(rangeArg || '7d').trim().toLowerCase();
		const match = /^(\d{1,2})d$/.exec(value);
		if (!match) return 7;
		return Math.max(1, Math.min(30, Number(match[1])));
	},

	// ─── ENHANCED COMMAND: USER DETAIL ───────────────────────────────────────

	async formatUserDetailCommand(c, userIdArg, pageArg = 1, highlightAccount = null) {
		const userId = Number(userIdArg || 0);
		const backPage = Math.max(1, Number(pageArg || 1));
		if (!userId) {
			return { text: `👤 <b>/user</b>\nUsage: <code>/user 2</code>`, replyMarkup: this.buildDetailMenu({ backText: '👥 Users List', backCallbackData: 'cmd:users:1' }) };
		}
		const userRow = await orm(c).select().from(user).where(eq(user.userId, userId)).get();
		if (!userRow) {
			return { text: `👤 <b>/user</b>\nUser #${userId} not found.`, replyMarkup: this.buildDetailMenu({ backText: '👥 Users List', backCallbackData: `cmd:users:${backPage}` }) };
		}

		const isAdmin = this.isAdminUser(c, userRow.email);

		const roleRows = await orm(c).select().from(role);
		const roleMap = new Map(roleRows.map(r => [r.roleId, r.name]));

		let effectiveRoleInfo;
		let roleName;
		if (isAdmin) {
			effectiveRoleInfo = {
				roleId: 0,
				name: 'Admin (env)',
				sendType: 'unlimited',
				sendCount: 0,
				accountCount: 0,
				canSendEmail: true,
				canAddAddress: true,
				isAdmin: true
			};
			roleName = '👑 Admin (env)';
		} else {
			const roleRow = roleMap.get(userRow.type);
			roleName = roleRow || `Type ${userRow.type}`;
			const fullRoleRow = roleRows.find(r => r.roleId === userRow.type);
			effectiveRoleInfo = fullRoleRow ? await this.attachRolePermInfo(c, { ...fullRoleRow }) : null;
		}

		const sendLimit = this.formatSendLimit(effectiveRoleInfo);
		const addressLimit = this.formatAddressLimit(effectiveRoleInfo);

		const sendCountRow = await c.env.db.prepare(`
			SELECT COUNT(*) as sendCount FROM email WHERE user_id = ? AND type = 1 AND is_del = 0
		`).bind(userId).first();
		const receiveCountRow = await c.env.db.prepare(`
			SELECT COUNT(*) as receiveCount FROM email WHERE user_id = ? AND type = 0 AND is_del = 0
		`).bind(userId).first();
		const userSendCount = Number(userRow.sendCount || 0);
		const totalSendEmails = Number(sendCountRow?.sendCount || 0);
		const totalReceiveEmails = Number(receiveCountRow?.receiveCount || 0);

		let quotaLine = '';
		if (isAdmin) {
			quotaLine = `📊 Send Quota: Unlimited (Admin)`;
		} else if (effectiveRoleInfo?.sendCount > 0) {
			const remaining = Math.max(0, effectiveRoleInfo.sendCount - userSendCount);
			const pct = Math.round((userSendCount / effectiveRoleInfo.sendCount) * 100);
			const bar = this.buildProgressBar(pct);
			quotaLine = `📊 Send Used: ${userSendCount}/${effectiveRoleInfo.sendCount} ${bar} (${pct}% | ${remaining} left)`;
		} else {
			quotaLine = `📊 Send Used: ${totalSendEmails} total (Unlimited)`;
		}

		const relatedAccountsRows = await c.env.db.prepare(`
			SELECT account_id as accountId, email, is_del as isDel
			FROM account
			WHERE user_id = ?
			ORDER BY account_id DESC
			LIMIT 10
		`).bind(userId).all();
		const relatedAccounts = relatedAccountsRows?.results || [];
		const activeAccounts = relatedAccounts.filter(a => !a.isDel);
		const accountText = relatedAccounts.length
			? relatedAccounts.map(item => `• ${item.isDel ? '❌' : '✅'} account_id ${item.accountId}: ${item.email}`).join('\n')
			: '-';

		let addressQuotaLine = '';
		if (isAdmin) {
			addressQuotaLine = `📬 Address Quota: Unlimited (Admin)`;
		} else if (effectiveRoleInfo?.accountCount > 0) {
			const activeCount = activeAccounts.length;
			const pct = Math.round((activeCount / effectiveRoleInfo.accountCount) * 100);
			const bar = this.buildProgressBar(pct);
			addressQuotaLine = `📬 Address: ${activeCount}/${effectiveRoleInfo.accountCount} ${bar} (${pct}%)`;
		} else {
			addressQuotaLine = `📬 Address: ${activeAccounts.length} (Unlimited)`;
		}

		const ipDetail = await this.queryIpSecurity(c, userRow.activeIp);
		const sec = ipDetail?.security || {};
		const loc = ipDetail?.location || {};
		const ipLine = userRow.activeIp
			? `📍 IP: <code>${userRow.activeIp}</code> | vpn=${sec.vpn ? 'Y' : 'N'} proxy=${sec.proxy ? 'Y' : 'N'} tor=${sec.tor ? 'Y' : 'N'}\n🗺️ Loc: ${loc.city || '-'}, ${loc.country || '-'}`
			: `📍 IP: -`;

		const recent = await this.queryRecentActivity(c, { userId: userRow.userId, address: userRow.email, accountId: highlightAccount || null, ip: userRow.activeIp }, 5);
		const eventButtons = recent.map(item => ([{ text: `🧾 Event #${item.logId} ${item.eventType}`.slice(0, 64), callback_data: `cmd:userevent:${item.logId}:${userRow.userId}:${backPage}` }]));

		const detail = `👤 <b>User Detail</b>

🆔 User: #${userRow.userId} <code>${userRow.email}</code>
${isAdmin ? '👑' : '🛡️'} Role: <b>${roleName}</b>
📊 Status: ${this.mapUserStatusLabel(userRow.status)} | Deleted: ${userRow.isDel ? 'Yes' : 'No'}

<b>📈 Quotas &amp; Limits</b>
${quotaLine}
${addressQuotaLine}
📧 Send Limit: ${sendLimit}
📬 Address Limit: ${addressLimit}

<b>📧 Email Stats</b>
📥 Received: ${totalReceiveEmails} | 📤 Sent: ${totalSendEmails}

<b>📬 Accounts</b>
${accountText}
${highlightAccount ? `\n🎯 Highlighted: account_id ${highlightAccount}` : ''}
<b>🌐 Network</b>
${ipLine}
📱 Device: ${userRow.device || '-'} / ${userRow.os || '-'}
🌐 Browser: ${userRow.browser || '-'}

<b>📅 Timestamps</b>
🗓️ Created: ${userRow.createTime || '-'}
🕐 Last Active: ${userRow.activeTime || '-'}

${this.formatActivityBlock(recent)}`;

		const replyMarkup = { inline_keyboard: [...eventButtons, [{ text: '📧 View Emails', callback_data: `cmd:usermail:${userRow.userId}:1` }, { text: '🚫 Ban/Unban', callback_data: `cmd:banuser:${userRow.userId}` }], [{ text: '👥 Users List', callback_data: `cmd:users:${backPage}` }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] };
		return { text: detail, replyMarkup };
	},

	buildProgressBar(pct, length = 10) {
		const filled = Math.round((pct / 100) * length);
		const empty = length - filled;
		return '[' + '█'.repeat(Math.max(0, filled)) + '░'.repeat(Math.max(0, empty)) + ']';
	},

	// ─── ENHANCED COMMAND: USERS LIST ────────────────────────────────────────

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
		if (rows.length === 0) return { text: `👤 <b>/users</b>\nNo user data.`, replyMarkup: this.buildMainMenu() };

		const hasNext = rows.length > pageSize;
		const visibleRows = hasNext ? rows.slice(0, pageSize) : rows;
		const visibleUserIds = visibleRows.map(item => item.userId);

		let receiveCountMap = new Map();
		let sendCountMap = new Map();
		if (visibleUserIds.length > 0) {
			const placeholders = visibleUserIds.map(() => '?').join(',');
			const { results: rr } = await c.env.db.prepare(`
				SELECT user_id as userId, COUNT(*) as cnt FROM email WHERE type = 0 AND is_del = 0 AND user_id IN (${placeholders}) GROUP BY user_id
			`).bind(...visibleUserIds).all();
			receiveCountMap = new Map((rr || []).map(r => [r.userId, r.cnt]));
			const { results: sr } = await c.env.db.prepare(`
				SELECT user_id as userId, COUNT(*) as cnt FROM email WHERE type = 1 AND is_del = 0 AND user_id IN (${placeholders}) GROUP BY user_id
			`).bind(...visibleUserIds).all();
			sendCountMap = new Map((sr || []).map(r => [r.userId, r.cnt]));
		}

		const roleRows = await orm(c).select().from(role);
		const roleMap = new Map(roleRows.map(r => [r.roleId, r]));

		const bodyParts = [];
		for (const item of visibleRows) {
			const isAdmin = this.isAdminUser(c, item.email);
			let roleDisplay = '';
			let sendLimit = '';
			let addressLimit = '';

			if (isAdmin) {
				roleDisplay = '👑 Admin (env)';
				sendLimit = 'Unlimited';
				addressLimit = 'Unlimited';
			} else {
				const roleRow = roleMap.get(item.type);
				roleDisplay = roleRow?.name || `Type ${item.type}`;
				if (roleRow) {
					const enriched = await this.attachRolePermInfo(c, { ...roleRow });
					sendLimit = this.formatSendLimit(enriched);
					addressLimit = this.formatAddressLimit(enriched);
				}
			}

			const ipDetail = await this.queryIpSecurity(c, item.activeIp);
			const sec = ipDetail?.security || {};
			const loc = ipDetail?.location || {};

			bodyParts.push(`🆔 <code>${item.userId}</code> ${item.email}
${isAdmin ? '👑' : '🛡️'} Role: ${roleDisplay} | Status: ${this.mapUserStatusLabel(item.status)}
📤 Send: ${item.sendCount || 0} used | Limit: ${sendLimit}
📬 Address Limit: ${addressLimit}
📥 Receive: ${receiveCountMap.get(item.userId) || 0} | 📤 Send total: ${sendCountMap.get(item.userId) || 0}
📍 IP: <code>${item.activeIp || '-'}</code> vpn=${sec.vpn ? 'Y' : 'N'} | ${loc.city || '-'}, ${loc.country || '-'}
🗓️ Created: ${item.createTime || '-'}`);
		}

		const userButtons = visibleRows.map(item => ([
			{ text: `👤 #${item.userId} ${item.email}`.slice(0, 40), callback_data: `cmd:userid:${item.userId}:${currentPage}` },
			{ text: '📧', callback_data: `cmd:usermail:${item.userId}:1` }
		]));
		const pagerMarkup = this.buildPager('users', currentPage, hasNext);
		const replyMarkup = { inline_keyboard: [...userButtons, ...(pagerMarkup?.inline_keyboard || [])] };
		return { text: `👥 <b>/users</b> (page ${currentPage})\n\n${bodyParts.join('\n\n')}`, replyMarkup };
	},

	// ─── ENHANCED COMMAND: ROLE LIST ─────────────────────────────────────────

	async formatRoleCommand(c) {
		const rows = await orm(c).select().from(role);
		if (rows.length === 0) return `🛡️ <b>/role</b>\nNo role data.`;
		const roleRows = await Promise.all(rows.map(async item => this.attachRolePermInfo(c, { ...item })));

		const roleIds = rows.map(r => r.roleId);
		const placeholders = roleIds.map(() => '?').join(',');
		const { results: userCounts } = await c.env.db.prepare(
			`SELECT type, COUNT(*) as cnt FROM user WHERE is_del = 0 AND type IN (${placeholders}) GROUP BY type`
		).bind(...roleIds).all();
		const userCountMap = new Map((userCounts || []).map(r => [r.type, r.cnt]));

		const body = roleRows.map(item => {
			const sendLimit = this.formatSendLimit(item);
			const addressLimit = this.formatAddressLimit(item);
			const userCount = userCountMap.get(item.roleId) || 0;

			return `🆔 <code>${item.roleId}</code> <b>${item.name}</b>${item.isDefault ? ' ⭐ Default' : ''}
👥 Users: ${userCount}
📤 Send Limit: ${sendLimit}
📬 Address Limit: ${addressLimit}
✉️ Perm send: ${item.canSendEmail ? 'Yes' : 'No'} | add-address: ${item.canAddAddress ? 'Yes' : 'No'}
🚫 Ban email: ${item.banEmail || '-'}
🌐 Avail domain: ${item.availDomain || 'All'}`;
		}).join('\n\n');

		return `🛡️ <b>/role</b>\n\n${body}`;
	},

	// ─── ENHANCED COMMAND: STATUS ─────────────────────────────────────────────

	async formatStatusCommand(c) {
		const metrics = await this.collectAtGlanceMetrics(c);

		const todayStr = dayjs.utc().format('YYYY-MM-DD');
		const todayRegRow = await c.env.db.prepare(`SELECT COUNT(*) as cnt FROM user WHERE DATE(create_time) = ?`).bind(todayStr).first();
		const todayReceiveRow = await c.env.db.prepare(`SELECT COUNT(*) as cnt FROM email WHERE type = 0 AND DATE(create_time) = ?`).bind(todayStr).first();
		const todaySendRow = await c.env.db.prepare(`SELECT COUNT(*) as cnt FROM email WHERE type = 1 AND DATE(create_time) = ?`).bind(todayStr).first();
		const deletedUserRow = await c.env.db.prepare(`SELECT COUNT(*) as cnt FROM user WHERE is_del = 1`).first();

		const healthIcon = this.severityLabel(metrics.systemError24h + metrics.failed24h, 3, 10);
		const securityIcon = this.severityLabel(metrics.failed24h + metrics.blocked24h, 4, 12);

		return `📊 <b>/status</b> — Main Dashboard

<b>${healthIcon} Platform Health (24h)</b>
Failed login: <b>${metrics.failed24h}</b> | System error: <b>${metrics.systemError24h}</b>
Blocked email event: <b>${metrics.blocked24h}</b>

<b>${securityIcon} Security & Bot Runtime</b>
🤖 Bot enabled: ${metrics.botEnabled ? 'Yes' : 'No'}
🌐 Push notify: ${metrics.pushEnabled ? 'Yes' : 'No'}
🔐 Allowed CHAT_ID: ${metrics.allowed.length > 0 ? metrics.allowed.join(', ') : '(empty)'}

<b>👥 Users</b>
Total: ${metrics.numberCount.userTotal} | Deleted: ${deletedUserRow?.cnt || 0} | New today: ${todayRegRow?.cnt || 0}

<b>📬 Addresses</b>
Total: ${metrics.numberCount.accountTotal}

<b>📧 Emails</b>
Received: ${metrics.numberCount.receiveTotal} | Sent: ${metrics.numberCount.sendTotal}
Today recv: ${todayReceiveRow?.cnt || 0} | Today sent: ${todaySendRow?.cnt || 0}

📅 Server time (UTC): ${metrics.nowUtc}

Tip: gunakan <code>/security</code> untuk detail insiden dan <code>/system</code> untuk detail webhook/log.`;
	},

	// ─── ENHANCED COMMAND: SECURITY ──────────────────────────────────────────

	async formatSecurityCommand(c) {
		const { results } = await c.env.db.prepare(`
			SELECT isc.ip, isc.update_time, isc.data,
				COUNT(DISTINCT u.user_id) as affectedUsers
			FROM ip_security_cache isc
			INNER JOIN user u ON (u.active_ip = isc.ip OR u.create_ip = isc.ip)
			WHERE u.is_del = 0
			  AND (
			      COALESCE(json_extract(isc.data, '$.security.vpn'), 0) = 1
			      OR COALESCE(json_extract(isc.data, '$.security.proxy'), 0) = 1
			      OR COALESCE(json_extract(isc.data, '$.security.tor'), 0) = 1
			      OR COALESCE(json_extract(isc.data, '$.security.relay'), 0) = 1
			  )
			GROUP BY isc.ip
			ORDER BY isc.update_time DESC
			LIMIT 10
		`).all();

		let riskyLines = 'No risky IP found in cache.';
		if (results?.length) {
			riskyLines = results.map((row, idx) => {
				let detail = {};
				try { detail = JSON.parse(row.data || '{}'); } catch (_) {}
				const sec = detail.security || {};
				const location = detail.location || {};
				return `${idx + 1}. <code>${row.ip || '-'}</code> users=${row.affectedUsers || 0}\n   🧷 vpn=${sec.vpn ? 'Y' : 'N'} proxy=${sec.proxy ? 'Y' : 'N'} tor=${sec.tor ? 'Y' : 'N'} relay=${sec.relay ? 'Y' : 'N'}\n   📍 ${location.country || '-'} / ${location.city || '-'} | Updated: ${row.update_time || '-'}`;
			}).join('\n');
		}

		const failedRows = await c.env.db.prepare(`
			SELECT log_id as logId, message, create_time as createTime
			FROM webhook_event_log
			WHERE event_type = 'auth.login.failed'
			ORDER BY log_id DESC
			LIMIT 6
		`).all();
		const failedItems = failedRows?.results || [];
		const failedPreview = failedItems.length
			? failedItems.map(item => {
				const oneLine = String(item.message || '').split('\n').slice(0, 1).join(' ').trim();
				return `• #${item.logId} ${oneLine}\n  At: ${item.createTime || '-'}`;
			}).join('\n')
			: '-';

		const blacklistRows = await c.env.db.prepare(`
			SELECT log_id as logId, event_type as eventType, message, meta, create_time as createTime
			FROM webhook_event_log
			WHERE event_type IN ('security.blacklist.blocked', 'security.outbound.blocked')
			ORDER BY log_id DESC
			LIMIT 8
		`).all();
		const blacklistItems = blacklistRows?.results || [];

		const { customDomain } = await settingService.query(c);
		const blacklistPreviewMap = new Map();
		if (customDomain) {
			for (const item of blacklistItems) {
				let meta = {};
				try { meta = JSON.parse(item.meta || '{}'); } catch (_) {}
				if (meta.banLogId) {
					const token = await jwtUtils.generateToken(c, { banLogId: meta.banLogId });
					blacklistPreviewMap.set(item.logId, `${domainUtils.toOssDomain(customDomain)}/api/telegram/getBanEmail/${token}`);
				}
			}
		}

		const blacklistPreview = blacklistItems.length
			? blacklistItems.map(item => {
				let meta = {};
				try { meta = JSON.parse(item.meta || '{}'); } catch (_) {}
				const isOutbound = item.eventType === 'security.outbound.blocked' || String(item.message || '').includes('Outbound');
				const icon = isOutbound ? '📤' : '📥';
				const dir = isOutbound ? 'OUT' : 'IN';
				const hasPreview = blacklistPreviewMap.has(item.logId) ? ' 🔎' : '';
				const actor = isOutbound && meta.actorEmail ? ` | Actor: <code>${meta.actorEmail}</code> (#${meta.actorUserId || '-'})` : '';
				return `• ${icon}[${dir}] #${item.logId}${hasPreview} <code>${meta.senderEmail || meta.actorEmail || '-'}</code> → <code>${meta.to || meta.toEmail || '-'}</code>\n  Rule: ${meta.matchedRule || '-'}${actor}\n  At: ${item.createTime || '-'}`;
			}).join('\n')
			: '-';

		const [{ cnt: failed24h = 0 } = {}] = [await c.env.db.prepare(`SELECT COUNT(*) as cnt FROM webhook_event_log WHERE event_type = 'auth.login.failed' AND create_time >= datetime('now', '-24 hour')`).first()];
		const [{ cnt: blocked24h = 0 } = {}] = [await c.env.db.prepare(`SELECT COUNT(*) as cnt FROM webhook_event_log WHERE event_type IN ('security.blacklist.blocked', 'security.outbound.blocked') AND create_time >= datetime('now', '-24 hour')`).first()];

		const summary = `🧠 Summary (24h): Failed login <b>${failed24h}</b> | Blocked mail <b>${blocked24h}</b> | Risky IP cache <b>${results?.length || 0}</b>`;

		const securityButtons = failedItems.map(item => ([{ text: `🧾 Event #${item.logId}`, callback_data: `cmd:securityevent:${item.logId}` }]));
		const blacklistButtons = blacklistItems.map(item => {
			const row = [{ text: `🚫 Blocked #${item.logId}`, callback_data: `cmd:securityevent:${item.logId}` }];
			const previewUrl = blacklistPreviewMap.get(item.logId);
			if (previewUrl) row.push({ text: '🔎 Preview', web_app: { url: previewUrl } });
			return row;
		});

		const replyMarkup = {
			inline_keyboard: [
				[{ text: '📊 Status', callback_data: 'cmd:status' }, { text: '🗂 Full Events', callback_data: 'cmd:events:1' }],
				...securityButtons,
				...blacklistButtons,
				[{ text: '🚫 Blacklist Rules', callback_data: 'cmd:blacklist' }, { text: '🔑 Keyword Rules', callback_data: 'cmd:keyword' }],
				[{ text: '🏠 Menu', callback_data: 'cmd:menu' }]
			]
		};

		return {
			text: `🔐 <b>/security dashboard</b>\n\n${summary}\n\n<b>⚠️ Risky IPs (cache)</b>\n${riskyLines}\n\n<b>🔒 Failed login events (latest)</b>\n${failedPreview}\n\n<b>🚫 Blocked email logs (important)</b>\n${blacklistPreview}\n\nTip: tap an event button or run <code>/security event &lt;id&gt;</code> for full detail.`,
			replyMarkup
		};
	},

	async formatSecurityEventDetailCommand(c, eventIdArg) {
		return await this.formatEventDetailCommand(c, eventIdArg, { fromSecurity: true });
	},

	// ─── NEW COMMAND: BAN USER ────────────────────────────────────────────────

	async formatBanUserCommand(c, userIdArg, action = 'ban') {
		const userId = Number(userIdArg || 0);
		if (!userId) return { text: `🚫 Usage: <code>/ban &lt;userId&gt;</code> or <code>/unban &lt;userId&gt;</code>`, replyMarkup: this.buildMainMenu() };

		const userRow = await c.env.db.prepare('SELECT user_id as userId, email, status, is_del as isDel FROM user WHERE user_id = ?').bind(userId).first();
		if (!userRow) return { text: `🚫 User #${userId} not found.`, replyMarkup: this.buildMainMenu() };

		if (this.isAdminUser(c, userRow.email)) {
			return { text: `🚫 Cannot ban admin user.`, replyMarkup: this.buildMainMenu() };
		}

		const newStatus = action === 'ban' ? 1 : 0;
		await c.env.db.prepare('UPDATE user SET status = ? WHERE user_id = ?').bind(newStatus, userId).run();

		const actionText = action === 'ban' ? '🚫 Banned' : '✅ Unbanned';
		return { text: `${actionText} user #${userId} <code>${userRow.email}</code>`, replyMarkup: this.buildMainMenu() };
	},

	// ─── WHOIS COMMAND ────────────────────────────────────────────────────────

	async formatWhoisCommand(c, ipArg) {
		const ip = String(ipArg || '').trim();
		if (!ip || ip === 'help') {
			return { text: `🌐 <b>/whois</b>\nUsage: <code>/whois 1.1.1.1</code>`, replyMarkup: this.buildMainMenu() };
		}
		const detail = await this.queryIpSecurity(c, ip, { noCache: true });
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
		const userLines = relatedUsers.map(item => `• #${item.userId} ${item.email} | status=${item.status} | active=${item.activeIp || '-'} create=${item.createIp || '-'}`).join('\n');

		return {
			text: `🌐 <b>/whois ${ip}</b>

🛡️ VPN/Proxy/Tor/Relay: ${sec.vpn ? '✅' : '❌'}/${sec.proxy ? '✅' : '❌'}/${sec.tor ? '✅' : '❌'}/${sec.relay ? '✅' : '❌'}
🏙️ Location: ${loc.city || '-'}, ${loc.region || '-'}, ${loc.country || '-'} (${loc.country_code || '-'})
🏢 ASN Org: ${net.autonomous_system_organization || '-'}
🔢 ASN: ${net.autonomous_system_number || '-'}

👥 <b>Accounts with this IP</b>
${userLines || '-'}`,
			replyMarkup: this.buildMainMenu()
		};
	},

	// ─── STATS COMMAND ────────────────────────────────────────────────────────

	async formatStatsCommand(c, rangeArg = '7d') {
		const sub = String(rangeArg || '').toLowerCase();
		if (sub === 'top') return await this.formatStatsTopCommand(c);
		if (sub === 'bounce') return await this.formatStatsBounceCommand(c);

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
		let regTotal = 0, recvTotal = 0, sendTotal = 0;
		for (let i = days - 1; i >= 0; i--) {
			const day = dayjs.utc().subtract(i, 'day').format('YYYY-MM-DD');
			const reg = regMap.get(day) || 0;
			const recv = recvMap.get(day) || 0;
			const send = sendMap.get(day) || 0;
			regTotal += reg; recvTotal += recv; sendTotal += send;
			const bar = recv > 0 ? '▓'.repeat(Math.min(10, recv)) : '░';
			lines.push(`${day}: 👤${reg} 📥${recv} ${bar} 📤${send}`);
		}

		return {
			text: `📈 <b>/stats ${days}d</b>

<b>Totals</b>
👤 New users: ${regTotal}
📥 Received: ${recvTotal}
📤 Sent: ${sendTotal}

<b>Daily (U=users R=receive S=send)</b>
${lines.join('\n')}`,
			replyMarkup: { inline_keyboard: [[{ text: '🏆 Top Users', callback_data: 'cmd:stats:top' }, { text: '📉 Bounce/Fail', callback_data: 'cmd:stats:bounce' }], [{ text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
		};
	},

	// ─── EVENTS COMMAND ───────────────────────────────────────────────────────

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
			if (!items.length) return { text: `🗂 <b>/events</b>\nNo webhook event logs yet.`, replyMarkup: this.buildMainMenu() };

			const hasNext = items.length > pageSize;
			const visible = hasNext ? items.slice(0, pageSize) : items;
			const levelEmoji = { info: 'ℹ️', warn: '⚠️', error: '❌' };
			const body = visible.map(item => {
				const lines = String(item.message || '').split('\n').filter(Boolean);
				const preview = lines.slice(0, 2).join(' ');
				return `${levelEmoji[item.level] || '•'} #${item.logId} [${item.eventType}]\n${preview.slice(0, 120)}\n🕐 ${item.createTime}`;
			}).join('\n\n');

			const eventButtons = visible.map(item => [{ text: `🧾 #${item.logId} ${item.eventType}`, callback_data: `cmd:event:${item.logId}:${currentPage}` }]);
			const pagerMarkup = this.buildPager('events', currentPage, hasNext);
			const replyMarkup = { inline_keyboard: [...eventButtons, ...(pagerMarkup?.inline_keyboard || [])] };
			return { text: `🗂 <b>/events</b> (page ${currentPage})\n\n${body}`, replyMarkup };
		} catch (e) {
			return { text: `🗂 <b>/events</b>\nError: ${e.message}`, replyMarkup: this.buildMainMenu() };
		}
	},

	async formatEventDetailCommand(c, idArg, options = {}) {
		const logId = Number(idArg || 0);
		const fromSecurity = Boolean(options?.fromSecurity);
		const backPage = Math.max(1, Number(options?.backPage || 1));
		const finalBackText = options?.backText || (fromSecurity ? '🔐 Security List' : '🗂 Events List');
		const finalBackCallbackData = options?.backCallbackData || (fromSecurity ? 'cmd:security' : `cmd:events:${backPage}`);

		if (!logId) return { text: `🧾 <b>/event</b>\nUsage: <code>/event 123</code>`, replyMarkup: this.buildDetailMenu({ backText: finalBackText, backCallbackData: finalBackCallbackData }) };

		const row = await c.env.db.prepare(`
			SELECT log_id as logId, event_type as eventType, level, message, meta, create_time as createTime
			FROM webhook_event_log WHERE log_id = ?
		`).bind(logId).first();
		if (!row) return { text: `🧾 Event #${logId} not found.`, replyMarkup: this.buildDetailMenu({ backText: finalBackText, backCallbackData: finalBackCallbackData }) };

		let meta = {};
		try { meta = row.meta ? JSON.parse(row.meta) : {}; } catch (_) {}
		const previewUrl = meta?.webAppUrl;

		const detail = `🧾 <b>/event ${row.logId}</b>

Type: ${row.eventType}
Level: ${row.level}
At: ${row.createTime}

Message:
${row.message}

Meta: <code>${JSON.stringify(meta || {}, null, 2).slice(0, 1200)}</code>`;

		return { text: detail, replyMarkup: this.buildDetailMenu({ backText: finalBackText, backCallbackData: finalBackCallbackData, previewUrl }) };
	},

	// ─── MAIL COMMANDS ────────────────────────────────────────────────────────

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

		if (rows.length === 0) return { text: `📭 <b>/mail</b>\nNo email data.`, replyMarkup: this.buildMainMenu() };
		const hasNext = rows.length > pageSize;
		const visibleRows = hasNext ? rows.slice(0, pageSize) : rows;
		const body = visibleRows.map(item => `🆔 <code>${item.emailId}</code> | ${item.type === 0 ? '📥 RECV' : '📤 SEND'} | del=${item.isDel}
From: <code>${item.sendEmail || '-'}</code>
To: <code>${item.toEmail || '-'}</code>
Subj: ${(item.subject || '-').slice(0, 60)}
At: ${item.createTime}`).join('\n\n');

		const mailButtons = visibleRows.map(item => [{ text: `✉️ #${item.emailId} ${(item.subject || '(no subject)').slice(0, 50)}`, callback_data: `cmd:mailid:${item.emailId}:${currentPage}` }]);
		const pagerMarkup = this.buildPager('mail', currentPage, hasNext);
		const replyMarkup = { inline_keyboard: [...mailButtons, ...(pagerMarkup?.inline_keyboard || [])] };
		return { text: `📨 <b>/mail</b> (page ${currentPage})\n\n${body}`, replyMarkup };
	},

	async formatMailDetailCommand(c, emailIdArg, pageArg = 1) {
		const emailId = Number(emailIdArg || 0);
		const backPage = Math.max(1, Number(pageArg || 1));
		if (!emailId) return { text: `📨 <b>/mail</b>\nUsage: <code>/mail 120</code>`, replyMarkup: this.buildDetailMenu({ backText: '📨 Mail List', backCallbackData: 'cmd:mail:1' }) };

		const row = await c.env.db.prepare(`
			SELECT email_id as emailId, send_email as sendEmail, to_email as toEmail,
				subject, text, type, status, create_time as createTime,
				user_id as userId, unread, is_del as isDel
			FROM email WHERE email_id = ?
		`).bind(emailId).first();

		if (!row) return { text: `📨 Email #${emailId} not found.`, replyMarkup: this.buildDetailMenu({ backText: '📨 Mail List', backCallbackData: `cmd:mail:${backPage}` }) };

		const { customDomain } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: row.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : null;

		const statusMap = { 0: 'Saving', 1: 'Received', 2: 'Sent', 3: 'Delivered', 4: 'Bounced', 5: 'Failed', 6: 'Complained', 7: 'Delayed', 8: 'No recipient' };
		const preview = (row.text || '').slice(0, 200);

		const isDelLabel = row.isDel === 1
			? '🗑️ Soft deleted (is_del=1) — hidden from user'
			: row.isDel === 2
				? '💥 Hard deleted (is_del=2)'
				: '✅ Active (not deleted)';

		const detail = `📧 <b>Email #${row.emailId}</b>

📥/📤 Type: ${row.type === 0 ? 'Received' : 'Sent'}
📊 Status: ${statusMap[row.status] || row.status}
👁️ Read: ${row.unread ? 'Unread' : 'Read'}
🗑️ Deleted: ${isDelLabel}

📤 From: <code>${row.sendEmail || '-'}</code>
📨 To: <code>${row.toEmail || '-'}</code>
📝 Subject: ${row.subject || '-'}
🆔 User ID: ${row.userId}
🕐 At: ${row.createTime}

💬 Preview:
${preview || '-'}`;

		return { text: detail, replyMarkup: this.buildDetailMenu({ backText: '📨 Mail List', backCallbackData: `cmd:mail:${backPage}`, previewUrl: webAppUrl }) };
	},

	// ─── SYSTEM COMMAND ───────────────────────────────────────────────────────

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
					ORDER BY log_id DESC LIMIT 3
				`).all()
			]);

			const webhookUrl = webhookInfo?.result?.url || '-';
			const pending = webhookInfo?.result?.pending_update_count ?? '-';
			const lastError = webhookInfo?.result?.last_error_message || '-';
			const pushMode = await this.shouldSendWebhookPush(c) ? 'Push + Log' : 'Log only';

			const logs = (recentSystemLogs?.results || []).map((row, i) => {
				const firstLine = String(row.message || '').split('\n').find(Boolean) || '-';
				return `${i + 1}. [${row.createTime || '-'}] [${row.level}] ${row.eventType}: ${firstLine.slice(0, 150)}`;
			}).join('\n');

			return `🧭 <b>/system</b>

<b>💾 IP Cache</b>
Total rows: ${cacheCount?.total || 0}
Stale (≥2 days): ${staleCount?.total || 0}

<b>🤖 Webhook</b>
URL: <code>${webhookUrl}</code>
Pending: ${pending}
Last Error: ${lastError}
Notify Mode: ${pushMode}

<b>📜 Recent Email/Error Logs</b>
${logs || 'No logs yet.'}`;
		} catch (e) {
			return `🧭 <b>/system</b>\nError: ${e.message}`;
		}
	},

	// ─── INVITE COMMANDS ──────────────────────────────────────────────────────

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

		if (rows.length === 0) return { text: `🎟️ <b>/invite</b>\nNo invite code data.`, replyMarkup: this.buildMainMenu() };

		const hasNext = rows.length > pageSize;
		const visibleRows = hasNext ? rows.slice(0, pageSize) : rows;
		const roleRows = await orm(c).select().from(role);
		const roleMap = new Map(roleRows.map(r => [r.roleId, r.name]));

		const body = visibleRows.map(item => {
			const roleName = roleMap.get(item.roleId) || `Role ${item.roleId}`;
			const expired = item.expireTime && dayjs.utc(item.expireTime).isBefore(dayjs.utc()) ? ' ⛔ Expired' : '';
			const exhausted = item.count <= 0 ? ' ⚠️ Exhausted' : '';
			return `🆔 <code>${item.regKeyId}</code> <code>${item.code}</code> | ${roleName}${expired}${exhausted}\n   Uses left: ${item.count} | Expire: ${item.expireTime || '-'}`;
		}).join('\n');

		const inviteButtons = visibleRows.map(item => [{ text: `🎟️ #${item.regKeyId} ${item.code}`.slice(0, 64), callback_data: `cmd:inviteid:${item.regKeyId}:${currentPage}` }]);
		const pagerMarkup = this.buildPager('invite', currentPage, hasNext);
		const replyMarkup = { inline_keyboard: [...inviteButtons, ...(pagerMarkup?.inline_keyboard || [])] };
		return { text: `🎟️ <b>/invite</b> (page ${currentPage})\n\n${body}`, replyMarkup };
	},

	async formatInviteDetailCommand(c, inviteIdArg, pageArg = 1) {
		const inviteId = Number(inviteIdArg || 0);
		const backPage = Math.max(1, Number(pageArg || 1));
		if (!inviteId) return { text: `🎟️ Usage: <code>/invite 6</code>`, replyMarkup: this.buildDetailMenu({ backText: '🎟 Invite List', backCallbackData: 'cmd:invite:1' }) };

		const item = await orm(c).select().from(regKey).where(eq(regKey.regKeyId, inviteId)).get();
		if (!item) return { text: `🎟️ Invite #${inviteId} not found.`, replyMarkup: this.buildDetailMenu({ backText: '🎟 Invite List', backCallbackData: `cmd:invite:${backPage}` }) };

		const roleInfo = await orm(c).select().from(role).where(eq(role.roleId, item.roleId)).get();
		const enrichedRole = roleInfo ? await this.attachRolePermInfo(c, { ...roleInfo }) : null;

		const historyRows = await c.env.db.prepare(`
			SELECT user_id as userId, email, create_time as createTime FROM user WHERE reg_key_id = ? ORDER BY user_id DESC LIMIT 5
		`).bind(inviteId).all();
		const historyUsers = historyRows?.results || [];
		const historyText = historyUsers.length
			? historyUsers.map(u => `• #${u.userId} ${u.email} (${u.createTime})`).join('\n')
			: '-';

		const expired = item.expireTime && dayjs.utc(item.expireTime).isBefore(dayjs.utc()) ? ' ⛔ Expired' : '';
		const exhausted = item.count <= 0 ? ' ⚠️ Exhausted' : '';

		const text = `🎟️ <b>Invite Detail #${inviteId}</b>

🔑 Code: <code>${item.code}</code>${expired}${exhausted}
🛡️ Role: ${roleInfo?.name || '-'}
📤 Send limit: ${enrichedRole ? this.formatSendLimit(enrichedRole) : '-'}
📬 Address limit: ${enrichedRole ? this.formatAddressLimit(enrichedRole) : '-'}
🔢 Uses left: ${item.count}
⏳ Expire: ${item.expireTime || '-'}
🗓️ Created: ${item.createTime || '-'}

<b>Recent users who used this code:</b>
${historyText}`;

		return { text, replyMarkup: this.buildDetailMenu({ backText: '🎟 Invite List', backCallbackData: `cmd:invite:${backPage}` }) };
	},

	// ─── SEARCH COMMANDS ──────────────────────────────────────────────────────

	async formatSearchCommand(c, typeArg, queryArgs = []) {
		const type = String(typeArg || '').toLowerCase();
		const query = String((queryArgs || []).join(' ').trim());
		if (!type) return { text: this.formatSearchHelp('general'), replyMarkup: this.buildSearchMenu() };
		if (type === 'ip') return await this.formatWhoisCommand(c, query);
		if (type === 'email') return await this.formatMailDetailCommand(c, query, 1);
		if (type === 'invite') {
			if (!query) return { text: this.formatSearchHelp('invite'), replyMarkup: this.buildSearchMenu() };
			let row = null;
			if (/^\d+$/.test(query)) row = await orm(c).select({ regKeyId: regKey.regKeyId }).from(regKey).where(eq(regKey.regKeyId, Number(query))).get();
			if (!row) {
				const byCode = await c.env.db.prepare('SELECT reg_key_id as regKeyId FROM reg_key WHERE code = ? LIMIT 1').bind(query).first();
				if (byCode) row = byCode;
			}
			if (!row?.regKeyId) return { text: `🔎 Invite not found: <code>${query}</code>`, replyMarkup: this.buildSearchMenu() };
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
			if (!roleRow) return { text: `🔎 Role not found: <code>${query}</code>`, replyMarkup: this.buildSearchMenu() };
			const roleInfo = await this.attachRolePermInfo(c, { ...roleRow });
			return {
				text: `🔎 <b>Search Result: Role</b>

🆔 <code>${roleInfo.roleId}</code> <b>${roleInfo.name}</b>
📤 Send limit: ${this.formatSendLimit(roleInfo)}
📬 Address limit: ${this.formatAddressLimit(roleInfo)}
✉️ Can send: ${roleInfo.canSendEmail ? 'Yes' : 'No'} | add-address: ${roleInfo.canAddAddress ? 'Yes' : 'No'}
🚫 Ban email: ${roleInfo.banEmail || '-'}
🌐 Avail domain: ${roleInfo.availDomain || 'All'}
⭐ Default: ${roleInfo.isDefault ? 'Yes' : 'No'}`,
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
			if (!matchedUser) return { text: `🔎 User not found: <code>${query}</code>`, replyMarkup: this.buildSearchMenu() };
			return await this.formatUserDetailCommand(c, matchedUser.userId, 1, matchedAccount?.accountId || null);
		}
		return { text: this.formatSearchHelp('general'), replyMarkup: this.buildSearchMenu() };
	},

	// ─── NEW COMMAND: RECENT EMAILS ──────────────────────────────────────────

	async formatRecentCommand(c) {
		const rows = await c.env.db.prepare(`
			SELECT e.email_id as emailId, e.send_email as sendEmail, e.to_email as toEmail,
				e.subject, e.type, e.is_del as isDel, e.create_time as createTime,
				e.user_id as userId, u.email as userEmail
			FROM email e
			LEFT JOIN user u ON u.user_id = e.user_id
			ORDER BY e.email_id DESC
			LIMIT 10
		`).all();
		const items = rows?.results || [];
		if (!items.length) return { text: `📬 <b>/recent</b>\nNo emails yet.`, replyMarkup: this.buildMainMenu() };

		const body = items.map(item => {
			const typeIcon = item.type === 0 ? '📥' : '📤';
			const subj = (item.subject || '(no subject)').slice(0, 50);
			const ownerTag = item.userEmail ? ` | 👤 #${item.userId}` : '';
			return `${typeIcon} <code>#${item.emailId}</code>${ownerTag}\nFrom: ${item.sendEmail || '-'} → To: ${item.toEmail || '-'}\nSubj: ${subj}\nAt: ${item.createTime}`;
		}).join('\n\n');

		const mailButtons = items.map(item => [{ text: `✉️ #${item.emailId} ${(item.subject || '(no subject)').slice(0, 45)}`, callback_data: `cmd:mailid:${item.emailId}:1` }]);
		const replyMarkup = { inline_keyboard: [...mailButtons, [{ text: '🏠 Menu', callback_data: 'cmd:menu' }]] };
		return { text: `📬 <b>/recent</b> — Last 10 emails\n\n${body}`, replyMarkup };
	},

	// ─── NEW COMMAND: RESET QUOTA ─────────────────────────────────────────────

	async formatResetQuotaCommand(c, userIdArg) {
		const userId = Number(userIdArg || 0);
		if (!userId) return { text: `🔄 Usage: <code>/resetquota &lt;userId&gt;</code>`, replyMarkup: this.buildMainMenu() };

		const userRow = await c.env.db.prepare('SELECT user_id as userId, email, send_count as sendCount FROM user WHERE user_id = ?').bind(userId).first();
		if (!userRow) return { text: `🔄 User #${userId} not found.`, replyMarkup: this.buildMainMenu() };

		const oldCount = userRow.sendCount || 0;
		await c.env.db.prepare('UPDATE user SET send_count = 0 WHERE user_id = ?').bind(userId).run();
		await this.logSystemEvent(c, 'admin.quota.reset', EVENT_LEVEL.INFO, `Quota reset for user #${userId} ${userRow.email} (was ${oldCount})`, { userId, email: userRow.email, oldCount });

		return { text: `✅ <b>Quota Reset</b>\n\nUser: #${userId} <code>${userRow.email}</code>\nPrevious send_count: ${oldCount} → 0`, replyMarkup: { inline_keyboard: [[{ text: '👤 View User', callback_data: `cmd:userid:${userId}:1` }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] } };
	},

	// ─── NEW COMMAND: USER MAIL LIST ─────────────────────────────────────────

	async formatUserMailCommand(c, userIdArg, pageArg = 1) {
		const userId = Number(userIdArg || 0);
		const currentPage = Math.max(1, Number(pageArg) || 1);
		const pageSize = 8;
		if (!userId) return { text: `📧 Usage: <code>/usermail &lt;userId&gt;</code>`, replyMarkup: this.buildMainMenu() };

		const userRow = await c.env.db.prepare('SELECT user_id as userId, email FROM user WHERE user_id = ?').bind(userId).first();
		if (!userRow) return { text: `📧 User #${userId} not found.`, replyMarkup: this.buildMainMenu() };

		const rows = await c.env.db.prepare(`
			SELECT email_id as emailId, send_email as sendEmail, to_email as toEmail,
				subject, type, is_del as isDel, create_time as createTime
			FROM email
			WHERE user_id = ?
			ORDER BY email_id DESC
			LIMIT ? OFFSET ?
		`).bind(userId, pageSize + 1, (currentPage - 1) * pageSize).all();

		const items = rows?.results || [];
		if (!items.length && currentPage === 1) return {
			text: `📧 <b>Emails of #${userId} ${userRow.email}</b>\n\nNo emails found.`,
			replyMarkup: { inline_keyboard: [[{ text: '👤 Back to User', callback_data: `cmd:userid:${userId}:1` }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
		};

		const hasNext = items.length > pageSize;
		const visible = hasNext ? items.slice(0, pageSize) : items;
		const body = visible.map(item => {
			const typeIcon = item.type === 0 ? '📥' : '📤';
			return `${typeIcon} <code>#${item.emailId}</code> ${(item.subject || '(no subject)').slice(0, 45)}\n  ${item.sendEmail || '-'} → ${item.toEmail || '-'} | ${item.createTime}`;
		}).join('\n');

		const mailButtons = visible.map(item => [{ text: `✉️ #${item.emailId} ${(item.subject || '(no subject)').slice(0, 45)}`, callback_data: `cmd:mailid:${item.emailId}:${currentPage}` }]);

		const navButtons = [];
		if (currentPage > 1) navButtons.push({ text: '⬅️ Prev', callback_data: `cmd:usermail:${userId}:${currentPage - 1}` });
		if (hasNext) navButtons.push({ text: 'Next ➡️', callback_data: `cmd:usermail:${userId}:${currentPage + 1}` });

		const replyMarkup = { inline_keyboard: [...mailButtons, navButtons.length ? navButtons : [], [{ text: '👤 Back to User', callback_data: `cmd:userid:${userId}:1` }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]].filter(r => r.length) };
		return { text: `📧 <b>Emails of #${userId} ${userRow.email}</b> (page ${currentPage})\n\n${body}`, replyMarkup };
	},

	// ─── NEW COMMAND: STATS TOP ───────────────────────────────────────────────

	async formatStatsTopCommand(c) {
		const [topSenders, topReceivers, topActive] = await Promise.all([
			c.env.db.prepare(`
				SELECT u.user_id as userId, u.email, COUNT(*) as cnt
				FROM email e
				JOIN user u ON u.user_id = e.user_id
				WHERE e.type = 1 AND e.is_del = 0
				GROUP BY e.user_id ORDER BY cnt DESC LIMIT 5
			`).all(),
			c.env.db.prepare(`
				SELECT u.user_id as userId, u.email, COUNT(*) as cnt
				FROM email e
				JOIN user u ON u.user_id = e.user_id
				WHERE e.type = 0 AND e.is_del = 0
				GROUP BY e.user_id ORDER BY cnt DESC LIMIT 5
			`).all(),
			c.env.db.prepare(`
				SELECT u.user_id as userId, u.email, COUNT(*) as cnt
				FROM webhook_event_log w
				JOIN user u ON CAST(json_extract(w.meta, '$.userId') AS INTEGER) = u.user_id
				WHERE w.create_time >= datetime('now', '-7 day')
				GROUP BY u.user_id ORDER BY cnt DESC LIMIT 5
			`).all()
		]);

		const fmt = (rows) => (rows?.results || []).map((r, i) => `${i + 1}. #${r.userId} ${r.email} — ${r.cnt}`).join('\n') || '-';
		return {
			text: `📈 <b>/stats top</b>\n\n<b>📤 Top Senders (all time)</b>\n${fmt(topSenders)}\n\n<b>📥 Top Receivers (all time)</b>\n${fmt(topReceivers)}\n\n<b>🔥 Most Active (last 7d events)</b>\n${fmt(topActive)}`,
			replyMarkup: { inline_keyboard: [[{ text: '📈 Back to Stats', callback_data: 'cmd:stats:7d' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
		};
	},

	// ─── NEW COMMAND: STATS BOUNCE ────────────────────────────────────────────

	async formatStatsBounceCommand(c) {
		const rows = await c.env.db.prepare(`
			SELECT e.email_id as emailId, e.send_email as sendEmail, e.to_email as toEmail,
				e.subject, e.status, e.create_time as createTime, u.email as userEmail, e.user_id as userId
			FROM email e
			LEFT JOIN user u ON u.user_id = e.user_id
			WHERE e.status IN (4, 5, 6, 7, 8)
			ORDER BY e.email_id DESC
			LIMIT 15
		`).all();

		const statusLabel = { 4: '🔴 Bounced', 5: '❌ Failed', 6: '⚠️ Complained', 7: '⏳ Delayed', 8: '📭 No recipient' };
		const items = rows?.results || [];
		if (!items.length) return {
			text: `📉 <b>/stats bounce</b>\n\n✅ No bounced/failed emails found.`,
			replyMarkup: { inline_keyboard: [[{ text: '📈 Back to Stats', callback_data: 'cmd:stats:7d' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
		};

		const countByStatus = {};
		items.forEach(item => { countByStatus[item.status] = (countByStatus[item.status] || 0) + 1; });
		const summary = Object.entries(countByStatus).map(([s, n]) => `${statusLabel[s] || `Status ${s}`}: ${n}`).join(' | ');

		const body = items.map(item => {
			const lbl = statusLabel[item.status] || `Status ${item.status}`;
			return `${lbl} <code>#${item.emailId}</code>\n  From: ${item.sendEmail || '-'} → ${item.toEmail || '-'}\n  Subj: ${(item.subject || '-').slice(0, 50)}\n  User: #${item.userId} | At: ${item.createTime}`;
		}).join('\n\n');

		const mailButtons = items.slice(0, 8).map(item => [{ text: `✉️ #${item.emailId} ${statusLabel[item.status] || ''} ${(item.subject || '(no subject)').slice(0, 35)}`, callback_data: `cmd:mailid:${item.emailId}:1` }]);
		const replyMarkup = { inline_keyboard: [...mailButtons, [{ text: '📈 Back to Stats', callback_data: 'cmd:stats:7d' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] };
		return { text: `📉 <b>/stats bounce</b> — Recent failures\n${summary}\n\n${body}`, replyMarkup };
	},

	// ─── SECURITY: BLACKLIST MANAGEMENT ──────────────────────────────────────

	async formatSecurityBlacklistCommand(c, subArg, targetArg) {
		const sub = String(subArg || 'list').toLowerCase();
		// Support multiple targets separated by comma or space-after-comma
		const rawTargets = String(targetArg || '').trim();
		const targets = rawTargets.split(/[\s,]+/).map(t => t.trim()).filter(Boolean);

		try {
			await c.env.db.prepare(`
				CREATE TABLE IF NOT EXISTS ban_email (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					email TEXT UNIQUE NOT NULL,
					create_time TEXT DEFAULT (datetime('now'))
				)
			`).run();
		} catch (e) {}

		const backMarkup = { inline_keyboard: [[{ text: '🚫 Blacklist', callback_data: 'cmd:blacklist' }, { text: '🔐 Security', callback_data: 'cmd:security' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] };

		if (sub === 'add' || sub === 'remove') {
			if (!targets.length) return {
				text: `🚫 Usage:\n• <code>/security blacklist ${sub} email@ex.com</code>\n• <code>/security blacklist ${sub} evil.com,spam.net,bad@x.com</code>`,
				replyMarkup: backMarkup
			};

			const results = { added: [], skipped: [], removed: [], notFound: [], invalid: [] };

			for (const target of targets) {
				const normalized = this.normalizeBlacklistTarget(target);
				if (!normalized) { results.invalid.push(target); continue; }
				const safe = this.escapeHtml(normalized);

				if (sub === 'add') {
					try {
						const existing = await c.env.db.prepare('SELECT id FROM ban_email WHERE lower(email) = ?').bind(normalized).first();
						if (existing) { results.skipped.push(safe); continue; }
						await c.env.db.prepare(`INSERT INTO ban_email (email, create_time) VALUES (?, datetime('now'))`).bind(normalized).run();
						results.added.push(safe);
					} catch (e) { results.invalid.push(safe); }
				} else {
					try {
						const res = await c.env.db.prepare('DELETE FROM ban_email WHERE lower(email) = ?').bind(normalized).run();
						if (!res.meta?.changes) { results.notFound.push(safe); continue; }
						results.removed.push(safe);
					} catch (e) { results.invalid.push(safe); }
				}
			}

			if (results.added.length) await this.logSystemEvent(c, 'admin.blacklist.add', EVENT_LEVEL.WARN, `Blacklisted: ${results.added.join(', ')}`, { emails: results.added });
			if (results.removed.length) await this.logSystemEvent(c, 'admin.blacklist.remove', EVENT_LEVEL.INFO, `Removed from blacklist: ${results.removed.join(', ')}`, { emails: results.removed });

			const lines = [];
			if (results.added.length) lines.push(`✅ Added (${results.added.length}): ${results.added.map(e => `<code>${e}</code>`).join(', ')}`);
			if (results.removed.length) lines.push(`✅ Removed (${results.removed.length}): ${results.removed.map(e => `<code>${e}</code>`).join(', ')}`);
			if (results.skipped.length) lines.push(`⚠️ Already exists: ${results.skipped.map(e => `<code>${e}</code>`).join(', ')}`);
			if (results.notFound.length) lines.push(`⚠️ Not found: ${results.notFound.map(e => `<code>${e}</code>`).join(', ')}`);
			if (results.invalid.length) lines.push(`❌ Invalid: ${results.invalid.map(e => `<code>${e}</code>`).join(', ')}`);

			return { text: `🚫 <b>Blacklist ${sub === 'add' ? 'Add' : 'Remove'} Result</b>\n\n${lines.join('\n')}`, replyMarkup: backMarkup };
		}

		// List
		try {
			const rows = await c.env.db.prepare('SELECT id, email, create_time as createTime FROM ban_email ORDER BY id DESC LIMIT 20').all();
			const items = rows?.results || [];
			const body = items.length
				? items.map(r => `🚫 <code>${this.escapeHtml(r.email)}</code> — ${r.createTime || '-'}`).join('\n')
				: '✅ Blacklist is empty.';

			return {
				text: `🚫 <b>Email/Domain Blacklist</b>\n\n${body}\n\n<b>Commands (batch supported with comma):</b>\n• <code>/security blacklist add evil.com,spam@x.com</code>\n• <code>/security blacklist remove evil.com,spam@x.com</code>`,
				replyMarkup: { inline_keyboard: [[{ text: '🔐 Security', callback_data: 'cmd:security' }, { text: '🔑 Keywords', callback_data: 'cmd:keyword' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
			};
		} catch (e) {
			return { text: `🚫 <b>Email Blacklist</b>\n\nError: ${e.message}`, replyMarkup: backMarkup };
		}
	},

	async formatSecurityKeywordCommand(c, subArg, keywordArg) {
		const sub = String(subArg || 'list').toLowerCase();
		const rawKeywords = String(keywordArg || '').trim().toLowerCase();
		const keywords = rawKeywords.split(/[\s,]+/).map(k => k.trim()).filter(k => k.length >= 2);
		const tooShort = rawKeywords.split(/[\s,]+/).map(k => k.trim()).filter(k => k.length > 0 && k.length < 2);

		try {
			await c.env.db.prepare(`
				CREATE TABLE IF NOT EXISTS ban_keyword (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					keyword TEXT UNIQUE NOT NULL,
					create_time TEXT DEFAULT (datetime('now'))
				)
			`).run();
		} catch (e) {}

		const backMarkup = { inline_keyboard: [[{ text: '🔑 Keywords', callback_data: 'cmd:keyword' }, { text: '🔐 Security', callback_data: 'cmd:security' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] };

		if (sub === 'add' || sub === 'remove') {
			if (!keywords.length && !tooShort.length) return {
				text: `🔑 Usage:\n• <code>/security keyword ${sub} judi</code>\n• <code>/security keyword ${sub} judi,gacor,slot,togel</code>`,
				replyMarkup: backMarkup
			};

			const results = { added: [], skipped: [], removed: [], notFound: [], tooShort };

			for (const kw of keywords) {
				const safe = this.escapeHtml(kw);
				if (sub === 'add') {
					try {
						const existing = await c.env.db.prepare('SELECT id FROM ban_keyword WHERE lower(keyword) = ?').bind(kw).first();
						if (existing) { results.skipped.push(safe); continue; }
						await c.env.db.prepare(`INSERT INTO ban_keyword (keyword, create_time) VALUES (?, datetime('now'))`).bind(kw).run();
						results.added.push(safe);
					} catch (e) { results.skipped.push(safe); }
				} else {
					try {
						const res = await c.env.db.prepare('DELETE FROM ban_keyword WHERE lower(keyword) = ?').bind(kw).run();
						if (!res.meta?.changes) { results.notFound.push(safe); continue; }
						results.removed.push(safe);
					} catch (e) { results.notFound.push(safe); }
				}
			}

			if (results.added.length) await this.logSystemEvent(c, 'admin.keyword.add', EVENT_LEVEL.WARN, `Keywords added: ${results.added.join(', ')}`, { keywords: results.added });
			if (results.removed.length) await this.logSystemEvent(c, 'admin.keyword.remove', EVENT_LEVEL.INFO, `Keywords removed: ${results.removed.join(', ')}`, { keywords: results.removed });

			const lines = [];
			if (results.added.length) lines.push(`✅ Added (${results.added.length}): ${results.added.map(k => `<code>${k}</code>`).join(', ')}`);
			if (results.removed.length) lines.push(`✅ Removed (${results.removed.length}): ${results.removed.map(k => `<code>${k}</code>`).join(', ')}`);
			if (results.skipped.length) lines.push(`⚠️ Already exists: ${results.skipped.map(k => `<code>${k}</code>`).join(', ')}`);
			if (results.notFound.length) lines.push(`⚠️ Not found: ${results.notFound.map(k => `<code>${k}</code>`).join(', ')}`);
			if (results.tooShort.length) lines.push(`❌ Too short (min 2 chars): ${results.tooShort.map(k => `<code>${k}</code>`).join(', ')}`);

			return { text: `🔑 <b>Keyword ${sub === 'add' ? 'Add' : 'Remove'} Result</b>\n\n${lines.join('\n')}`, replyMarkup: backMarkup };
		}

		// List
		try {
			const rows = await c.env.db.prepare('SELECT id, keyword, create_time as createTime FROM ban_keyword ORDER BY id DESC LIMIT 30').all();
			const items = rows?.results || [];
			const body = items.length
				? items.map(r => `🔑 <code>${this.escapeHtml(r.keyword)}</code> — ${r.createTime || '-'}`).join('\n')
				: '✅ Keyword list is empty.';

			return {
				text: `🔑 <b>Keyword Blacklist</b>\n\n${body}\n\n<b>Commands (batch dengan koma):</b>\n• <code>/security keyword add judi,gacor,slot,togel</code>\n• <code>/security keyword remove judi,gacor</code>\n\n<i>Dicek di: subject + body email (case-insensitive)\nBerlaku untuk email masuk DAN keluar.</i>`,
				replyMarkup: { inline_keyboard: [[{ text: '🔐 Security', callback_data: 'cmd:security' }, { text: '🚫 Blacklist', callback_data: 'cmd:blacklist' }, { text: '🏠 Menu', callback_data: 'cmd:menu' }]] }
			};
		} catch (e) {
			return { text: `🔑 <b>Keyword Blacklist</b>\n\nError: ${e.message}`, replyMarkup: backMarkup };
		}
	},

	// ─── NEW NOTIFICATION: PASSWORD CHANGE ALERT ──────────────────────────────

	async sendPasswordChangeNotification(c, userInfo, changeType = 'change') {
		const isAdmin = this.isAdminUser(c, userInfo.email);
		const roleRow = await this.getRoleById(c, userInfo.type);
		const isSiteAdmin = roleRow?.roleId === 2;
		const isPrivileged = isAdmin || isSiteAdmin;

		const typeLabel = changeType === 'reset' ? 'Password Reset' : 'Password Changed';
		const ipInfo = userInfo.activeIp ? ` from IP <code>${userInfo.activeIp}</code>` : '';
		const roleLabel = isAdmin ? 'Admin (env)' : (roleRow?.name || `role ${userInfo.type}`);

		const eventType = changeType === 'reset' ? 'auth.password.reset' : 'auth.password.change';
		const level = isPrivileged ? EVENT_LEVEL.WARN : EVENT_LEVEL.INFO;
		const message = `🔑 <b>${typeLabel}</b>
User: ${userInfo.email} (#${userInfo.userId || '-'})
Role: ${roleLabel}${ipInfo}
At: ${dayjs.utc().format('YYYY-MM-DD HH:mm:ss')} UTC`;

		await this.logSystemEvent(c, eventType, level, message, { userId: userInfo.userId, email: userInfo.email, changeType });

		if (isPrivileged) {
			await this.sendSecurityEventAlert(c,
				`⚠️ ${typeLabel}: <b>${userInfo.email}</b>`,
				`Role: ${roleLabel}${ipInfo}`
			);
		} else {
			await this.sendTelegramMessage(c, message);
		}
	},

	// ─── OUTBOUND FILTER: CHECK & NOTIFY ─────────────────────────────────────

	/**
	 * Call this from email-send service BEFORE actually sending.
	 * Returns { blocked: true, reason, matchedRule } if blocked, else { blocked: false }.
	 */
	async checkOutboundFilter(c, { toEmail, subject, bodyText }) {
		const toEmailLower = (toEmail || '').trim().toLowerCase();
		const toDomain = toEmailLower.includes('@') ? toEmailLower.split('@')[1] : '';

		// 1. Check recipient domain/email against ban_email
		try {
			const blacklisted = await c.env.db.prepare(`
				SELECT email FROM ban_email
				WHERE lower(email) = ? OR lower(email) = ?
				LIMIT 1
			`).bind(toEmailLower, toDomain).first();
			if (blacklisted) {
				return { blocked: true, reason: 'blacklist', matchedRule: blacklisted.email };
			}
		} catch (e) {
			if (!String(e?.message || '').toLowerCase().includes('no such table')) {
				console.error('Outbound blacklist check failed:', e.message);
			}
		}

		// 2. Check subject + body against ban_keyword
		try {
			const { results: keywords } = await c.env.db.prepare(`
				SELECT id, keyword FROM ban_keyword ORDER BY id ASC
			`).all();
			if (keywords?.length) {
				const combined = ((subject || '') + ' ' + (bodyText || '')).toLowerCase();
				const matched = keywords.find(k => combined.includes(String(k.keyword || '').toLowerCase()));
				if (matched) {
					return { blocked: true, reason: 'keyword', matchedRule: `keyword:${matched.keyword}` };
				}
			}
		} catch (e) {
			if (!String(e?.message || '').toLowerCase().includes('no such table')) {
				console.error('Outbound keyword check failed:', e.message);
			}
		}

		return { blocked: false };
	},

	/**
	 * Log a blocked outbound email attempt to security board (silent, no push).
	 */
	async logOutboundBlocked(c, { actorUser, toEmail, subject, bodyText, matchedRule, reason }) {
		try {
			await c.env.db.prepare(`
				CREATE TABLE IF NOT EXISTS ban_email_log (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					sender_email TEXT,
					to_email TEXT,
					matched_rule TEXT,
					subject TEXT,
					text_preview TEXT,
					html_content TEXT,
					create_time TEXT DEFAULT (datetime('now'))
				)
			`).run();

			const textPreview = (bodyText || '').slice(0, 500);

			await c.env.db.batch([
				c.env.db.prepare(`
					INSERT INTO ban_email_log (sender_email, to_email, matched_rule, subject, text_preview, html_content, create_time)
					VALUES (?, ?, ?, ?, ?, '', datetime('now'))
				`).bind(
					actorUser?.email || '-',
					toEmail || '-',
					matchedRule || '-',
					subject || '',
					textPreview
				),
				c.env.db.prepare(`
					DELETE FROM ban_email_log WHERE create_time <= datetime('now', '-24 hour')
				`)
			]);

			const lastRow = await c.env.db.prepare(`
				SELECT id FROM ban_email_log
				WHERE sender_email = ? AND to_email = ?
				ORDER BY id DESC LIMIT 1
			`).bind(actorUser?.email || '-', toEmail || '-').first();

			const banLogId = lastRow?.id || null;

			const actorIp = actorUser?.activeIp || '-';
			const actorRole = actorUser?.roleLabel || '-';

			await this.logSystemEvent(
				c,
				'security.outbound.blocked',
				'warn',
				`🚫 Outbound email blocked (${reason})\n👤 Actor: ${actorUser?.email || '-'} (#${actorUser?.userId || '-'})\n🛡️ Role: ${actorRole}\n📍 IP: ${actorIp}\n📨 To: ${toEmail}\n🔑 Matched: ${matchedRule}\n📝 Subject: ${subject || '-'}`,
				{
					actorEmail: actorUser?.email,
					actorUserId: actorUser?.userId,
					actorIp,
					toEmail,
					subject,
					matchedRule,
					reason,
					banLogId
				}
			);
		} catch (e) {
			console.error('Failed to log outbound block:', e.message);
		}
	},

	// ─── MAIN RESOLVER ────────────────────────────────────────────────────────

	async resolveCommand(c, command, args, chatId, userId) {
		const pageArg = Number(args?.[0] || 1);
		switch (command) {
			case '/start':
				return { text: await this.formatStatusCommand(c), replyMarkup: this.buildMainMenu() };
			case '/help':
				return {
					text: `🤖 <b>Abyn Mail Bot — Command Center</b>

📊 /status — Main dashboard (overview + runtime + counters)
🔐 /security — Security dashboard (risky IP + blocked logs)
🧭 /system — Webhook health + recent errors

👥 /users [page] — Users list with quota info
👤 /user &lt;id&gt; — User detail with role, quota, progress bars
📧 /usermail &lt;userId&gt; [page] — List a user's emails
📨 /mail [page|emailId] — Emails with pager or detail
📬 /recent — Last 10 emails across all users

📈 /stats [range|top|bounce] — Email &amp; user stats
🗂 /events [page] — Webhook/system event log
🧾 /event &lt;id&gt; — Event detail + preview
🛡️ /role — Role quota + authorization flags
🎟️ /invite [page] — Invite codes with usage history
🔎 /search [type] [query] — Search user/email/invite/role/ip
🌐 /whois &lt;ip&gt; — IP intelligence lookup

🔄 /resetquota &lt;userId&gt; — Reset user send quota to 0
🚫 /ban &lt;userId&gt; — Ban a user
✅ /unban &lt;userId&gt; — Unban a user
🆔 /chatid — Your chat_id / user_id

━━━━━━━━━━━━━━━━━━━━
📌 <b>Subcommands &amp; Examples</b>

👤 <b>User</b>
• <code>/user 1</code> — detail user #1
• <code>/usermail 5 2</code> — emails of user #5, page 2
• <code>/resetquota 5</code> — reset send quota user #5
• <code>/ban 5</code> / <code>/unban 5</code>

📈 <b>Stats</b>
• <code>/stats 7d</code> — last 7 days (default)
• <code>/stats 14d</code> — last 14 days
• <code>/stats top</code> — top senders/receivers
• <code>/stats bounce</code> — bounced/failed emails

🔐 <b>Security</b>
• <code>/security</code> — dashboard detail security
• <code>/security event &lt;id&gt;</code> — event detail
• <code>/security blacklist add spammer@evil.com</code>
• <code>/security blacklist add evil.com</code>
• <code>/security blacklist remove spammer@evil.com</code>
• <code>/security keyword add judi</code>
• <code>/security keyword add gacor</code>
• <code>/security keyword remove judi</code>

🔎 <b>Search</b>
• <code>/search user abyn@abyn.xyz</code>
• <code>/search user 5</code> — by user ID
• <code>/search email 121</code> — by email ID
• <code>/search invite CODE123</code>
• <code>/search role admin</code>
• <code>/search ip 1.2.3.4</code>`,
					replyMarkup: this.buildMainMenu()
				};
			case '/recent':
				return await this.formatRecentCommand(c);
			case '/resetquota':
				return await this.formatResetQuotaCommand(c, args?.[0]);
			case '/usermail':
				return await this.formatUserMailCommand(c, args?.[0], args?.[1] || 1);
			case '/mail':
				if (args?.[0] === 'page') return await this.formatMailCommand(c, Number(args?.[1] || 1));
				if (/^\d+$/.test(String(args?.[0] || '')) && Number(args[0]) > 0 && Number(args[0]) <= 50) return await this.formatMailCommand(c, Number(args[0]));
				if (args?.[0]) return await this.formatMailDetailCommand(c, args[0], args?.[1]);
				return await this.formatMailCommand(c, pageArg);
			case '/users':
				if (args?.[0] === 'detail') return await this.formatUserDetailCommand(c, args?.[1], args?.[2]);
				return await this.formatUsersCommand(c, pageArg);
			case '/user':
				return await this.formatUserDetailCommand(c, args?.[0], args?.[1]);
			case '/role':
				return { text: await this.formatRoleCommand(c), replyMarkup: this.buildMainMenu() };
			case '/invite':
				if (args?.[0] === 'detail') return await this.formatInviteDetailCommand(c, args?.[1], args?.[2]);
				if (args?.[0] && /^\d+$/.test(String(args[0])) && Number(args[0]) > 50) return await this.formatInviteDetailCommand(c, args[0], 1);
				return await this.formatInviteCommand(c, pageArg);
			case '/status':
				return { text: await this.formatStatusCommand(c), replyMarkup: this.buildMainMenu() };
			case '/chatid':
				return { text: `🆔 chat_id: <code>${chatId}</code>\n👤 user_id: <code>${userId || '-'}</code>`, replyMarkup: this.buildMainMenu() };
			case '/system':
				return { text: await this.formatSystemCommand(c), replyMarkup: this.buildMainMenu() };
			case '/security':
				if (args?.[0] === 'event') return await this.formatSecurityEventDetailCommand(c, args?.[1]);
				if (args?.[0] === 'blacklist') return await this.formatSecurityBlacklistCommand(c, args?.[1], args?.[2]);
				if (args?.[0] === 'keyword') return await this.formatSecurityKeywordCommand(c, args?.[1], args?.[2]);
				return await this.formatSecurityCommand(c);
			case '/whois':
				return await this.formatWhoisCommand(c, args?.[0]);
			case '/stats':
				return await this.formatStatsCommand(c, args?.[0] || '7d');
			case '/events':
				if (args?.[0] === 'page') return await this.formatEventsCommand(c, Number(args?.[1] || 1));
				if (args?.[0]) return await this.formatEventDetailCommand(c, args[0]);
				return await this.formatEventsCommand(c, pageArg);
			case '/event':
				if (args?.[0] === 'user') return await this.formatEventDetailCommand(c, args?.[1], { backText: '👤 User Detail', backCallbackData: `cmd:userid:${args?.[2] || 1}:${args?.[3] || 1}` });
				return await this.formatEventDetailCommand(c, args?.[0], { backPage: args?.[1] });
			case '/ban':
				return await this.formatBanUserCommand(c, args?.[0], 'ban');
			case '/unban':
				return await this.formatBanUserCommand(c, args?.[0], 'unban');
			case '/search':
			case '/searchs':
				if (!args?.[0]) return { text: this.formatSearchHelp('general'), replyMarkup: this.buildSearchMenu() };
				if (['user','email','invite','role','ip'].includes(args[0]) && !args[1]) {
					return { text: this.formatSearchHelp(args[0]), replyMarkup: this.buildSearchMenu() };
				}
				return await this.formatSearchCommand(c, args?.[0], args?.slice(1));
			default:
				return await this.resolveCommand(c, '/help', [], chatId, userId);
		}
	},

	// ─── WEBHOOK HANDLER ──────────────────────────────────────────────────────

	async handleBotWebhook(c, body) {
		const callback = body?.callback_query;
		if (callback?.data) {
			const chatId = callback?.message?.chat?.id;
			const userId = callback?.from?.id;
			if (!chatId) return;
			await this.answerCallbackQuery(c, callback.id);
			if (!await this.isAllowedChat(c, chatId, userId)) return;
			if (callback.data === 'cmd:noop') return;

			let command = '/help';
			let args = [];

			if (callback.data === 'cmd:menu') {
				command = '/status';
			} else if (callback.data === 'cmd:help') {
				command = '/help';
			} else {
				const pagingMatch = /^cmd:(mail|users|invite|events):(\d+)$/.exec(callback.data);
				if (pagingMatch) {
					command = `/${pagingMatch[1]}`;
					if (['mail', 'events'].includes(pagingMatch[1])) {
						args = ['page', pagingMatch[2]];
					} else {
						args = [pagingMatch[2]];
					}
				} else if (/^cmd:userid:(\d+):(\d+)$/.test(callback.data)) {
					const m = /^cmd:userid:(\d+):(\d+)$/.exec(callback.data);
					command = '/users'; args = ['detail', m[1], m[2]];
				} else if (/^cmd:userevent:(\d+):(\d+):(\d+)$/.test(callback.data)) {
					const m = /^cmd:userevent:(\d+):(\d+):(\d+)$/.exec(callback.data);
					command = '/event'; args = ['user', m[1], m[2], m[3]];
				} else if (/^cmd:inviteid:(\d+):(\d+)$/.test(callback.data)) {
					const m = /^cmd:inviteid:(\d+):(\d+)$/.exec(callback.data);
					command = '/invite'; args = ['detail', m[1], m[2]];
				} else if (/^cmd:searchhelp:(user|email|invite|role)$/.test(callback.data)) {
					const m = /^cmd:searchhelp:(user|email|invite|role)$/.exec(callback.data);
					command = '/search'; args = [m[1]];
				} else if (callback.data === 'cmd:search') {
					command = '/search';
				} else if (/^cmd:usermail:(\d+):(\d+)$/.test(callback.data)) {
					const m = /^cmd:usermail:(\d+):(\d+)$/.exec(callback.data);
					command = '/usermail'; args = [m[1], m[2]];
				} else if (/^cmd:usermail:(\d+)$/.test(callback.data)) {
					const m = /^cmd:usermail:(\d+)$/.exec(callback.data);
					command = '/usermail'; args = [m[1], '1'];
				} else if (/^cmd:banuser:(\d+)$/.test(callback.data)) {
					const m = /^cmd:banuser:(\d+)$/.exec(callback.data);
					const uid = Number(m[1]);
					const uRow = await c.env.db.prepare('SELECT status FROM user WHERE user_id = ?').bind(uid).first();
					const isBanned = uRow?.status === 1;
					command = isBanned ? '/unban' : '/ban'; args = [String(uid)];
				} else if (callback.data === 'cmd:blacklist') {
					command = '/security'; args = ['blacklist'];
				} else if (callback.data === 'cmd:keyword') {
					command = '/security'; args = ['keyword'];
				} else if (callback.data === 'cmd:stats:top') {
					command = '/stats'; args = ['top'];
				} else if (callback.data === 'cmd:stats:bounce') {
					command = '/stats'; args = ['bounce'];
				} else if (/^cmd:mailid:(\d+):(\d+)$/.test(callback.data)) {
					const m = /^cmd:mailid:(\d+):(\d+)$/.exec(callback.data);
					command = '/mail'; args = [m[1], m[2]];
				} else if (/^cmd:mailid:(\d+)$/.test(callback.data)) {
					const m = /^cmd:mailid:(\d+)$/.exec(callback.data);
					command = '/mail'; args = [m[1], '1'];
				} else if (/^cmd:securityevent:(\d+)$/.test(callback.data)) {
					const m = /^cmd:securityevent:(\d+)$/.exec(callback.data);
					command = '/security'; args = ['event', m[1]];
				} else if (/^cmd:event:(\d+):(\d+)$/.test(callback.data)) {
					const m = /^cmd:event:(\d+):(\d+)$/.exec(callback.data);
					command = '/event'; args = [m[1], m[2]];
				} else if (/^cmd:event:(\d+)$/.test(callback.data)) {
					const m = /^cmd:event:(\d+)$/.exec(callback.data);
					command = '/event'; args = [m[1], '1'];
				} else if (callback.data === 'cmd:stats:7d') {
					command = '/stats'; args = ['7d'];
				} else if (callback.data === 'cmd:whois:help') {
					command = '/whois'; args = ['help'];
				} else {
					const single = /^cmd:(status|role|chatid|system|security|recent)$/.exec(callback.data);
					if (single) command = `/${single[1]}`;
				}
			}

			const result = await this.resolveCommand(c, command, args, chatId, userId);
			const edited = await this.editTelegramReply(c, chatId, callback.message.message_id, result.text, result.replyMarkup);
			if (edited) await this.saveLastBotMessageId(c, chatId, callback.message.message_id);
			if (!edited) await this.sendOrEditSingleChatMessage(c, chatId, result.text, result.replyMarkup);
			return;
		}

		const message = body?.message || body?.edited_message || body?.channel_post;
		const text = message?.text?.trim();
		const chatId = message?.chat?.id;
		const userId = message?.from?.id;
		const userMessageId = message?.message_id;
		if (!text || !chatId) return;

		if (!await this.isAllowedChat(c, chatId, userId)) {
			const allowed = await this.parseAllowedChatIds(c);
			const msg = allowed.length === 0
				? '⛔ Unauthorized\nReason: CHAT_ID allowlist is empty.'
				: `⛔ Unauthorized\nAllowed: ${allowed.join(', ')}\nCurrent chat_id: ${chatId}${userId ? `\nCurrent user_id: ${userId}` : ''}`;
			await this.sendTelegramReply(c, chatId, msg);
			await this.logSystemEvent(c, 'telegram.command.unauthorized', EVENT_LEVEL.WARN, 'Unauthorized command attempt', { chatId, userId, text });
			return;
		}

		const argParts = text.split(/\s+/).filter(Boolean);
		const rawCommand = argParts.shift();
		const command = rawCommand.includes('@') ? rawCommand.split('@')[0] : rawCommand;
		console.log(`Telegram bot command: chat_id=${chatId} user_id=${userId || '-'} command=${command}`);
		await this.logSystemEvent(c, 'telegram.command.received', EVENT_LEVEL.INFO, command, { chatId, userId, args: argParts });

		const result = await this.resolveCommand(c, command, argParts, chatId, userId);
		let reply = result.text;
		if (reply.length > 3800) reply = `${reply.slice(0, 3800)}\n\n...truncated`;

		await this.sendOrEditSingleChatMessage(c, chatId, reply, result.replyMarkup);

		if (userMessageId && message?.from?.id) {
			await this.deleteTelegramMessage(c, chatId, userMessageId);
		}
	},
};

export default telegramService;
