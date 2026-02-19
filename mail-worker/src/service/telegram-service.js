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

	async sendTelegramMessage(c, message, reply_markup = null) {
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
					console.error(`Failed to send Telegram notification status: ${res.status} response: ${await res.text()}`);
				}
			} catch (e) {
				console.error('Failed to send Telegram notification:', e.message);
			}
		}));
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
		}

		let detail = { ip };
		try {
			const res = await fetch(`https://vpnapi.io/api/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`);
			if (!res.ok) {
				console.error(`Failed to query vpnapi.io status: ${res.status} response: ${await res.text()}`);
				return detail;
			}
			detail = await res.json();
		} catch (e) {
			console.error('Failed to query vpnapi.io:', e.message);
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
		}

		return detail;
	},

	async sendEmailToBot(c, emailData) {
		const { customDomain, tgMsgTo, tgMsgFrom, tgMsgText } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: emailData.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404';
		const message = emailMsgTemplate(emailData, tgMsgTo, tgMsgFrom, tgMsgText, null);
		await this.sendTelegramMessage(c, message, { inline_keyboard: [[{ text: 'Check', web_app: { url: webAppUrl } }]] });
	},

	async sendIpSecurityNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const ipDetail = await this.queryIpSecurity(c, userInfo.activeIp);
		const message = ipSecurityMsgTemplate(userInfo, ipDetail);
		await this.sendTelegramMessage(c, message);
	},

	async sendRegKeyManageNotification(c, action, regKeyInfo, actorInfo, extraInfo = {}) {
		if (actorInfo?.activeIp) {
			actorInfo.timezone = await timezoneUtils.getTimezone(c, actorInfo.activeIp);
			await this.setIpDetailContext(c, actorInfo);
		}
		regKeyInfo.roleInfo = await this.attachRolePermInfo(c, regKeyInfo.roleInfo);
		if (actorInfo?.role) actorInfo.role = await this.attachRolePermInfo(c, actorInfo.role);
		const message = regKeyManageMsgTemplate(action, regKeyInfo, actorInfo, extraInfo);
		await this.sendTelegramMessage(c, message);
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

		await this.sendTelegramMessage(c, message);
	},

	async sendRegisterNotification(c, userInfo, accountCount, roleInfo = null) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.createIp);
		await this.setIpDetailContext(c, userInfo, 'createIp');
		roleInfo = await this.attachRolePermInfo(c, roleInfo);
		const message = registerMsgTemplate(userInfo, accountCount, roleInfo);
		await this.sendTelegramMessage(c, message);
	},

	async sendAdminCreateUserNotification(c, newUserInfo, roleInfo, adminUser) {
		adminUser.timezone = await timezoneUtils.getTimezone(c, adminUser.activeIp);
		await this.setIpDetailContext(c, newUserInfo, 'createIp');
		await this.setIpDetailContext(c, adminUser);
		roleInfo = await this.attachRolePermInfo(c, roleInfo);
		adminUser.role = await this.attachRolePermInfo(c, adminUser.role);
		const message = adminCreateUserMsgTemplate(newUserInfo, roleInfo, adminUser);
		await this.sendTelegramMessage(c, message);
	},

	async sendEmailSentNotification(c, emailInfo, userInfo) {
		const { customDomain } = await settingService.query(c);
		const jwtToken = await jwtUtils.generateToken(c, { emailId: emailInfo.emailId });
		const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404';
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		const message = sendEmailMsgTemplate(emailInfo, userInfo);
		await this.sendTelegramMessage(c, message, { inline_keyboard: [[{ text: 'Check', web_app: { url: webAppUrl } }]] });
	},

	async sendEmailSoftDeleteNotification(c, emailIds, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, softDeleteEmailMsgTemplate(emailIds, userInfo));
	},

	async sendEmailHardDeleteNotification(c, emailIds, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, hardDeleteEmailMsgTemplate(emailIds, userInfo));
	},

	async sendAddAddressNotification(c, addressInfo, userInfo, totalAddresses) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, addAddressMsgTemplate(addressInfo, userInfo, totalAddresses));
	},

	async sendDeleteAddressNotification(c, addressEmail, userInfo, remainingAddresses) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, deleteAddressMsgTemplate(addressEmail, userInfo, remainingAddresses));
	},

	async sendRoleChangeNotification(c, userInfo, oldRole, newRole, changedBy) {
		changedBy.timezone = await timezoneUtils.getTimezone(c, changedBy.activeIp);
		await this.setIpDetailContext(c, userInfo);
		await this.setIpDetailContext(c, changedBy);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		changedBy.role = await this.attachRolePermInfo(c, changedBy.role);
		oldRole = await this.attachRolePermInfo(c, oldRole);
		newRole = await this.attachRolePermInfo(c, newRole);
		await this.sendTelegramMessage(c, roleChangeMsgTemplate(userInfo, oldRole, newRole, changedBy));
	},

	async sendUserStatusChangeNotification(c, userInfo, oldStatus, newStatus, changedBy) {
		changedBy.timezone = await timezoneUtils.getTimezone(c, changedBy.activeIp);
		await this.setIpDetailContext(c, userInfo);
		await this.setIpDetailContext(c, changedBy);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		changedBy.role = await this.attachRolePermInfo(c, changedBy.role);
		await this.sendTelegramMessage(c, userStatusChangeMsgTemplate(userInfo, oldStatus, newStatus, changedBy));
	},

	async sendPasswordResetNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, passwordResetMsgTemplate(userInfo));
	},

	async sendUserSelfDeleteNotification(c, userInfo) {
		userInfo.timezone = await timezoneUtils.getTimezone(c, userInfo.activeIp);
		await this.setIpDetailContext(c, userInfo);
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, userSelfDeleteMsgTemplate(userInfo));
	},

	async sendAdminDeleteUserNotification(c, deletedUser, adminUser) {
		adminUser.timezone = await timezoneUtils.getTimezone(c, adminUser.activeIp);
		await this.setIpDetailContext(c, deletedUser);
		await this.setIpDetailContext(c, adminUser);
		deletedUser.role = await this.attachRolePermInfo(c, deletedUser.role);
		adminUser.role = await this.attachRolePermInfo(c, adminUser.role);
		await this.sendTelegramMessage(c, adminDeleteUserMsgTemplate(deletedUser, adminUser));
	},


	async sendRoleManageNotification(c, action, roleInfo, actorInfo, extra = '') {
		actorInfo.timezone = await timezoneUtils.getTimezone(c, actorInfo.activeIp);
		await this.setIpDetailContext(c, actorInfo);
		actorInfo.role = await this.attachRolePermInfo(c, actorInfo.role);

		if (roleInfo?.roleId !== undefined && roleInfo?.roleId !== null) {
			const roleRow = await orm(c).select().from(role).where(eq(role.roleId, roleInfo.roleId)).get();
			roleInfo = await this.attachRolePermInfo(c, roleRow || roleInfo);
		}

		await this.sendTelegramMessage(c, roleManageMsgTemplate(action, roleInfo, actorInfo, extra));
	},

	async sendFailedLoginNotification(c, email, ip, attempts, device, os, browser) {
		const userTimezone = await timezoneUtils.getTimezone(c, ip);
		const ipDetail = await this.queryIpSecurity(c, ip);
		await this.sendTelegramMessage(c, failedLoginMsgTemplate(email, ip, attempts, device, os, browser, userTimezone, ipDetail));
	},

	async sendQuotaWarningNotification(c, userInfo, quotaType) {
		userInfo.role = await this.attachRolePermInfo(c, userInfo.role);
		await this.sendTelegramMessage(c, quotaWarningMsgTemplate(userInfo, quotaType));
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
				[{ text: '🎟️ Invite', callback_data: 'cmd:invite:1' }, { text: '🆔 Chat ID', callback_data: 'cmd:chatid' }],
				[{ text: '🧭 System', callback_data: 'cmd:system' }, { text: '❓ Help', callback_data: 'cmd:help' }]
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
		return { text: `📨 <b>/mail</b> (page ${currentPage})

${body}`, replyMarkup: this.buildPager('mail', currentPage, hasNext) };
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
		const body = roleRows.map(item => `🆔 <code>${item.roleId}</code> ${item.name}
Send: ${item.sendType || '-'} / ${item.sendCount ?? '-'}
Address limit: ${item.accountCount ?? '-'}
Permission: send=${item.canSendEmail ? 'Yes' : 'No'} | add-address=${item.canAddAddress ? 'Yes' : 'No'}
Default: ${item.isDefault ? 'Yes' : 'No'}
Ban email: ${item.banEmail || '-'}
Avail domain: ${item.availDomain || '-'}`).join('\n\n');
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
		const roleRows = await orm(c).select().from(role);
		const map = new Map(roleRows.map(r => [r.roleId, r.name]));
		const body = visibleRows.map(item => `🆔 <code>${item.regKeyId}</code> <code>${item.code}</code>
Role: ${map.get(item.roleId) || item.roleId}
Remaining: ${item.count} | Expire: ${item.expireTime || '-'}
Created: ${item.createTime || '-'}`).join('\n\n');
		return { text: `🎟️ <b>/invite</b> (page ${currentPage})

${body}`, replyMarkup: this.buildPager('invite', currentPage, hasNext) };
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
		const [cacheCount, staleCount, webhookInfo, recentIpLogs] = await Promise.all([
			c.env.db.prepare('SELECT COUNT(*) as total FROM ip_security_cache').first(),
			c.env.db.prepare("SELECT COUNT(*) as total FROM ip_security_cache WHERE update_time <= datetime('now', '-2 day')").first(),
			this.getWebhookInfo(c),
			c.env.db.prepare('SELECT ip, update_time FROM ip_security_cache ORDER BY update_time DESC LIMIT 3').all()
		]);
		const webhookUrl = webhookInfo?.result?.url || '-';
		const pending = webhookInfo?.result?.pending_update_count ?? '-';
		const lastError = webhookInfo?.result?.last_error_message || '-';
		const logs = (recentIpLogs?.results || []).map((row, index) =>
			`${index + 1}. [${row.update_time || '-'}] IP intel refreshed: <code>${row.ip || '-'}</code>`
		).join('\n');
		return `🧭 <b>/system</b>

IP Cache Rows: ${cacheCount?.total || 0}
Stale (≥2 days): ${staleCount?.total || 0}

Webhook URL: <code>${webhookUrl}</code>
Pending Updates: ${pending} (queued updates waiting delivery)
Last Error: ${lastError}

📜 Recent System Logs (3):
${logs || 'No logs yet.'}`;
	},

	async resolveCommand(c, command, pageArg, chatId, userId) {
		switch (command) {
			case '/start':
			case '/help':
				return {
					text: `🤖 <b>Cloud Mail Bot Command Center</b>

Use buttons below or type commands manually:

📊 <b>/status</b> — system counters, bot enable state, allowed chat IDs
👥 <b>/users [page]</b> — users + active IP + VPNAPI risk summary
📨 <b>/mail [page]</b> — latest received/sent mail list
🛡️ <b>/role</b> — role quotas + send/add-address permission flags
🎟️ <b>/invite [page]</b> — invitation code list
🆔 <b>/chatid</b> — show your current chat_id/user_id
🧭 <b>/system</b> — cache + webhook diagnostics

<b>Examples:</b>
• <code>/users 2</code>
• <code>/mail 3</code>
• <code>/invite 1</code>
• <code>/system</code>

Tap pager buttons to navigate page-by-page.`,
					replyMarkup: this.buildMainMenu()
				};
			case '/mail':
				return await this.formatMailCommand(c, pageArg);
			case '/users':
				return await this.formatUsersCommand(c, pageArg);
			case '/role':
				return { text: await this.formatRoleCommand(c), replyMarkup: this.buildMainMenu() };
			case '/invite':
				return await this.formatInviteCommand(c, pageArg);
			case '/status':
				return { text: await this.formatStatusCommand(c), replyMarkup: this.buildMainMenu() };
			case '/chatid':
				return { text: `🆔 chat_id: <code>${chatId}</code>\n👤 user_id: <code>${userId || '-'}</code>`, replyMarkup: this.buildMainMenu() };
			case '/system':
				return { text: await this.formatSystemCommand(c), replyMarkup: this.buildMainMenu() };
			default:
				return await this.resolveCommand(c, '/help', pageArg, chatId, userId);
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
			let command = '/help';
			let pageArg = 1;
			if (callback.data === 'cmd:menu') {
				const result = await this.resolveCommand(c, '/help', 1, chatId, userId);
				const edited = await this.editTelegramReply(c, chatId, callback.message.message_id, result.text, result.replyMarkup);
				if (!edited) await this.sendTelegramReply(c, chatId, result.text, result.replyMarkup);
				return;
			}
			if (callback.data === 'cmd:help') {
				const result = await this.resolveCommand(c, '/help', 1, chatId, userId);
				const edited = await this.editTelegramReply(c, chatId, callback.message.message_id, result.text, result.replyMarkup);
				if (!edited) await this.sendTelegramReply(c, chatId, result.text, result.replyMarkup);
				return;
			}
			const match = /^cmd:(mail|users|invite):(\d+)$/.exec(callback.data);
			if (match) {
				command = `/${match[1]}`;
				pageArg = Number(match[2] || 1);
			} else {
				const single = /^cmd:(status|role|chatid|system)$/.exec(callback.data);
				if (single) command = `/${single[1]}`;
			}
			const result = await this.resolveCommand(c, command, pageArg, chatId, userId);
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
			return;
		}

		const args = text.split(/\s+/).filter(Boolean);
		const rawCommand = args[0];
		const pageArg = Number(args[1] || 1);
		const command = rawCommand.includes('@') ? rawCommand.split('@')[0] : rawCommand;
		console.log(`Telegram bot command received chat_id=${chatId} user_id=${userId || '-'} command=${command}`);

		const result = await this.resolveCommand(c, command, pageArg, chatId, userId);
		let reply = result.text;
		if (reply.length > 3800) {
			reply = `${reply.slice(0, 3800)}\n\n...truncated`;
		}
		await this.sendTelegramReply(c, chatId, reply, result.replyMarkup);
	},

};

export default telegramService;
