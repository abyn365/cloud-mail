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

	async sendTelegramMessage(c, message, reply_markup = null) {
		const { tgBotToken, tgChatId } = await settingService.query(c);
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
			const cache = await c.env.db.prepare('SELECT data FROM ip_security_cache WHERE ip = ?').bind(ip).first();
			if (cache?.data) {
				return JSON.parse(cache.data);
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

	parseAllowedChatIds(c) {
		const raw = c.env.CHAT_ID || '';
		return String(raw)
			.split(',')
			.map(item => item.trim())
			.filter(Boolean);
	},

	isAllowedChat(c, chatId) {
		const allowed = this.parseAllowedChatIds(c);
		if (allowed.length === 0) {
			return false;
		}
		return allowed.includes(String(chatId));
	},

	async sendTelegramReply(c, chatId, message) {
		const { tgBotToken } = await settingService.query(c);
		if (!tgBotToken) return;
		const payload = {
			chat_id: String(chatId),
			parse_mode: 'HTML',
			text: message,
		};
		await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		});
	},

	async formatMailCommand(c) {
		const rows = await orm(c).select({
			emailId: email.emailId,
			sendEmail: email.sendEmail,
			toEmail: email.toEmail,
			subject: email.subject,
			type: email.type,
			isDel: email.isDel,
			createTime: email.createTime,
		}).from(email).orderBy(desc(email.emailId)).limit(20);

		if (rows.length === 0) return `📭 <b>/mail</b>
No email data.`;
		const body = rows.map(item => `🆔 <code>${item.emailId}</code> | ${item.type === 0 ? 'RECV' : 'SEND'} | del=${item.isDel}
From: <code>${item.sendEmail || '-'}</code>
To: <code>${item.toEmail || '-'}</code>
Subj: ${item.subject || '-'}
At: ${item.createTime}`).join('

');
		return `📨 <b>/mail</b> (last 20)

${body}`;
	},

	async formatUsersCommand(c) {
		const rows = await orm(c).select({
			userId: user.userId,
			email: user.email,
			status: user.status,
			isDel: user.isDel,
			type: user.type,
			sendCount: user.sendCount,
			createTime: user.createTime,
		}).from(user).orderBy(desc(user.userId)).limit(20);
		if (rows.length === 0) return `👤 <b>/users</b>
No user data.`;
		const roleRows = await orm(c).select().from(role);
		const map = new Map(roleRows.map(r => [r.roleId, r.name]));
		const body = rows.map(item => `🆔 <code>${item.userId}</code> ${item.email}
Role: ${map.get(item.type) || (item.type === 0 ? 'admin' : 'unknown')} | Status: ${item.status} | Deleted: ${item.isDel}
Send Count: ${item.sendCount || 0} | Created: ${item.createTime || '-'}`).join('

');
		return `👥 <b>/users</b> (first 20)

${body}`;
	},

	async formatRoleCommand(c) {
		const rows = await orm(c).select().from(role);
		if (rows.length === 0) return `🛡️ <b>/role</b>
No role data.`;
		const body = rows.map(item => `🆔 <code>${item.roleId}</code> ${item.name}
Send: ${item.sendType || '-'} / ${item.sendCount ?? 'Unlimited'}
Address limit: ${item.accountCount ?? 'Unlimited'}
Default: ${item.isDefault ? 'Yes' : 'No'}
Ban email: ${item.banEmail || '-'}
Avail domain: ${item.availDomain || '-'}`).join('

');
		return `🛡️ <b>/role</b>

${body}`;
	},

	async formatInviteCommand(c) {
		const rows = await orm(c).select({
			regKeyId: regKey.regKeyId,
			code: regKey.code,
			count: regKey.count,
			roleId: regKey.roleId,
			expireTime: regKey.expireTime,
			createTime: regKey.createTime,
		}).from(regKey).orderBy(desc(regKey.regKeyId)).limit(30);
		if (rows.length === 0) return `🎟️ <b>/invite</b>
No invite code data.`;
		const roleRows = await orm(c).select().from(role);
		const map = new Map(roleRows.map(r => [r.roleId, r.name]));
		const body = rows.map(item => `🆔 <code>${item.regKeyId}</code> <code>${item.code}</code>
Role: ${map.get(item.roleId) || item.roleId}
Remaining: ${item.count} | Expire: ${item.expireTime || '-'}
Created: ${item.createTime || '-'}`).join('

');
		return `🎟️ <b>/invite</b>

${body}`;
	},

	async formatStatusCommand(c) {
		const numberCount = await analysisDao.numberCount(c);
		const allowed = this.parseAllowedChatIds(c);
		const botEnabled = Boolean((await settingService.query(c)).tgBotToken);
		return `📊 <b>/status</b>

Users: ${numberCount.userCount}
Accounts: ${numberCount.accountCount}
Receive Emails: ${numberCount.receiveEmailCount}
Send Emails: ${numberCount.sendEmailCount}

🤖 Bot enabled: ${botEnabled ? 'Yes' : 'No'}
🔐 Allowed CHAT_ID: ${allowed.length > 0 ? allowed.join(', ') : '(empty)'}`;
	},

	async handleBotWebhook(c, body) {
		const message = body?.message;
		const text = message?.text?.trim();
		const chatId = message?.chat?.id;
		if (!text || !chatId) {
			return;
		}

		if (!this.isAllowedChat(c, chatId)) {
			await this.sendTelegramReply(c, chatId, '⛔ Unauthorized');
			return;
		}

		let reply = '';
		switch (text.split(' ')[0]) {
			case '/mail':
				reply = await this.formatMailCommand(c);
				break;
			case '/users':
				reply = await this.formatUsersCommand(c);
				break;
			case '/role':
				reply = await this.formatRoleCommand(c);
				break;
			case '/invite':
				reply = await this.formatInviteCommand(c);
				break;
			case '/status':
				reply = await this.formatStatusCommand(c);
				break;
			default:
				reply = `📌 Commands:
/mail
/users
/role
/invite
/status`;
		}

		await this.sendTelegramReply(c, chatId, reply);
	},

};

export default telegramService;
