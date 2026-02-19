import PostalMime from 'postal-mime';
import emailService from '../service/email-service';
import accountService from '../service/account-service';
import settingService from '../service/setting-service';
import attService from '../service/att-service';
import constant from '../const/constant';
import fileUtils from '../utils/file-utils';
import { emailConst, isDel, settingConst } from '../const/entity-const';
import emailUtils from '../utils/email-utils';
import roleService from '../service/role-service';
import userService from '../service/user-service';
import telegramService from '../service/telegram-service';

export async function email(message, env, ctx) {

	try {

		const {
			receive,
			tgChatId,
			tgBotStatus,
			forwardStatus,
			forwardEmail,
			ruleEmail,
			ruleType,
			r2Domain,
			noRecipient
		} = await settingService.query({ env });

		if (receive === settingConst.receive.CLOSE) {
			message.setReject('Service suspended');
			return;
		}


		const reader = message.raw.getReader();
		let content = '';

		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			content += new TextDecoder().decode(value);
		}

		const email = await PostalMime.parse(content);
		const senderEmail = (email?.from?.address || '').trim().toLowerCase();
		const senderDomain = senderEmail.includes('@') ? senderEmail.split('@')[1] : '';

		try {
			const blacklisted = await env.db.prepare(`
				SELECT email FROM ban_email
				WHERE lower(email) = ? OR lower(email) = ?
				LIMIT 1
			`).bind(senderEmail, senderDomain).first();

			if (blacklisted) {
				message.setReject('Sender is blacklisted');

				// Silently save blocked email to ban_email_log for admin preview
				// Records auto-deleted after 24h to save storage
				try {
					await env.db.prepare(`
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

					const textPreview = (email?.text || '').slice(0, 500);
					const htmlContent = (email?.html || '').slice(0, 65000);

					await env.db.batch([
						env.db.prepare(`
							INSERT INTO ban_email_log (sender_email, to_email, matched_rule, subject, text_preview, html_content, create_time)
							VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
						`).bind(
							senderEmail,
							message.to || '',
							blacklisted.email || '',
							email?.subject || '',
							textPreview,
							htmlContent
						),
						env.db.prepare(`
							DELETE FROM ban_email_log
							WHERE create_time <= datetime('now', '-24 hour')
						`)
					]);

					const lastRow = await env.db.prepare(`
						SELECT id FROM ban_email_log
						WHERE sender_email = ? AND to_email = ?
						ORDER BY id DESC LIMIT 1
					`).bind(senderEmail, message.to || '').first();

					const banLogId = lastRow?.id || null;

					await telegramService.logSystemEvent(
						{ env },
						'security.blacklist.blocked',
						'warn',
						`🚫 Blacklisted sender blocked\nFrom: ${senderEmail}\nTo: ${message.to}\nMatched rule: ${blacklisted.email}\nSubject: ${email?.subject || '-'}`,
						{ senderEmail, to: message.to, matchedRule: blacklisted.email, subject: email?.subject || '', banLogId }
					);
				} catch (e) {
					console.error('Failed to log blacklist block event:', e);
				}

				return;
			}
		} catch (e) {
			if (!String(e?.message || '').toLowerCase().includes('no such table')) {
				console.error('Blacklist check failed:', e.message);
			}
		}

		// Keyword blacklist check — subject + body (text)
		try {
			const { results: keywords } = await env.db.prepare(`
				SELECT id, keyword FROM ban_keyword ORDER BY id ASC
			`).all();

			if (keywords?.length) {
				const subject = (email?.subject || '').toLowerCase();
				const body = (email?.text || '').toLowerCase();
				const combined = subject + ' ' + body;

				const matchedKeyword = keywords.find(k =>
					combined.includes(String(k.keyword || '').toLowerCase())
				);

				if (matchedKeyword) {
					message.setReject('Message blocked by keyword filter');

					try {
						await env.db.prepare(`
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

						const textPreview = (email?.text || '').slice(0, 500);
						const htmlContent = (email?.html || '').slice(0, 65000);

						await env.db.batch([
							env.db.prepare(`
								INSERT INTO ban_email_log (sender_email, to_email, matched_rule, subject, text_preview, html_content, create_time)
								VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
							`).bind(
								senderEmail,
								message.to || '',
								`keyword:${matchedKeyword.keyword}`,
								email?.subject || '',
								textPreview,
								htmlContent
							),
							env.db.prepare(`
								DELETE FROM ban_email_log
								WHERE create_time <= datetime('now', '-24 hour')
							`)
						]);

						const lastRow = await env.db.prepare(`
							SELECT id FROM ban_email_log
							WHERE sender_email = ? AND to_email = ?
							ORDER BY id DESC LIMIT 1
						`).bind(senderEmail, message.to || '').first();

						const banLogId = lastRow?.id || null;

						await telegramService.logSystemEvent(
							{ env },
							'security.blacklist.blocked',
							'warn',
							`🚫 Keyword blocked email\nFrom: ${senderEmail}\nTo: ${message.to}\nKeyword: "${matchedKeyword.keyword}"\nSubject: ${email?.subject || '-'}`,
							{ senderEmail, to: message.to, matchedRule: `keyword:${matchedKeyword.keyword}`, subject: email?.subject || '', banLogId }
						);
					} catch (e) {
						console.error('Failed to log keyword block event:', e);
					}

					return;
				}
			}
		} catch (e) {
			if (!String(e?.message || '').toLowerCase().includes('no such table')) {
				console.error('Keyword blacklist check failed:', e.message);
			}
		}

		const account = await accountService.selectByEmailIncludeDel({ env: env }, message.to);

		if (!account && noRecipient === settingConst.noRecipient.CLOSE) {
			message.setReject('Recipient not found');
			return;
		}

		let userRow = {}

		if (account) {
			 userRow = await userService.selectByIdIncludeDel({ env: env }, account.userId);
		}

		if (account && userRow.email !== env.admin) {

			let { banEmail, availDomain } = await roleService.selectByUserId({ env: env }, account.userId);

			if (!roleService.hasAvailDomainPerm(availDomain, message.to)) {
				message.setReject('The recipient is not authorized to use this domain.');
				return;
			}

			if(roleService.isBanEmail(banEmail, email.from.address)) {
				message.setReject('The recipient is disabled from receiving emails.');
				return;
			}

		}


		if (!email.to) {
			email.to = [{ address: message.to, name: emailUtils.getName(message.to)}]
		}

		const toName = email.to.find(item => item.address === message.to)?.name || '';

		const params = {
			toEmail: message.to,
			toName: toName,
			sendEmail: email.from.address,
			name: email.from.name || emailUtils.getName(email.from.address),
			subject: email.subject,
			content: email.html,
			text: email.text,
			cc: email.cc ? JSON.stringify(email.cc) : '[]',
			bcc: email.bcc ? JSON.stringify(email.bcc) : '[]',
			recipient: JSON.stringify(email.to),
			inReplyTo: email.inReplyTo,
			relation: email.references,
			messageId: email.messageId,
			userId: account ? account.userId : 0,
			accountId: account ? account.accountId : 0,
			isDel: isDel.DELETE,
			status: emailConst.status.SAVING
		};

		const attachments = [];
		const cidAttachments = [];

		for (let item of email.attachments) {
			let attachment = { ...item };
			attachment.key = constant.ATTACHMENT_PREFIX + await fileUtils.getBuffHash(attachment.content) + fileUtils.getExtFileName(item.filename);
			attachment.size = item.content.length ?? item.content.byteLength;
			attachments.push(attachment);
			if (attachment.contentId) {
				cidAttachments.push(attachment);
			}
		}

		let emailRow = await emailService.receive({ env }, params, cidAttachments, r2Domain);

		attachments.forEach(attachment => {
			attachment.emailId = emailRow.emailId;
			attachment.userId = emailRow.userId;
			attachment.accountId = emailRow.accountId;
		});

		try {
			if (attachments.length > 0) {
				await attService.addAtt({ env }, attachments);
			}
		} catch (e) {
			console.error(e);
		}

		emailRow = await emailService.completeReceive({ env }, account ? emailConst.status.RECEIVE : emailConst.status.NOONE, emailRow.emailId);


		if (ruleType === settingConst.ruleType.RULE) {

			const emails = ruleEmail.split(',');

			if (!emails.includes(message.to)) {
				return;
			}

		}

		//转发到TG
		if (tgBotStatus === settingConst.tgBotStatus.OPEN && tgChatId) {
			await telegramService.sendEmailToBot({ env }, emailRow)
		}

		//转发到其他邮箱
		if (forwardStatus === settingConst.forwardStatus.OPEN && forwardEmail) {

			const emails = forwardEmail.split(',');

			await Promise.all(emails.map(async email => {

				try {
					await message.forward(email);
				} catch (e) {
					console.error(`转发邮箱 ${email} 失败：`, e);
				}

			}));

		}

	} catch (e) {
		console.error('邮件接收异常: ', e);
		throw e
	}
}
