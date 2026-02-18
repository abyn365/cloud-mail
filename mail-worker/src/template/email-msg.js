import emailUtils from '../utils/email-utils';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';

dayjs.extend(utc);
dayjs.extend(timezone);

// Helper function untuk format waktu dengan dual timezone
function formatDualTime(timestamp, userTimezone = null) {
	const utcTime = dayjs(timestamp).utc().format('YYYY-MM-DD HH:mm:ss');
	
	if (userTimezone) {
		try {
			const localTime = dayjs(timestamp).tz(userTimezone).format('YYYY-MM-DD HH:mm:ss');
			const offset = dayjs(timestamp).tz(userTimezone).format('Z');
			return `⏰ Server (UTC): ${utcTime}\n🌍 Local (${userTimezone} UTC${offset}): ${localTime}`;
		} catch (e) {
			console.error('Invalid timezone:', userTimezone, e);
		}
	}
	
	return `⏰ Time (UTC): ${utcTime}`;
}

// Helper untuk format role info
function formatRoleInfo(roleInfo) {
	if (!roleInfo) return '';
	
	let roleText = `\n👤 Role: <b>${roleInfo.name || 'Unknown'}</b>`;
	
	// Tambahkan info send limit jika ada
	if (roleInfo.canSendEmail === false) {
		roleText += `\n📤 Send Email: Unauthorized`;
	} else if (roleInfo.sendCount !== undefined && roleInfo.sendCount !== null) {
		if (roleInfo.sendType === 'day') {
			roleText += roleInfo.sendCount > 0
				? `\n📊 Send Limit: ${roleInfo.sendCount} emails/day`
				: `\n📊 Send Limit: Unlimited`;
		} else if (roleInfo.sendType === 'count') {
			roleText += roleInfo.sendCount > 0
				? `\n📊 Send Limit: ${roleInfo.sendCount} emails total`
				: `\n📊 Send Limit: Unlimited`;
		} else if (roleInfo.sendType === 'ban') {
			roleText += `\n🚫 Send Status: Banned`;
		} else if (roleInfo.sendType === 'internal') {
			roleText += `\n📨 Send Status: Internal only`;
		}
	}
	
	// Tambahkan info account limit jika ada
	if (roleInfo.canAddAddress === false) {
		roleText += `\n📬 Address: Unauthorized`;
	} else if (roleInfo.accountCount !== undefined && roleInfo.accountCount !== null) {
		roleText += roleInfo.accountCount > 0
			? `\n📬 Address Limit: ${roleInfo.accountCount}`
			: `\n📬 Address Limit: Unlimited`;
	}
	
	return roleText;
}


function formatIpDetail(ipDetail) {
	if (!ipDetail) return '';
	const security = ipDetail.security || {};
	const location = ipDetail.location || {};
	const network = ipDetail.network || {};
	return `
🛡️ VPN/Proxy/Tor/Relay: ${security.vpn ? 'Y' : 'N'}/${security.proxy ? 'Y' : 'N'}/${security.tor ? 'Y' : 'N'}/${security.relay ? 'Y' : 'N'}
🏙️ Location: ${(location.city || '-')}${location.region ? `, ${location.region}` : ''}, ${location.country || '-'}
🏢 ASN Org: ${network.autonomous_system_organization || '-'}`;
}

// Template untuk notifikasi penerimaan email
export default function emailMsgTemplate(email, tgMsgTo, tgMsgFrom, tgMsgText, senderTimezone = null) {

	let template = `📨 <b>Email Received</b>

📧 To: <code>${email.toEmail}</code>`

	if (tgMsgFrom === 'only-name') {
		template += `
📤 From: ${email.name}`
	}

	if (tgMsgFrom === 'show') {
		template += `
📤 From: ${email.name} &lt;${email.sendEmail}&gt;`
	}

	template += `
📝 Subject: <b>${email.subject}</b>`

	const text = (emailUtils.formatText(email.text) || emailUtils.htmlToText(email.content))
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.substring(0, 200);

	if(tgMsgText === 'show' && text) {
		template += `

💬 Preview: ${text}${(email.text?.length > 200 || email.content?.length > 200) ? '...' : ''}`
	}

	// Tambahkan info attachments jika ada
	if (email.attachmentCount > 0) {
		template += `
📎 Attachments: ${email.attachmentCount} file(s)`;
	}

	template += `

${formatDualTime(email.createTime, senderTimezone)}`

	return template;

}

// Template untuk notifikasi login
export function loginMsgTemplate(userInfo) {
	return `🔐 <b>User Login</b>

📧 Email: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
📱 Device: ${userInfo.device || 'Unknown'}
💻 OS: ${userInfo.os || 'Unknown'}
🌐 Browser: ${userInfo.browser || 'Unknown'}
${userInfo.loginCount ? `🔢 Total Logins: ${userInfo.loginCount}\n` : ''}${formatDualTime(userInfo.activeTime, userInfo.timezone)}`;
}

// Template untuk notifikasi registrasi
export function registerMsgTemplate(userInfo, accountCount, roleInfo = null) {
	return `✅ <b>New User Registration</b>

📧 Email: <code>${userInfo.email}</code>${formatRoleInfo(roleInfo)}
📬 Addresses: ${accountCount}
📍 Registration IP: <code>${userInfo.createIp}</code>${formatIpDetail(userInfo.createIpDetail || userInfo.ipDetail)}
📱 Device: ${userInfo.device || 'Unknown'}
💻 OS: ${userInfo.os || 'Unknown'}
🌐 Browser: ${userInfo.browser || 'Unknown'}
${formatDualTime(userInfo.createTime, userInfo.timezone)}`;
}

// Template untuk notifikasi pengiriman email
export function sendEmailMsgTemplate(emailInfo, userInfo) {
	const recipients = JSON.parse(emailInfo.recipient || '[]');
	const recipientList = recipients.map(r => r.address).join(', ');
	
	const text = (emailUtils.formatText(emailInfo.text) || emailUtils.htmlToText(emailInfo.content))
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.substring(0, 200);
	
	let template = `📤 <b>Email Sent</b>

📧 From: <code>${emailInfo.sendEmail}</code>${formatRoleInfo(userInfo.role)}
📨 To: <code>${recipientList}</code>
📝 Subject: <b>${emailInfo.subject}</b>`;

	if (text) {
		template += `
💬 Preview: ${text}${(emailInfo.text?.length > 200 || emailInfo.content?.length > 200) ? '...' : ''}`;
	}

	// Tambahkan info attachments jika ada
	if (emailInfo.attachmentCount > 0) {
		template += `
📎 Attachments: ${emailInfo.attachmentCount} file(s)`;
	}

	template += `

📍 Sender IP: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}`;

	// Tambahkan info send quota jika ada
	if (userInfo.sendCount !== undefined && userInfo.role?.sendCount) {
		const remaining = userInfo.role.sendCount - userInfo.sendCount;
		template += `
📊 Quota: ${userInfo.sendCount}/${userInfo.role.sendCount} (${remaining} remaining)`;
	}

	template += `
${formatDualTime(emailInfo.createTime, userInfo.timezone)}`;

	return template;
}

// Template untuk notifikasi soft delete email (user inbox)
export function softDeleteEmailMsgTemplate(emailIds, userInfo) {
	const idArray = emailIds.split(',');
	const count = idArray.length;

	return `🗑️ <b>Email Soft Deleted</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
🧩 Delete Type: Soft delete (set <code>is_del=1</code>)
🔢 Email Count: ${count}
📋 Email IDs: <code>${emailIds}</code>
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}

// Template untuk notifikasi hard delete email (all mail / privileged user)
export function hardDeleteEmailMsgTemplate(emailIds, userInfo) {
	const idArray = emailIds.split(',');
	const count = idArray.length;

	return `💥 <b>Email Permanently Deleted</b>

📧 Actor: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
🧩 Delete Type: Hard delete (removed from DB)
🔢 Email Count: ${count}
📋 Email IDs: <code>${emailIds}</code>
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}

// Template untuk notifikasi penambahan address
export function addAddressMsgTemplate(addressInfo, userInfo, totalAddresses) {
	return `➕ <b>Address Added</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📬 New Address: <code>${addressInfo.email}</code>
📝 Name: ${addressInfo.name}
🔢 Total Addresses: ${totalAddresses}${userInfo.role?.accountCount ? `/${userInfo.role.accountCount}` : ''}
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}

// Template untuk notifikasi penghapusan address
export function deleteAddressMsgTemplate(addressEmail, userInfo, remainingAddresses) {
	return `❌ <b>Address Deleted</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📬 Deleted Address: <code>${addressEmail}</code>
🔢 Remaining Addresses: ${remainingAddresses}${userInfo.role?.accountCount ? `/${userInfo.role.accountCount}` : ''}
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}

// Template untuk notifikasi perubahan role
export function roleChangeMsgTemplate(userInfo, oldRole, newRole, changedBy) {
	return `🔄 <b>Role Changed</b>

📧 User: <code>${userInfo.email}</code>
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}

<b>Role Update:</b>
❌ Old Role: <b>${oldRole.name}</b>
${oldRole.sendType === 'day' || oldRole.sendType === 'count'
		? `   ├ Send Limit: ${oldRole.sendCount > 0 ? `${oldRole.sendCount}${oldRole.sendType === 'day' ? '/day' : ' total'}` : 'Unlimited'}\n`
		: ''}${oldRole.accountCount !== undefined && oldRole.accountCount !== null ? `   └ Address Limit: ${oldRole.accountCount > 0 ? oldRole.accountCount : 'Unlimited'}\n` : ''}
✅ New Role: <b>${newRole.name}</b>
${newRole.sendType === 'day' || newRole.sendType === 'count'
		? `   ├ Send Limit: ${newRole.sendCount > 0 ? `${newRole.sendCount}${newRole.sendType === 'day' ? '/day' : ' total'}` : 'Unlimited'}\n`
		: ''}${newRole.accountCount !== undefined && newRole.accountCount !== null ? `   └ Address Limit: ${newRole.accountCount > 0 ? newRole.accountCount : 'Unlimited'}\n` : ''}
👨‍💼 Changed By: <code>${changedBy.email}</code>${formatRoleInfo(changedBy.role)}
💻 Device: ${changedBy.device || 'Unknown'} / ${changedBy.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), changedBy.timezone)}`;
}

// Template untuk notifikasi perubahan status user (ban/unban)
export function userStatusChangeMsgTemplate(userInfo, oldStatus, newStatus, changedBy) {
	const statusText = {
		0: '✅ Active',
		1: '🚫 Banned'
	};
	
	return `⚠️ <b>User Status Changed</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📍 User IP: <code>${userInfo.activeIp || 'Unknown'}</code>${formatIpDetail(userInfo.ipDetail)}

<b>Status Update:</b>
Old: ${statusText[oldStatus] || 'Unknown'}
New: ${statusText[newStatus] || 'Unknown'}

👨‍💼 Changed By: <code>${changedBy.email}</code>${formatRoleInfo(changedBy.role)}
📍 Admin IP: <code>${changedBy.activeIp}</code>${formatIpDetail(changedBy.ipDetail)}
💻 Device: ${changedBy.device || 'Unknown'} / ${changedBy.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), changedBy.timezone)}`;
}

// Template untuk notifikasi password reset
export function passwordResetMsgTemplate(userInfo) {
	return `🔐 <b>Password Reset</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}
🌐 Browser: ${userInfo.browser || 'Unknown'}
${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}

// Template untuk notifikasi user deletion (self-delete)
export function userSelfDeleteMsgTemplate(userInfo) {
	return `⚠️ <b>User Self-Deleted Account</b>

📧 Email: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📬 Addresses: ${userInfo.addressCount || 0}
📨 Total Emails: ${userInfo.emailCount || 0}
📍 IP Address: <code>${userInfo.activeIp}</code>${formatIpDetail(userInfo.ipDetail)}
💻 Device: ${userInfo.device || 'Unknown'} / ${userInfo.os || 'Unknown'}
📅 Account Age: ${userInfo.accountAge || 'Unknown'}
${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}

// Template untuk notifikasi admin deletion
export function adminDeleteUserMsgTemplate(deletedUser, adminUser) {
	return `🗑️ <b>User Deleted by Admin</b>

<b>Deleted User:</b>
📧 Email: <code>${deletedUser.email}</code>${formatRoleInfo(deletedUser.role)}
📬 Addresses: ${deletedUser.addressCount || 0}
📨 Total Emails: ${deletedUser.emailCount || 0}

<b>Deleted By:</b>
👨‍💼 Admin: <code>${adminUser.email}</code>${formatRoleInfo(adminUser.role)}
📍 IP Address: <code>${adminUser.activeIp}</code>${formatIpDetail(adminUser.ipDetail)}
💻 Device: ${adminUser.device || 'Unknown'} / ${adminUser.os || 'Unknown'}
${formatDualTime(new Date().toISOString(), adminUser.timezone)}`;
}

// Template untuk notifikasi failed login attempts
export function failedLoginMsgTemplate(email, ip, attempts, device, os, browser, timezone, ipDetail = null) {
	return `⚠️ <b>Failed Login Attempt${attempts > 1 ? 's' : ''}</b>

📧 Email: <code>${email}</code>
🔢 Attempts: ${attempts}
📍 IP Address: <code>${ip}</code>${formatIpDetail(ipDetail)}
💻 Device: ${device || 'Unknown'} / ${os || 'Unknown'}
🌐 Browser: ${browser || 'Unknown'}
${formatDualTime(new Date().toISOString(), timezone)}

${attempts >= 3 ? '⚠️ <b>Warning:</b> Multiple failed attempts detected!' : ''}`;
}

// Template untuk notifikasi quota warning
export function quotaWarningMsgTemplate(userInfo, quotaType) {
	let warningText = '';
	
	if (quotaType === 'send') {
		const remaining = userInfo.role.sendCount - userInfo.sendCount;
		const percentage = (remaining / userInfo.role.sendCount * 100).toFixed(0);
		warningText = `📤 Send Quota: ${userInfo.sendCount}/${userInfo.role.sendCount} (${remaining} remaining - ${percentage}%)`;
	} else if (quotaType === 'address') {
		const remaining = userInfo.role.accountCount - userInfo.addressCount;
		const percentage = (remaining / userInfo.role.accountCount * 100).toFixed(0);
		warningText = `📬 Address Quota: ${userInfo.addressCount}/${userInfo.role.accountCount} (${remaining} remaining - ${percentage}%)`;
	}
	
	return `⚠️ <b>Quota Warning</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
${warningText}

⚠️ User approaching quota limit!`;
}

// Template untuk notifikasi manajemen invite code
export function regKeyManageMsgTemplate(action, regKeyInfo, actorInfo, extraInfo = {}) {
	const actionMap = {
		create: '🆕 Invite Code Created',
		use: '🎟️ Invite Code Used',
		delete: '🗑️ Invite Code Deleted',
		clear: '🧹 Invite Code Auto Cleared'
	};

	const title = actionMap[action] || '🎟️ Invite Code Updated';
	const beforeCount = extraInfo.beforeCount ?? '-';
	const afterCount = extraInfo.afterCount ?? regKeyInfo?.count ?? '-';

	return `${title ? `<b>${title}</b>` : ''}

🔑 Code: <code>${regKeyInfo?.code || '-'}</code>
👤 Role: <b>${regKeyInfo?.roleName || '-'}</b>
🔢 Remaining: ${afterCount}
${action === 'use' ? `📉 Usage: ${beforeCount} ➜ ${afterCount}\n` : ''}${regKeyInfo?.expireTime ? `⏳ Expire: ${regKeyInfo.expireTime}\n` : ''}${regKeyInfo?.roleInfo ? `${formatRoleInfo(regKeyInfo.roleInfo)}\n` : ''}${actorInfo?.email ? `👨‍💼 By: <code>${actorInfo.email}</code>\n` : ''}${actorInfo?.role ? `🧩 Actor Role: <b>${actorInfo.role.name || 'Unknown'}</b>\n` : ''}${actorInfo?.activeIp ? `📍 IP Address: <code>${actorInfo.activeIp}</code>${formatIpDetail(actorInfo.ipDetail)}\n` : ''}${formatDualTime(new Date().toISOString(), actorInfo?.timezone)}`;
}



export function adminCreateUserMsgTemplate(newUser, roleInfo, adminUser) {
	return `🆕 <b>User Created by Admin</b>

📧 User: <code>${newUser.email}</code>${formatRoleInfo(roleInfo)}
📍 Registration IP: <code>${newUser.createIp || '-'}</code>${formatIpDetail(newUser.createIpDetail || newUser.ipDetail)}
💻 Device: ${newUser.device || 'Unknown'} / ${newUser.os || 'Unknown'}

👨‍💼 Admin: <code>${adminUser.email}</code>
📍 Admin IP: <code>${adminUser.activeIp}</code>${formatIpDetail(adminUser.ipDetail)}
${formatDualTime(new Date().toISOString(), adminUser.timezone)}`;
}

// Template untuk detail keamanan IP (vpnapi.io)
export function ipSecurityMsgTemplate(userInfo, ipDetail) {
	const security = ipDetail?.security || {};
	const location = ipDetail?.location || {};
	const network = ipDetail?.network || {};

	return `🌐 <b>Recent IP Updated</b>

📧 User: <code>${userInfo.email}</code>${formatRoleInfo(userInfo.role)}
📍 Recent IP: <code>${ipDetail?.ip || userInfo.activeIp || '-'}</code>

<b>Security Check</b>
🛡️ VPN: ${security.vpn ? '✅ Yes' : '❌ No'}
🧭 Proxy: ${security.proxy ? '✅ Yes' : '❌ No'}
🕸️ Tor: ${security.tor ? '✅ Yes' : '❌ No'}
🔁 Relay: ${security.relay ? '✅ Yes' : '❌ No'}

<b>Location</b>
🏙️ City/Region: ${(location.city || '-')}${location.region ? `, ${location.region}` : ''}
🌍 Country: ${location.country || '-'} (${location.country_code || '-'})

<b>Network</b>
🏢 ASN Org: ${network.autonomous_system_organization || '-'}
🔢 ASN: ${network.autonomous_system_number || '-'}

${formatDualTime(new Date().toISOString(), userInfo.timezone)}`;
}
