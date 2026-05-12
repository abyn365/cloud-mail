import orm from '../entity/orm';
import email from '../entity/email';
import settingService from './setting-service';
import { eq } from 'drizzle-orm';
import jwtUtils from '../utils/jwt-utils';
import emailMsgTemplate from '../template/email-msg';
import emailTextTemplate from '../template/email-text';
import emailHtmlTemplate from '../template/email-html';
import domainUtils from "../utils/domain-uitls";

const TG_CHAT_ID_PATTERN = /^-?\d+$/;

function normalizeTgChatIds(tgChatId = '') {
    return [...new Set(
        `${tgChatId}`
            .split(',')
            .map(id => id.trim())
            .filter(id => id && TG_CHAT_ID_PATTERN.test(id))
    )];
}

function buildInlineKeyboard(emailRow, webAppUrl, chatType) {
    const checkButton = chatType === 'private'
        ? { text: 'Check', web_app: { url: webAppUrl } }
        : { text: 'Check', url: webAppUrl };

    const inlineKeyboard = [[checkButton]];

    if (emailRow.code) {
        inlineKeyboard.push([
            {
                text: emailRow.code,
                copy_text: { text: emailRow.code }
            }
        ]);
    }

    return inlineKeyboard;
}

async function detectChatType(tgBotToken, chatId) {
    try {
        const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/getChat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ chat_id: chatId })
        });

        const responseBody = await res.text();
        let responseData = null;
        try {
            responseData = JSON.parse(responseBody);
        } catch (_) {
            responseData = null;
        }

        if (!res.ok || !responseData?.ok) {
            console.error(`Telegram getChat failed chatId: ${chatId} status: ${res.status} response: ${responseBody}`);
            return 'unknown';
        }

        return responseData.result?.type || 'unknown';
    } catch (e) {
        console.error(`Telegram getChat failed chatId: ${chatId} status: network_error response: ${e.message}`);
        return 'unknown';
    }
}

const telegramService = {

    async getEmailContent(c, params) {

        const { token } = params

        const result = await jwtUtils.verifyToken(c, token);

        if (!result) {
            return emailTextTemplate('Access denied')
        }

        const emailRow = await orm(c).select().from(email).where(eq(email.emailId, result.emailId)).get();

        if (emailRow) {

            if (emailRow.content) {
                const { r2Domain } = await settingService.query(c);
                return emailHtmlTemplate(emailRow.content || '', r2Domain)
            } else {
                return emailTextTemplate(emailRow.text || '')
            }

        } else {
            return emailTextTemplate('The email does not exist')
        }

    },

    async sendEmailToBot(c, email) {

        const { tgBotToken, tgChatId, customDomain, tgMsgTo, tgMsgFrom, tgMsgText } = await settingService.query(c);
        const tgChatIds = normalizeTgChatIds(tgChatId);

        if (!tgBotToken || !tgChatIds.length) {
            return;
        }

        const jwtToken = await jwtUtils.generateToken(c, { emailId: email.emailId })
        const webAppUrl = customDomain ? `${domainUtils.toOssDomain(customDomain)}/api/telegram/getEmail/${jwtToken}` : 'https://www.cloudflare.com/404'

        await Promise.all(tgChatIds.map(async chatId => {
            const chatType = await detectChatType(tgBotToken, chatId);
            const inlineKeyboard = buildInlineKeyboard(email, webAppUrl, chatType);

            try {
                const res = await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        chat_id: chatId,
                        parse_mode: 'HTML',
                        text: emailMsgTemplate(email, tgMsgTo, tgMsgFrom, tgMsgText),
                        reply_markup: {
                            inline_keyboard: inlineKeyboard
                        }
                    })
                });
                if (!res.ok) {
                    const responseBody = await res.text();
                    console.error(`转发 Telegram 失败 chatId: ${chatId} type: ${chatType} status: ${res.status} response: ${responseBody}`);
                }
            } catch (e) {
                console.error(`转发 Telegram 失败 chatId: ${chatId} type: ${chatType} status: network_error response: ${e.message}`);
            }
        }));

    }

}

export default telegramService
