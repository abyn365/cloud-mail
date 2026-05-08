import orm from '../entity/orm';
import { mergeRecord } from '../entity/merge-record';
import emailService from './email-service';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';
import { eq, desc } from 'drizzle-orm';
import { mergeConst } from '../const/entity-const';

const mergeService = {
    // Simple CSV parser that handles quotes
    parseCSV(csvData) {
        const rows = [];
        let currentRow = [];
        let currentField = '';
        let insideQuotes = false;

        for (let i = 0; i < csvData.length; i++) {
            const char = csvData[i];
            const nextChar = csvData[i + 1];

            if (char === '"' && insideQuotes && nextChar === '"') {
                currentField += '"';
                i++;
            } else if (char === '"') {
                insideQuotes = !insideQuotes;
            } else if (char === ',' && !insideQuotes) {
                currentRow.push(currentField.trim());
                currentField = '';
            } else if ((char === '\r' || char === '\n') && !insideQuotes) {
                if (char === '\r' && nextChar === '\n') i++;
                currentRow.push(currentField.trim());
                if (currentRow.length > 0 && currentRow.some(f => f !== '')) {
                    rows.push(currentRow);
                }
                currentRow = [];
                currentField = '';
            } else {
                currentField += char;
            }
        }
        if (currentField || currentRow.length > 0) {
            currentRow.push(currentField.trim());
            rows.push(currentRow);
        }

        if (rows.length < 2) return [];

        const headers = rows[0];
        return rows.slice(1).map(row => {
            const obj = {};
            headers.forEach((header, index) => {
                obj[header] = row[index] || '';
            });
            return obj;
        });
    },

    replacePlaceholders(template, variables) {
        if (!template) return '';
        return template.replace(/\{\{(.*?)\}\}/g, (match, key) => {
            const trimmedKey = key.trim();
            return variables[trimmedKey] !== undefined ? variables[trimmedKey] : match;
        });
    },

    async sendMerge(c, params, userId) {
        const { accountId, subject, content, csvData, attachments, cc, bcc } = params;

        if (!accountId || !subject || !content || !csvData) {
            throw new BizError(t('missingParams'));
        }

        const recipients = this.parseCSV(csvData);
        if (recipients.length === 0) {
            throw new BizError(t('noRecipientsFound'));
        }

        // Create merge record
        const record = await orm(c).insert(mergeRecord).values({
            userId,
            accountId,
            subject,
            content,
            total: recipients.length,
            status: mergeConst.status.PENDING
        }).returning().get();

        // Update to processing
        await orm(c).update(mergeRecord).set({ status: mergeConst.status.PROCESSING }).where(eq(mergeRecord.mergeId, record.mergeId)).run();

        let sentCount = 0;
        let failedCount = 0;
        const failures = [];

        for (const recipient of recipients) {
            const emailAddr = recipient.email || recipient.Email || recipient.EMAIL;
            if (!emailAddr) {
                failedCount++;
                failures.push({ recipient, error: 'No email address found' });
                continue;
            }

            const personalizedSubject = this.replacePlaceholders(subject, recipient);
            const personalizedContent = this.replacePlaceholders(content, recipient);

            try {
                await emailService.send(c, {
                    accountId,
                    receiveEmail: [emailAddr],
                    cc,
                    bcc,
                    subject: personalizedSubject,
                    content: personalizedContent,
                    sendType: 'send',
                    name: recipient.name || recipient.Name || '',
                    attachments: attachments || []
                }, userId);
                sentCount++;
            } catch (e) {
                failedCount++;
                failures.push({ email: emailAddr, error: e.message });
            }
        }

        const status = failedCount === 0 ? mergeConst.status.COMPLETED : (sentCount === 0 ? mergeConst.status.FAILED : mergeConst.status.PARTIALLY_FAILED);
        
        await orm(c).update(mergeRecord).set({
            sent: sentCount,
            failed: failedCount,
            failures: JSON.stringify(failures),
            status
        }).where(eq(mergeRecord.mergeId, record.mergeId)).run();

        return {
            mergeId: record.mergeId,
            total: recipients.length,
            sent: sentCount,
            failed: failedCount,
            failures
        };
    },
    
    async list(c, userId) {
        return orm(c).select().from(mergeRecord)
            .where(eq(mergeRecord.userId, userId))
            .orderBy(desc(mergeRecord.mergeId))
            .all();
    }
};

export default mergeService;
