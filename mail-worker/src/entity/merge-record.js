import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const mergeRecord = sqliteTable('merge_record', {
	mergeId: integer('merge_id').primaryKey({ autoIncrement: true }),
	userId: integer('user_id').notNull(),
	accountId: integer('account_id').notNull(),
	subject: text('subject').notNull(),
	content: text('content').notNull(),
	total: integer('total').default(0).notNull(),
	sent: integer('sent').default(0).notNull(),
	failed: integer('failed').default(0).notNull(),
	failures: text('failures').default('[]'),
	status: integer('status').default(0).notNull(), // 0: pending, 1: processing, 2: completed, 3: partially failed, 4: failed
	createTime: text('create_time').default(sql`CURRENT_TIMESTAMP`).notNull()
});

export default mergeRecord;
