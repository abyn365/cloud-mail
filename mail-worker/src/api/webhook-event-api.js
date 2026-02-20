import app from '../hono/hono';
import result from '../model/result';

app.get('/webhook-event/list', async (c) => {
	const page = Math.max(1, Number(c.req.query('page') || 1));
	const size = Math.min(50, Math.max(1, Number(c.req.query('size') || 20)));
	const offset = (page - 1) * size;
	const eventId = Number(c.req.query('eventId') || 0);
	const keyword = String(c.req.query('keyword') || '').trim();

	const where = [];
	const params = [];
	if (eventId > 0) {
		where.push('log_id = ?');
		params.push(eventId);
	}
	if (keyword) {
		where.push('(event_type LIKE ? OR message LIKE ? OR meta LIKE ?)');
		const like = `%${keyword}%`;
		params.push(like, like, like);
	}
	const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

	const totalRow = await c.env.db.prepare(`SELECT COUNT(*) as total FROM webhook_event_log ${whereSql}`)
		.bind(...params).first();
	const { results } = await c.env.db.prepare(`
		SELECT log_id as logId, event_type as eventType, level, message, meta, create_time as createTime
		FROM webhook_event_log
		${whereSql}
		ORDER BY log_id DESC
		LIMIT ? OFFSET ?
	`).bind(...params, size, offset).all();

	return c.json(result.ok({
		list: results || [],
		total: Number(totalRow?.total || 0),
		page,
		size
	}));
});

app.get('/webhook-event/detail', async (c) => {
	const eventId = Number(c.req.query('eventId') || 0);
	if (!eventId) return c.json(result.ok(null));
	const row = await c.env.db.prepare(`
		SELECT log_id as logId, event_type as eventType, level, message, meta, create_time as createTime
		FROM webhook_event_log WHERE log_id = ?
	`).bind(eventId).first();
	return c.json(result.ok(row || null));
});
