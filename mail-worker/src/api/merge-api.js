import app from '../hono/hono';
import mergeService from '../service/merge-service';
import result from '../model/result';
import userContext from '../security/user-context';

app.get('/merge/list', async (c) => {
	const data = await mergeService.list(c, userContext.getUserId(c));
	return c.json(result.ok(data));
});

app.post('/merge/send', async (c) => {
	const data = await mergeService.sendMerge(c, await c.req.json(), userContext.getUserId(c));
	return c.json(result.ok(data));
});
