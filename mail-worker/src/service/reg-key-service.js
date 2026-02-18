import orm from '../entity/orm';
import regKey from '../entity/reg-key';
import { inArray, like, eq, desc, sql, or } from 'drizzle-orm';
import roleService from './role-service';
import BizError from '../error/biz-error';
import { formatDetailDate, toUtc } from '../utils/date-uitil';
import userService from './user-service';
import { t } from '../i18n/i18n.js';
import telegramService from './telegram-service';

const regKeyService = {

	async add(c, params, userId) {

		let {code,roleId,count,expireTime} = params;

		if (!code) {
			throw new BizError(t('emptyRegKey'));
		}

		if (!count) {
			throw new BizError(t('emptyRegKey'));
		}

		if (!expireTime) {
			throw new BizError(t('emptyRegKeyExpire'));
		}

		const regKeyRow = await orm(c).select().from(regKey).where(eq(regKey.code, code)).get();

		if (regKeyRow) {
			throw new BizError(t('isExistRegKye'));
		}

		const roleRow = await roleService.selectById(c, roleId);
		if (!roleRow) {
			throw new BizError(t('roleNotExist'));
		}

		expireTime = formatDetailDate(expireTime)

		const inserted = await orm(c).insert(regKey).values({code,roleId,count,userId,expireTime}).returning().get();

		try {
			const [roleRow, actor] = await Promise.all([
				roleService.selectById(c, roleId),
				userService.selectById(c, userId)
			]);
			if (actor) {
				actor.role = await userService.selectEffectiveRole(c, actor);
			}
			await telegramService.sendRegKeyManageNotification(c, 'create', {
				...inserted,
				code,
				count,
				expireTime,
				roleName: roleRow?.name
			}, actor);
		} catch (e) {
			console.error('Failed to send reg key create notification:', e);
		}
	},

	async delete(c, params, actorUserId = null) {
		let {regKeyIds} = params;
		regKeyIds = regKeyIds.split(',').map(id => Number(id));
		const deletedRows = await orm(c).select().from(regKey).where(inArray(regKey.regKeyId,regKeyIds)).all();
		await orm(c).delete(regKey).where(inArray(regKey.regKeyId,regKeyIds)).run();

		try {
			const actor = actorUserId ? await userService.selectById(c, actorUserId) : null;
			if (actor) {
				actor.role = await userService.selectEffectiveRole(c, actor);
			}
			for (const row of deletedRows) {
				const roleRow = await roleService.selectById(c, row.roleId);
				await telegramService.sendRegKeyManageNotification(c, 'delete', {
					...row,
					roleName: roleRow?.name
				}, actor);
			}
		} catch (e) {
			console.error('Failed to send reg key delete notification:', e);
		}
	},

	async clearNotUse(c, actorUserId = null) {
		let now = formatDetailDate(toUtc().tz('Asia/Shanghai').startOf('day'))
		const toDelete = await orm(c).select().from(regKey).where(or(eq(regKey.count, 0),sql`datetime(${regKey.expireTime}, '+8 hours') < datetime(${now})`)).all();
		await orm(c).delete(regKey).where(or(eq(regKey.count, 0),sql`datetime(${regKey.expireTime}, '+8 hours') < datetime(${now})`)).run();

		try {
			const actor = actorUserId ? await userService.selectById(c, actorUserId) : null;
			if (actor) {
				actor.role = await userService.selectEffectiveRole(c, actor);
			}
			for (const row of toDelete) {
				const roleRow = await roleService.selectById(c, row.roleId);
				await telegramService.sendRegKeyManageNotification(c, 'clear', {
					...row,
					roleName: roleRow?.name
				}, actor);
			}
		} catch (e) {
			console.error('Failed to send reg key clear notification:', e);
		}
	},

	selectByCode(c, code) {
		return orm(c).select().from(regKey).where(eq(regKey.code, code)).get();
	},

	async list(c, params) {

		const {code} = params
		let query = orm(c).select().from(regKey)

		if (code) {
			query = query.where(like(regKey.code, `${code}%`))
		}

		const regKeyList = await query.orderBy(desc(regKey.regKeyId)).all();
		const roleList = await roleService.roleSelectUse(c);

		const today = toUtc().tz('Asia/Shanghai').startOf('day')

		regKeyList.forEach(regKeyRow => {

			const index = roleList.findIndex(roleRow => roleRow.roleId === regKeyRow.roleId)
			regKeyRow.roleName = index > -1 ? roleList[index].name : ''

			const expireTime = toUtc(regKeyRow.expireTime).tz('Asia/Shanghai').startOf('day');

			if (expireTime.isBefore(today)) {
				regKeyRow.expireTime = null
			}
		})

		return regKeyList;
	},

	async reduceCount(c, code, count, actorUserId = null) {
		const before = await this.selectByCode(c, code);
		await orm(c).update(regKey).set({
			count: sql`${regKey.count}
	  -
	  ${count}`
		}).where(eq(regKey.code, code)).run();
		const after = await this.selectByCode(c, code);

		try {
			const actor = actorUserId ? await userService.selectById(c, actorUserId) : null;
			if (actor) {
				actor.role = await userService.selectEffectiveRole(c, actor);
			}
			const roleRow = after ? await roleService.selectById(c, after.roleId) : (before ? await roleService.selectById(c, before.roleId) : null);
			await telegramService.sendRegKeyManageNotification(c, 'use', {
				...(after || before),
				roleName: roleRow?.name
			}, actor, {
				beforeCount: before?.count,
				afterCount: after?.count
			});
		} catch (e) {
			console.error('Failed to send reg key use notification:', e);
		}
	},

	async history(c, params) {
		const { regKeyId } = params;
		return userService.listByRegKeyId(c, regKeyId);
	}
}

export default regKeyService;
