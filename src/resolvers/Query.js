const { forwardTo } = require("prisma-binding");

const { hasPermission } = require("../utils");

const Query = {
	items: forwardTo("db"),
	item: forwardTo("db"),
	itemsConnection: forwardTo("db"),
	me(parent, args, ctx, info) {
		// check if there is a current ID
		if (!ctx.request.userId) {
			return null;
		}
		return ctx.db.query.user(
			{
				where: { id: ctx.request.userId }
			},
			info
		);
	},
	async users(parent, args, ctx, info) {
		// 1 check if they are logged in
		if (!ctx.request.userId) {
			throw new Error("Logged in please");
		}
		// 2. check if the user has the permissions to query all the users
		hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);
		// 3. if they do, query all the users
		return await ctx.db.query.users({}, info);
	}
};

module.exports = Query;
