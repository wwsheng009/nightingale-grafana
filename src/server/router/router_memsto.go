package router

import (
	"github.com/gin-gonic/gin"
	"github.com/toolkits/pkg/ginx"

	"github.com/didi/nightingale/v5/src/server/idents"
	"github.com/didi/nightingale/v5/src/server/memsto"
)

func alertRuleGet(c *gin.Context) {
	id := ginx.QueryInt64(c, "id")
	rule := memsto.AlertRuleCache.Get(id)
	c.JSON(200, gin.H{"id": id, "rule": rule})
}

func identsGets(c *gin.Context) {
	c.JSON(200, idents.Idents.Items())
}

func mutesGets(c *gin.Context) {
	c.JSON(200, memsto.AlertMuteCache.GetAllStructs())
}

func subscribesGets(c *gin.Context) {
	c.JSON(200, memsto.AlertSubscribeCache.GetStructs(ginx.QueryInt64(c, "id")))
}

func targetGet(c *gin.Context) {
	ident := ginx.QueryStr(c, "ident")
	target, _ := memsto.TargetCache.Get(ident)
	c.JSON(200, gin.H{"ident": ident, "target": target})
}

func userGet(c *gin.Context) {
	id := ginx.QueryInt64(c, "id")
	user := memsto.UserCache.GetByUserId(id)
	c.JSON(200, gin.H{"id": id, "user": user})
}

func userGroupGet(c *gin.Context) {
	id := ginx.QueryInt64(c, "id")
	ug := memsto.UserGroupCache.GetByUserGroupId(id)
	c.JSON(200, gin.H{"id": id, "user_group": ug})
}
