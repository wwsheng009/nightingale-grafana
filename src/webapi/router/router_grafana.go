package router

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/didi/nightingale/v5/src/models"
	"github.com/didi/nightingale/v5/src/webapi/config"
	"github.com/gin-gonic/gin"
	"github.com/toolkits/pkg/ginx"
)

//根据请求把sso token抽取出来
func ssoAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		metadata, err := extractSSOTokenMetadata(c.Request)
		if err != nil {
			ginx.Bomb(http.StatusUnauthorized, "unauthorized")
		}

		userIdentity, err := fetchAuth(c.Request.Context(), metadata.AccessUuid)
		if err != nil {
			ginx.Bomb(http.StatusUnauthorized, "unauthorized")
		}

		// ${userid}-${username}
		arr := strings.SplitN(userIdentity, "-", 2)
		if len(arr) != 2 {
			ginx.Bomb(http.StatusUnauthorized, "unauthorized")
		}

		userid, err := strconv.ParseInt(arr[0], 10, 64)
		if err != nil {
			ginx.Bomb(http.StatusUnauthorized, "unauthorized")
		}

		c.Set("userid", userid)
		c.Set("username", arr[1])
		c.Set("grafana-role", getUserRole(c))
		c.Next()
	}
}

//根据用户的信息判断在grafana中的角色，主要分两种，
//一种是管理员，管理员可以修改删除操作,
//另外一种是普通用户，普通用户只能查看
func getUserRole(c *gin.Context) string {
	userid := c.MustGet("userid").(int64)

	user, err := models.UserGetById(userid)
	if err != nil {
		ginx.Bomb(http.StatusUnauthorized, "unauthorized")
	}

	if user == nil {
		ginx.Bomb(http.StatusUnauthorized, "unauthorized")
	}

	roles := strings.Fields(user.Roles)
	found := false
	for i := 0; i < len(roles); i++ {
		if roles[i] == models.AdminRole {
			found = true
			break
		}
	}
	if !found {
		return "Viewer"
	}
	return "Admin"
}

func extractSSOTokenMetadata(r *http.Request) (*AccessDetails, error) {
	// ！！！ 不要使用verifyToken，要不然解析出来的token
	token, err := verifySSOToken(config.C.JWTAuth.SigningKey, extractSSOToken(r))
	if err != nil {
		return nil, err
	}

	//注意：检验token的代码需要放这个模块中，要不然会失败
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}

		return &AccessDetails{
			AccessUuid:   accessUuid,
			UserIdentity: claims["user_identity"].(string),
		}, nil
	}

	return nil, err
}
func verifySSOToken(signingKey, tokenString string) (*jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("Bearer token not found")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected jwt signing method: %v", token.Header["alg"])
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

//从cookie中把token取出
func extractSSOToken(r *http.Request) string {

	cookie, err := r.Cookie("sso2")
	if err != nil {
		return ""
	}

	return cookie.Value
}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		fmt.Printf("Got error while modifying response: %v \n", err)
		return
	}
}
func modifyResponse() func(*http.Response) error {
	return func(resp *http.Response) error {
		// resp.Header.Set("X-Proxy", "Magical")
		// println(resp.Header)
		// if strings.Contains(resp.Request.URL.Path, "live") {
		// 	bodyBytes, err := io.ReadAll(resp.Body)
		// 	if err != nil {
		// 		log.Fatal(err)
		// 	}
		// 	bodyString := string(bodyBytes)
		// 	println(bodyString)

		// }
		return nil
	}
}
func grafanaProxy(c *gin.Context) {
	if strings.Contains(c.Request.URL.Path, "live") {
		println("web socket request:", c.Request.URL.String())
	}
	//println("grafana request:", c.Request.URL.String())
	remote, err := url.Parse(config.C.Grafana)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)

	originalDirector := proxy.Director
	//Define the director func
	//This is a good place to log, for example
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header = c.Request.Header

		// tok := c.Request.Header.Get("Authorization")
		// println("Authorization", tok)
		me := c.MustGet("user").(*models.User)

		if me != nil {
			//对应grafana中proxy auth中的配置字段
			req.Header.Add("X-WEBAUTH-USER", me.Username)
		}
		role := c.GetString("grafana-role")
		if role != "" {
			//对应grafana中配置的角色映射字段
			req.Header.Add("X-WEBAUTH-ROLE", role)
		}
		//不要修改host,否则grafana无法通过web socket连接

		//req.Host = remote.Host
		//req.Header.Set("Orgin", config.C.Grafana)
		//req.URL.Scheme = remote.Scheme
		//req.URL.Host = remote.Host

		//需要修改path，不然url前面会附加了/grafana
		req.URL.Path = c.Param("proxyPath")
		//req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		// if strings.Contains(c.Request.URL.Path, "live") {
		// 	println("requst.host", req.Host)
		// 	println("req.URL.Path", req.URL.Path)
		// 	println("X-Forwarded-Host", req.Header.Get("Host"))
		// 	println("remote.Host", remote.Host)
		// }

	}
	proxy.ModifyResponse = modifyResponse()
	proxy.ErrorHandler = errorHandler()
	proxy.ServeHTTP(c.Writer, c.Request)
}
