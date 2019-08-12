/*******************************************************
	File Name: main.go
	Author: ~gan
	Mail:lijian@cmcm.com
	Created Time: 19/01/25 - 10:24:49
	Modify Time: 19/01/31 - 18:24:49
	Fun 测试谷歌验证器 秘钥的生成以及code的校验
 *******************************************************/
package main

import (
	"googleAuthenticator"
	"log"
)

func createSecret(ga *googleAuthenticator.GAuth) string {
	secret, err := ga.CreateSecret(16)
	if err != nil {
		return ""
	}
	return secret
}

//func getCode(ga *googleAuthenticator.GAuth, secret string) string {
//	code, err := ga.GetCode(secret)
//	if err != nil {
//		return "*"
//	}
//	return code
//}

func verifyCode(ga *googleAuthenticator.GAuth, secret, code string) bool {
	// 1:30sec
	ret, err := ga.VerifyCode(secret, code, 1)
	if err != nil {
		return false
	}
	return ret
}

func main() {

	//生成秘钥  随机数有问题，每次都一样
	//	ga := googleAuthenticator.NewGAuth()
	//	secret :=createSecret(ga)
	//	log.Print("secret:",secret)//V6RMOXPMPJISAQ4E
	//
	//	_route := fmt.Sprintf("https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s", "user", "host",secret)
	//	log.Print("_route::",_route)

	//获取code
	//secret :=  "ZCSDXNLJ5GZX7JMB"
	//ga := googleAuthenticator.NewGAuth()
	//
	//code :=getCode(ga, secret)
	//log.Print("code:",code)

	////校验
	secret := "ZCSDXNLJ5GZX7JMB"
	ga := googleAuthenticator.NewGAuth()
	var code string = "740457"
	sync := verifyCode(ga, secret, code)
	log.Print("sync:", sync)

}
