/*******************************************************
	File Name: hmac.go
	Author: ~gan
	Mail:lijian@cmcm.com
	Created Time: 19/01/25 - 10:24:49
	Modify Time: 19/01/31 - 18:24:49
 *******************************************************/
package googleAuthenticator

import (
	"crypto/hmac"
	"crypto/sha1"
)

func HmacSha1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
