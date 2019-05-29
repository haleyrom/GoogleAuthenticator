/*******************************************************
	File Name: error.go
	Author: ~gan
	Mail:lijian@cmcm.com
	Created Time: 19/01/25 - 10:24:49
	Modify Time: 19/01/31 - 18:24:49
	Fun 秘钥的生成或者code校验的错误类型
 *******************************************************/
package googleAuthenticator

import "errors"

var (
	ErrSecretLengthLss     = errors.New("secret length lss 6 error")
	ErrSecretLength        = errors.New("secret length error")
	ErrPaddingCharCount    = errors.New("padding char count error")
	ErrPaddingCharLocation = errors.New("padding char Location error")
	ErrParam               = errors.New("param error")
)
