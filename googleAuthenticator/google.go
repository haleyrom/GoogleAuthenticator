/*******************************************************
	File Name: googgle.go
	Author: ~gan
	Created Time: 19/01/25 - 10:24:49
	Modify Time: 19/01/31 - 18:24:49
	Func 秘钥的生成、code校验工具类
 *******************************************************/
package googleAuthenticator

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"

	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type GAuth struct {
	codeLen float64
	//table   map[string]int
}

func NewGAuth() *GAuth {
	return &GAuth{
		codeLen: 6,
		//table:   arrayFlip(Table),
	}
}

func (this *GAuth) CreateSecret(lens ...int) (string, error) {
	var (
		length int
		secret []string
	)
	// init length
	switch len(lens) {
	case 0:
		length = 16
	case 1:
		length = lens[0]
	default:
		return "", ErrParam
	}
	timestamp := time.Now().Unix()
	s1 := rand.NewSource(timestamp)
	r1 := rand.New(s1)

	for i := 0; i < length; i++ {
		//此处的随机数需要注意
		var r int = r1.Intn(len(Table))

		//var r int =rand.Intn(len(Table))

		secret = append(secret, Table[r])
	}
	return strings.Join(secret, ""), nil
}

// VerifyCode Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
func (this *GAuth) VerifyCode(secret, code string, discrepancy int64) (bool, error) {
	// now time
	//t := time.Now().Unix() // / 30
	//for i := -discrepancy; i <= discrepancy; i++ {
	//calculatedCode, err := this.GetCode(secret, curTimeSlice+i)
	hash := Check_code(secret, code)
	log.Print("hash:", hash)

	if hash == code {
		return true, nil
	}
	//}
	return false, nil
}
func Check_code(secret string, code string) string {

	decodedKey, _ := base32.StdEncoding.DecodeString(secret)
	decodedKeyint8 := bytetoint8(decodedKey)
	t := (time.Now().Unix()) / 30

	hash := verify_code(decodedKeyint8, t)

	log.Println("hash-code:", hash)
	hashstr := strconv.FormatInt(hash, 10)
	return hashstr

}
func verify_code(key []int8, t int64) int64 {

	var data []int8
	var datadesc []int8
	var value int64 = t
	for i := 8; i > 0; i-- {
		data = append(data, int8(value))
		value = value >> 8
	}
	log.Print("data:", data)

	for i := 0; i <= 7; i++ {
		datadesc = append(datadesc, data[7-i])
	}

	log.Print("datadesc:", datadesc)
	keybyte := int8tobyteforhmac(key)
	log.Print("keybyte:", keybyte)
	datamacbyte := int8tobyteforhmac(datadesc)
	log.Print("datamacbyte:", datamacbyte)
	mac := hmac.New(sha1.New, keybyte)
	mac.Write(datamacbyte)
	var res []byte = mac.Sum(nil)
	log.Print("res:", res)
	hash := bytetoint8(res)
	log.Print("resint8:", hash) //到这 数据正确

	var offset int8 = hash[19] & 0XF
	var offset32 int32 = int32(offset)
	log.Print("offset:", offset) //到这 数据正确
	var truncatedHash int64 = 0
	var index int32
	for i := 0; i < 4; i++ {
		truncatedHash <<= 8
		log.Print("truncatedHashpre:", truncatedHash)
		//var a int64 =0
		//a = a|2
		//truncatedHash = truncatedHash | (hash[offset+i] & 0xFF).()
		index = offset32 + int32(i)
		truncatedHash = truncatedHash | (int64(int32(hash[index]) & 0XFF))
		log.Print("truncatedHash:", truncatedHash)
	}

	truncatedHash &= 0x7FFFFFFF
	truncatedHash %= 1000000
	return truncatedHash

}
func bytetoint8(data []byte) []int8 {
	var res = []int8{}
	for _, item := range data {
		res = append(res, int8(item))
	}
	return res
}
func int8tobyteforhmac(data []int8) []byte {
	var res = []byte{}
	for _, item := range data {
		if item >= 0 && item <= 127 {
			res = append(res, byte(item))
		} else {
			//var temp byte =
			temp := 256 + int32(item)
			res = append(res, byte(temp))
		}

	}
	return res
}
