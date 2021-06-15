package aes

import (
	"testing"
)

// 例举CBC模式用法，其他类似
func TestAesEncryptToBase64(t *testing.T) {
	str := `{"currency":"SSS","keystore":"123456","time":1610795687392}`
	data, err := AesECBEncryptToBase64(str, "123456")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(data)

	data, err = AesECBDecryptFromBase64(data, "123")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(data)
}
