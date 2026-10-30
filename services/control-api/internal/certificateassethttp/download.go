package certificateassethttp

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
)

// 下载证书（fix-certops）：zip 内 fullchain.pem（证书链）与 privkey.pem（PKCS#8）。
// 文件名取证书主域名（通配符 * 换成 _），其余字符不安全时用证书 ID。
var downloadNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)

func downloadFileName(material certificateasset.Download) string {
	name := material.AssetID.String()
	if len(material.SANs) > 0 {
		candidate := []byte(material.SANs[0])
		for index, char := range candidate {
			if char == '*' {
				candidate[index] = '_'
			}
		}
		if downloadNamePattern.Match(candidate) {
			name = string(candidate)
		}
	}
	return name + ".zip"
}

func writeDownload(response http.ResponseWriter, material certificateasset.Download) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	// 固定修改时间，同一证书的下载内容稳定。
	modified := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, file := range []struct {
		name string
		body []byte
	}{{"fullchain.pem", material.CertificatePEM}, {"privkey.pem", material.PrivateKeyPEM}} {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: file.name, Method: zip.Deflate, Modified: modified})
		if err == nil {
			_, err = entry.Write(file.body)
		}
		if err != nil {
			writeError(response, response.Header().Get("X-Request-ID"), http.StatusInternalServerError,
				"certificate_asset_internal_error", "证书服务暂时不可用")
			return
		}
	}
	if err := writer.Close(); err != nil {
		writeError(response, response.Header().Get("X-Request-ID"), http.StatusInternalServerError,
			"certificate_asset_internal_error", "证书服务暂时不可用")
		return
	}
	defer func() {
		raw := archive.Bytes()
		clear(raw[:cap(raw)])
		clear(material.PrivateKeyPEM)
	}()
	name := downloadFileName(material)
	header := response.Header()
	header.Set("Content-Type", "application/zip")
	header.Set("Content-Disposition", `attachment; filename="`+name+`"; filename*=UTF-8''`+url.PathEscape(name))
	header.Set("Content-Length", strconv.Itoa(archive.Len()))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(archive.Bytes())
}
