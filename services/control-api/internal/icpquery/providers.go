package icpquery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// parseTianAPI follows https://www.tianapi.com/openapi/icp.json:
// {"code":200,"result":{"icp_state":"存在|暂无","icp_number","main_name"}}.
// Code 250 ("数据返回为空") is treated as "no filing record".
func parseTianAPI(body []byte) (Result, error) {
	var response struct {
		Code   int `json:"code"`
		Result struct {
			State    string `json:"icp_state"`
			Number   string `json:"icp_number"`
			MainName string `json:"main_name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return Result{}, fmt.Errorf("%w: tianapi response", ErrProvider)
	}
	switch response.Code {
	case 200:
		if response.Result.State == "存在" && response.Result.Number != "" {
			return Result{Status: Filed, Licence: response.Result.Number, Subject: response.Result.MainName}, nil
		}
		return Result{Status: Unfiled}, nil
	case 250:
		return Result{Status: Unfiled}, nil
	case 140, 160, 190, 230, 240:
		return Result{}, ErrCredential
	case 150:
		return Result{}, ErrQuota
	case 130:
		return Result{}, ErrRateLimited
	default:
		return Result{}, fmt.Errorf("%w: tianapi code %d", ErrProvider, response.Code)
	}
}

// parseALAPI follows the ALAPI "ICP域名备案实时查询" document (api id 24):
// {"success":true,"code":200,"data":{"is_icp":true,"service_licence","unit_name"}}.
func parseALAPI(body []byte, status int) (Result, error) {
	var response struct {
		Success bool `json:"success"`
		Code    int  `json:"code"`
		Data    *struct {
			IsICP          bool   `json:"is_icp"`
			ServiceLicence string `json:"service_licence"`
			UnitName       string `json:"unit_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return Result{}, fmt.Errorf("%w: alapi response", ErrProvider)
	}
	switch {
	case response.Success && response.Code == 200:
		if response.Data != nil && response.Data.IsICP {
			return Result{Status: Filed, Licence: response.Data.ServiceLicence, Subject: response.Data.UnitName}, nil
		}
		return Result{Status: Unfiled}, nil
	case response.Code >= 10001 && response.Code <= 10003:
		return Result{}, ErrCredential
	case status == http.StatusTooManyRequests || response.Code == 429:
		return Result{}, ErrRateLimited
	default:
		return Result{}, fmt.Errorf("%w: alapi code %d", ErrProvider, response.Code)
	}
}

func parseCustom(body []byte, status int, cfg Config) (Result, error) {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return Result{}, ErrCredential
	case status == http.StatusTooManyRequests:
		return Result{}, ErrRateLimited
	case status < 200 || status > 299:
		return Result{}, fmt.Errorf("%w: http %d", ErrProvider, status)
	}
	object, err := decodeObject(body)
	if err != nil {
		return Result{}, err
	}
	value, found := lookup(object, cfg.StatusPath)
	if !found {
		return Result{}, fmt.Errorf("%w: status path not present", ErrProvider)
	}
	result := Result{Status: Unfiled}
	if filed(value, cfg.FiledValues) {
		result.Status = Filed
	}
	if cfg.LicencePath != "" {
		if v, ok := lookup(object, cfg.LicencePath); ok {
			result.Licence = scalar(v)
		}
	}
	if cfg.SubjectPath != "" {
		if v, ok := lookup(object, cfg.SubjectPath); ok {
			result.Subject = scalar(v)
		}
	}
	return result, nil
}

func lookup(object map[string]any, path string) (any, bool) {
	var current any = object
	for _, part := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func filed(value any, accepted []string) bool {
	if len(accepted) > 0 {
		s := scalar(value)
		for _, a := range accepted {
			if s == a {
				return true
			}
		}
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != "" && v != "false" && v != "0"
	default:
		return false
	}
}

func scalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return ""
	}
}
