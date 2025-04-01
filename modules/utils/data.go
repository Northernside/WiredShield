package utils

import (
	"encoding/json"
	"fmt"
)

const (
	KB = 1024
	MB = KB * 1024
	GB = MB * 1024
	TB = GB * 1024
)

func FormatFileSize(bytes int64) string {
	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2fTB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2fGB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2fMB", float64(bytes)/float64(MB))
	default:
		return fmt.Sprintf("%.2fKB", float64(bytes)/float64(KB))
	}
}

func ConvertMapStringAny(i any) (map[string]any, bool) {
	m, ok := i.(map[interface{}]interface{})
	if !ok {
		return nil, false
	}

	result := make(map[string]any)
	for key, value := range m {
		strKey, ok := key.(string)
		if !ok {
			return nil, false
		}

		result[strKey] = value
	}

	return result, true
}

func MapToStruct[T any, U any](m map[string]any) (T, error) {
	var result T
	data, err := json.Marshal(m)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}
