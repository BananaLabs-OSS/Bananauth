// Command import-legacy applies an explicit offline identity export through the
// native owner's transactional import and idempotency rules. It starts no HTTP
// server and sends no email. Original source files are never changed.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readImport(reader io.Reader) (identity.LegacyImportRequest, error) {
	var request identity.LegacyImportRequest
	raw, err := io.ReadAll(io.LimitReader(reader, (64<<20)+1))
	if err != nil {
		return request, err
	}
	if len(raw) > 64<<20 {
		return request, errors.New("identity import exceeds 64 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	document, err := readJSONValue(decoder)
	if err != nil {
		return request, errors.New("invalid identity export JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return request, errors.New("trailing identity export data")
	}
	document, err = integers(document)
	if err != nil {
		return request, err
	}
	wire, err := msgpack.Marshal(document)
	if err != nil {
		return request, err
	}
	typed := msgpack.NewDecoder(bytes.NewReader(wire))
	typed.DisallowUnknownFields(true)
	if err := typed.Decode(&request); err != nil {
		return request, errors.New("invalid or unknown identity export fields")
	}
	if request.RequestID == "" {
		return request, errors.New("stable request_id is required")
	}
	return request, nil
}

// Reject duplicate keys before any owner database is opened.
func readJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	if delimiter == '{' {
		result := map[string]any{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, errors.New("invalid JSON key")
			}
			if _, exists := result[key]; exists {
				return nil, errors.New("duplicate JSON key")
			}
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		_, err := decoder.Token()
		return result, err
	}
	if delimiter == '[' {
		result := []any{}
		for decoder.More() {
			value, err := readJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		_, err := decoder.Token()
		return result, err
	}
	return nil, errors.New("invalid JSON delimiter")
}

func integers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		number, err := v.Int64()
		if err != nil {
			return nil, errors.New("identity export numbers must be exact signed integers")
		}
		return number, nil
	case map[string]any:
		for key, item := range v {
			n, err := integers(item)
			if err != nil {
				return nil, err
			}
			v[key] = n
		}
	case []any:
		for i, item := range v {
			n, err := integers(item)
			if err != nil {
				return nil, err
			}
			v[i] = n
		}
	}
	return value, nil
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("import-legacy", flag.ContinueOnError)
	input := flags.String("input", "", "offline JSON identity export")
	database := flags.String("database", "", "isolated native identity database path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *database == "" || flags.NArg() != 0 {
		return errors.New("-input and -database are required")
	}
	file, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer file.Close()
	sourceInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if targetInfo, err := os.Stat(*database); err == nil && os.SameFile(sourceInfo, targetInfo) {
		return errors.New("source and target must differ")
	}
	request, err := readImport(file)
	if err != nil {
		return err
	}
	keys, err := otpsecure.Parse(os.Getenv("BANANAUTH_OTP_KEY_CURRENT"), os.Getenv("BANANAUTH_OTP_KEY_PREVIOUS"))
	if err != nil {
		return err
	}
	providers, closeDB, err := identity.Open(context.Background(), *database, keys)
	if err != nil {
		return err
	}
	defer closeDB.Close()
	wire, err := msgpack.Marshal(request)
	if err != nil {
		return err
	}
	result, err := providers[identity.FnLegacyImport](wire)
	if err != nil {
		return err
	}
	var response identity.Result[identity.LegacyImportResult]
	if err := msgpack.Unmarshal(result, &response); err != nil {
		return err
	}
	if !response.OK {
		if response.Error != nil {
			return fmt.Errorf("identity import rejected: %s", response.Error.Code)
		}
		return errors.New("identity import rejected")
	}
	return json.NewEncoder(output).Encode(map[string]any{"request_id": request.RequestID, "counts": response.Value})
}
