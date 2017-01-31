/*
Copyright 2016 SPIFFE Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bolt

import (
	"encoding/json"

	"github.com/gravitational/trace"
)

// Codec is responsible for encoding/decoding objects
type Codec interface {
	EncodeToBytes(val interface{}) ([]byte, error)
	DecodeFromBytes(val []byte, in interface{}) error
}

// JSONCodec encodes and decodes value drom bytes using json
type JSONCodec struct {
}

func (*JSONCodec) EncodeToBytes(val interface{}) ([]byte, error) {
	data, err := json.Marshal(val)
	if err != nil {
		return nil, trace.Wrap(err, "failed to encode object")
	}
	return data, nil
}

func (*JSONCodec) DecodeFromBytes(data []byte, in interface{}) error {
	err := json.Unmarshal(data, &in)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}
