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

// package toolbox contains general purpose utility functions
package toolbox

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gravitational/trace"
)

func RemoveAllInDir(targetDirectory string) error {
	files, err := ioutil.ReadDir(targetDirectory)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	for _, f := range files {
		err = os.RemoveAll(filepath.Join(targetDirectory, f.Name()))
		if err != nil {
			return trace.ConvertSystemError(err)
		}
	}
	return nil
}

func Mkdir(targetDirectory string, mode os.FileMode) error {
	err := os.Mkdir(targetDirectory, mode)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	return nil
}
func MkdirAll(targetDirectory string, mode os.FileMode) error {
	err := os.MkdirAll(targetDirectory, mode)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	return nil
}

func NormalizePath(path string) (string, error) {
	s, err := filepath.Abs(path)
	if err != nil {
		return "", trace.ConvertSystemError(err)
	}
	abs, err := filepath.EvalSymlinks(s)
	if err != nil {
		return "", trace.ConvertSystemError(err)
	}
	return abs, nil
}

func Remove(path string) error {
	err := os.Remove(path)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	return nil
}

func WritePath(path string, data []byte, perm os.FileMode) error {
	err := ioutil.WriteFile(path, data, perm)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	return nil
}

func ReadPath(path string) ([]byte, error) {
	abs, err := NormalizePath(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	bytes, err := ioutil.ReadFile(abs)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return bytes, nil
}

func StatDir(path string) (os.FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	if !fi.IsDir() {
		return nil, trace.BadParameter("%v is not a directory", path)
	}
	return fi, nil
}

func ReadDir(dir string) ([]os.FileInfo, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return files, nil
}
