// Copyright (c) 2023 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	E "github.com/IBM/fp-go/either"
	IOE "github.com/IBM/fp-go/ioeither"
)

// RunIOEither executes an [IOE.IOEither], ignores the return value and only dispatches the error
func RunIOEither[T any](cmd IOE.IOEither[error, T]) error {
	_, err := E.Unwrap(cmd())
	return err
}
