// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHyperProtectTokens(t *testing.T) {
	goodTokens := []string{
		`hyper-protect-basic.UMs93kGaZrzYa6oeoYk8CyaCnsTtRPVdyT+zWBRKKaQD9H71G8bN3PQzbWVx/N84OeyorvERI9RVnpuWwlvnhXj5mu7KZdMXrPoLzW13/zB9HaKYLh64yV3fBsZbGkhlyyjW5n/dcoJ7zbAF5ZRe4m2unpsDUne2cLs27s1FD08oj7iWw/BrzNqqcyOayQnH1WUtHN2OhR4T3k+qSdj3XtnD6t+dsrxg9XFue0zciNQqxDfayBPiUWGpmtOKF2sc+Dp4cq9bV8SsF1crs3dXBsWc21Zl7nVcwt3bmQET++rBdgwI9TZDMa7gjB9Iu/JbjgbPHuBdIycWJMfIH4mseAH6r+HFg5Wq2t/s3FrWg5qdkwCWjzT3r5OoMOafiG06U0SFp29mND1t0kVypf3nEQJQjb6+WoIGcDvKzvUMz5NcRFi8zubziXg0wAJoSZWFL+/gXiDyg9ZbfR8/Ukx52CVLTYGW/IATChfIw51c57b2EddKT3aS/ZksZpyLfLdiLRxLn6X/lEmVGCUojAhmgiFQZzEjeREAV9HMNRnymiyq+qtK+zSMsfZMMdhesHalaRqK9ORqUgBaYII+AG7sWC1xS0FD5LNtN739SjY18/NAY0OznQWI8Yvfu0BoMRSVNIrZl4QWYHdmNHywSfkktc/Bk6qlkgTy392RbfgbcPw=.U2FsdGVkX1/DbyZBRupGSoukxfU91ywFu5HTUsqs8+LLU+MkGP3PJY1XxwaioHoq`,
	}
	for _, token := range goodTokens {
		assert.True(t, IsHyperProtectBasic(token))
	}

	badTokens := []string{
		`just some text`,
	}
	for _, token := range badTokens {
		assert.False(t, IsHyperProtectBasic(token))
	}
}
