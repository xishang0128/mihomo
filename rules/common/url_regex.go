package common

import (
	"fmt"
	"regexp"

	C "github.com/metacubex/mihomo/constant"
)

type UrlRegex struct {
	*Base
	regex   *regexp.Regexp
	adapter string
}

func (ur *UrlRegex) RuleType() C.RuleType {
	return C.UrlRegex
}

func (ur *UrlRegex) Match(metadata *C.Metadata) (bool, string) {
	if metadata.Type != C.MITM {
		return false, ur.adapter
	}

	url := metadata.Url
	fmt.Println(url)
	return ur.regex.MatchString(url), ur.adapter
}

func (ur *UrlRegex) Adapter() string {
	return ur.adapter
}

func (ur *UrlRegex) Payload() string {
	return ur.regex.String()
}

func NewUrlRegex(regex string, adapter string) (*UrlRegex, error) {
	r, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	return &UrlRegex{
		Base:    &Base{},
		regex:   r,
		adapter: adapter,
	}, nil
}

//var _ C.Rule = (*UrlRegex)(nil)
