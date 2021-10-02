package parser

// URI Resources JSON objects in API responses
type URI struct {
	Encrypt string `json:"encrypt"`
	URI     string `json:"uri"`
}

func (uri *URI) String() string {
	s, err := uri.Decrypt()
	if err != nil {
		return ""
	}
	return s
}

func (uri *URI) Decrypt() (string, error) {
	return "", nil
}
