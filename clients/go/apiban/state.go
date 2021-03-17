package apiban

import (
	"encoding/json"
	"fmt"
	"os"
)

type State struct {
	// Timestamp is the last timestamp returned by server
	Timestamp string `json:"Timestamp"`

	// name of the file where the state is saved to or loaded from
	Filename string `json:"-"`
}

// global state of the client
var state = State{
	Filename: "/var/lib/apiban/apiban.state",
}

// State returns a global State object which is used for filesystem state persistence
func GetState() *State {
	return &state
}

// Init sets the name of the file where the state is saved to or loaded from
func (s *State) Init(filename string) {
	s.Filename = filename
}

func (s *State) SaveToFile() error {
	f, err := os.Create(s.Filename)
	if err != nil {
		return fmt.Errorf("failed to open state file for writing: %w", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(s)
	return nil
}

func (s *State) LoadFromFile() error {
	f, err := os.Open(s.Filename)
	if err != nil {
		return fmt.Errorf("failed to open state file for reading: %w", err)
	}
	defer f.Close()
	json.NewDecoder(f).Decode(s)
	return nil
}
