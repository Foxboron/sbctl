package prompt

import (
	"github.com/manifoldco/promptui"
)

func SBCTLPrompt(validate func(string) error, label string, mask *rune) (string, error) {
	prompt := promptui.Prompt{
		Label:    label,
		Validate: validate,
	}
	if mask != nil {
		prompt.Mask = *mask
	}

	result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return result, nil
}
