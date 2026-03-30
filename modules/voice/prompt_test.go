package voice

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildPrompt_NoContext(t *testing.T) {
	prompt := buildPrompt("")
	assert.Equal(t, transcribePrompt, prompt)
	assert.Contains(t, prompt, "准确转写为文字")
	assert.NotContains(t, prompt, "已有文本")
}

func TestBuildPrompt_WithContext(t *testing.T) {
	contextText := "Hello, this is existing text."
	prompt := buildPrompt(contextText)

	assert.Contains(t, prompt, "已有文本")
	assert.Contains(t, prompt, contextText)
	assert.Contains(t, prompt, "修改或补充")
	assert.NotEqual(t, transcribePrompt, prompt)
}

func TestBuildPrompt_ContextTextEmbedded(t *testing.T) {
	contextText := "Line 1\nLine 2\nLine 3"
	prompt := buildPrompt(contextText)

	// Context text should appear between the --- delimiters
	parts := strings.Split(prompt, "---")
	assert.True(t, len(parts) >= 3, "prompt should contain --- delimiters")
	assert.Contains(t, parts[1], contextText)
}
