package voice

import "fmt"

const transcribePrompt = `你是一个语音转文字助手。请将音频内容准确转写为文字。
规则：
- 准确还原说话内容，保留原意
- 自动添加标点符号
- 修正明显的口误和重复
- 输出纯文本，不要加任何解释`

const modifyPromptTemplate = `你是一个语音转文字助手。用户已有一段文本，现在通过语音给出修改指令或补充内容。
已有文本：
---
%s
---
请根据音频内容，对已有文本进行修改或补充。
规则：
- 如果语音是修改指令（如"把第一句改成..."），执行修改
- 如果语音是补充内容，追加到已有文本后
- 输出修改后的完整文本，不要加解释`

// buildPrompt returns the appropriate prompt based on whether context text is provided.
func buildPrompt(contextText string) string {
	if contextText == "" {
		return transcribePrompt
	}
	return fmt.Sprintf(modifyPromptTemplate, contextText)
}
