package aide

type WhiteListEntry struct {
	Path 				string `json:"path"`
	WhiteListRuleName	string `json:"whiteListRuleName"`
}

type WhiteListGroup struct {
	GroupPrefix		string	`json:"groupPrefix"`
	WhiteListEntrys []*WhiteListEntry `json:"whiteListEntrys"`
}

type WhiteListRule struct {
	WhiteListRuleName	string	`json:"whiteListRuleName"`
	WhiteListKeys		[]string	`json:"whiteListKeys"`
}

type configsAIDE struct {
	ToolName 	string	`json:"toolName"`
	Version 	string	`json:"version"`
	WhiteListKeys	[]string 	`json:"whiteListKeys"`
	SupportAlgos	[]string	`json:"supportAlgos"`
	ContentHashAlgo		string	`json:"contentHashAlgo"`
	WhiteListRules		[]*WhiteListRule	`json:"whiteListRules"`
	WhiteListGroups		[]*WhiteListGroup	`json:"whiteListGroups"`
}


