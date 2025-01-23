package domain

type UserAttestation struct {
	Token    string
	UserInfo UserInfo
}

type UserInfo struct {
	Name       string
	Secret     string
	SystemInfo SystemInfo
}

type SystemInfo struct {
	UserID              string
	Username            string
	GroupID             string
	GroupName           string
	SupplementaryGroups []GroupInfo
}

type GroupInfo struct {
	GroupID   string
	GroupName string
}
