package model

type Call struct {
	ID      string  `json:"call_id"`
	Phone   string  `json:"phone"`
	Cost    float32 `json:"cost"`
	Balance float32 `json:"balance"`
}
