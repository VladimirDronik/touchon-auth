package model

type SMS struct {
	ID      string  `json:"call_id"`
	Phone   string  `json:"phone"`
	Cost    float32 `json:"cost"`
	Balance float32 `json:"balance"`
}
