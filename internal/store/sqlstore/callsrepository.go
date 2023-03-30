package sqlstore

import (
	"time"
	"touchon_auth/model"
)

type CallRepository struct {
	store *Store
}

// RemoveOldData Удаляет все ранее внесенные записи с номером, если они есть,
// также очищает от данных, которые больше часа лежат в БД
func (c *CallRepository) RemoveOldData(phone string) error {

	_, err := c.store.db.Exec(
		"DELETE FROM calls_codes WHERE phone = ? OR `datetime` <= ?",
		phone, time.Now().Add(-10*time.Minute))
	if err != nil {
		return err
	}

	return nil
}

// AddTempCallData Добавляет данные о звонке в таблицу для временного хранения
func (c *CallRepository) AddTempCallData(id string, phone string, code int) error {

	_, err := c.store.db.Exec(
		"INSERT INTO calls_codes (id, phone, code, datetime) VALUES (?, ?, ?, ?) ",
		id, phone, code, time.Now())
	if err != nil {
		return err
	}

	return nil
}

// AddCallData Добавляет данные о звонке в таблицу для хранения
func (c *CallRepository) AddCallData(call *model.Call) error {

	_, err := c.store.db.Exec(
		"INSERT INTO calls (id, phone, cost, balance, type, datetime) VALUES (?, ?, ?, ?, 'call', NOW()) ",
		call.ID, call.Phone, call.Cost, call.Balance)
	if err != nil {
		return err
	}

	return nil
}

// AddSMSData Добавляет данные о sms в таблицу для хранения
func (c *CallRepository) AddSMSData(sms *model.SMS) error {

	_, err := c.store.db.Exec(
		"INSERT INTO calls (id, phone, balance, type, datetime) VALUES (,?, ?, 'sms', NOW()) ",
		sms.Phone, sms.Balance)
	if err != nil {
		return err
	}

	return nil
}

// GetTempCodeByPhone получение верменного кода по номеру телефона и удаление этой записи в БД
func (c *CallRepository) GetRowByCodeANDPhone(phone string, code int) (int, error) {

	cnt := 0

	if err := c.store.db.QueryRow(
		"SELECT COUNT(id) FROM calls_codes WHERE phone = ? AND code = ?", phone, code).Scan(
		&cnt,
	); err != nil {
		return 0, err
	}

	return cnt, nil
}

func (c *CallRepository) GetCodeByPhone(phone string) (int, error) {

	code := 0000

	if err := c.store.db.QueryRow(
		"SELECT code FROM calls_codes WHERE phone = ?", phone).Scan(
		&code,
	); err != nil {
		return 0, err
	}

	return code, nil
}
