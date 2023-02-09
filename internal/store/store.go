package store

type Store interface {
	User() UserRepository
	Call() CallRepository
}
