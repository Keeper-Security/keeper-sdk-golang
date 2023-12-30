package storage

type IRecordStorage[T any] interface {
	Load() (T, error)
	Store(T) error
	Delete() error
}

type Key interface {
	string | int64
}
type IEntityStorage[T any, K Key] interface {
	GetEntity(K) (T, error)
	PutEntities([]T) error
	GetAll(func(T) bool) error
	DeleteUids([]K) error
	Clear() error
}

type IUidLink[KS Key, KO Key] interface {
	SubjectUid() KS
	ObjectUid() KO
}

type ILinkStorage[T any, KS Key, KO Key] interface {
	PutLinks([]T) error
	DeleteLinks([]IUidLink[KS, KO]) error
	DeleteLinksForSubjects([]KS) error
	DeleteLinksForObjects([]KO) error
	GetLinksForSubjects([]KS, func(T) bool) error
	GetLinksForObjects([]KO, func(T) bool) error
	GetAll(func(T) bool) error
	GetLink(KS, KO) (T, error)
	Clear() error
}

type IUid[K Key] interface {
	Uid() K
}

func NewUidLink[KS Key, KO Key](subjectUid KS, objectUid KO) IUidLink[KS, KO] {
	return &uidLink[KS, KO]{
		subjectUid: subjectUid,
		objectUid:  objectUid,
	}
}

type uidLink[KS comparable, KO comparable] struct {
	subjectUid KS
	objectUid  KO
}

func (link *uidLink[KS, KO]) SubjectUid() KS {
	return link.subjectUid
}
func (link *uidLink[KS, KO]) ObjectUid() KO {
	return link.objectUid
}
