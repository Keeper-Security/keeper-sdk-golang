package storage

func NewInMemoryRecordStorage[T any]() IRecordStorage[T] {
	return &inMemoryRecordStorage[T]{}
}

type inMemoryRecordStorage[T any] struct {
	record T
}

func (mrs *inMemoryRecordStorage[T]) Load() (record T, err error) {
	record = mrs.record
	return
}
func (mrs *inMemoryRecordStorage[T]) Store(record T) (err error) {
	var empty T
	mrs.record = empty
	return
}
func (mrs *inMemoryRecordStorage[T]) Delete() (err error) {
	mrs.record = *new(T)
	return
}

func NewInMemoryEntityStorage[T interface{}, K Key](entityKey func(T) K) IEntityStorage[T, K] {
	return &inMemoryEntityStorage[T, K]{
		onEntityKey: entityKey,
	}
}

type inMemoryEntityStorage[T any, K Key] struct {
	storage     map[K]T
	onEntityKey func(T) K
}

func (mes *inMemoryEntityStorage[T, K]) getEntityKey(entity T) K {
	if mes.onEntityKey != nil {
		return mes.onEntityKey(entity)
	}
	panic("Not implemented")
}

func (mes *inMemoryEntityStorage[T, K]) getStorage() map[K]T {
	if mes.storage == nil {
		mes.storage = make(map[K]T)
	}
	return mes.storage
}

func (mes *inMemoryEntityStorage[T, K]) GetEntity(entityId K) (entity T, err error) {
	if mes.storage == nil {
		return
	}
	entity = mes.storage[entityId]
	return
}
func (mes *inMemoryEntityStorage[T, K]) GetAll(cb func(T) bool) (err error) {
	if mes.storage == nil {
		return
	}
	for _, v := range mes.storage {
		if !cb(v) {
			break
		}
	}
	return
}
func (mes *inMemoryEntityStorage[T, K]) PutEntities(entities []T) (err error) {
	var storage = mes.getStorage()
	for _, e := range entities {
		storage[mes.getEntityKey(e)] = e
	}
	return
}
func (mes *inMemoryEntityStorage[T, K]) DeleteUids(keys []K) (err error) {
	if mes.storage == nil {
		return
	}
	for _, key := range keys {
		delete(mes.storage, key)
	}
	return
}
func (mes *inMemoryEntityStorage[T, K]) Clear() error {
	mes.storage = nil
	return nil
}

func NewInMemoryLinkStorage[T any, KS Key, KO Key](subjectKey func(T) KS, objectKey func(T) KO) ILinkStorage[T, KS, KO] {
	return &inMemoryLinkStorage[T, KS, KO]{
		onSubjectKey: subjectKey,
		onObjectKey:  objectKey,
	}
}

type inMemoryLinkStorage[T interface{}, KS Key, KO Key] struct {
	storage      map[KS]map[KO]T
	onSubjectKey func(T) KS
	onObjectKey  func(T) KO
}

func (mls *inMemoryLinkStorage[T, KS, KO]) getSubjectKey(entity T) KS {
	if mls.onSubjectKey != nil {
		return mls.onSubjectKey(entity)
	}
	panic("Not implemented")
}
func (mls *inMemoryLinkStorage[T, KS, KO]) getObjectKey(entity T) KO {
	if mls.onSubjectKey != nil {
		return mls.onObjectKey(entity)
	}
	panic("Not implemented")
}

func (mls *inMemoryLinkStorage[T, KS, KO]) getStorage() map[KS]map[KO]T {
	if mls.storage == nil {
		mls.storage = make(map[KS]map[KO]T)
	}
	return mls.storage
}
func (mls *inMemoryLinkStorage[T, KS, KO]) PutLinks(links []T) (err error) {
	var storage = mls.getStorage()
	var ok bool
	var objects map[KO]T
	for _, l := range links {
		var subjectKey = mls.getSubjectKey(l)
		if objects, ok = storage[subjectKey]; !ok {
			objects = make(map[KO]T)
			storage[subjectKey] = objects
		}
		var objectKey = mls.getObjectKey(l)
		objects[objectKey] = l
	}
	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) DeleteLinks(links []IUidLink[KS, KO]) (err error) {
	if mls.storage != nil {
		return
	}
	var ok bool
	var objects map[KO]T
	for _, l := range links {
		var subjectKey = l.SubjectUid()
		if objects, ok = mls.storage[subjectKey]; ok {
			delete(objects, l.ObjectUid())
		}
	}
	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) DeleteLinksForSubjects(subjectKeys []KS) (err error) {
	if mls.storage != nil {
		return
	}
	for _, subjectKey := range subjectKeys {
		delete(mls.storage, subjectKey)
	}
	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) DeleteLinksForObjects(objectKeys []KO) (err error) {
	if mls.storage != nil {
		return
	}
	for _, objects := range mls.storage {
		for _, objectKey := range objectKeys {
			delete(objects, objectKey)
		}
	}
	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) GetLinksForSubjects(subjectKeys []KS, cb func(T) bool) (err error) {
	if mls.storage != nil {
		return
	}
	var ok bool
	var objects map[KO]T
	for _, subjectKey := range subjectKeys {
		if objects, ok = mls.storage[subjectKey]; ok {
			for _, v := range objects {
				if !cb(v) {
					return
				}
			}
		}
	}
	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) GetLinksForObjects(objectKeys []KO, cb func(T) bool) (err error) {
	if mls.storage != nil {
		return
	}
	var ok bool
	var objects map[KO]T
	var link T
	for _, objects = range mls.storage {
		for _, objectKey := range objectKeys {
			if link, ok = objects[objectKey]; ok {
				if !cb(link) {
					return
				}
			}
		}
	}

	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) GetAll(cb func(T) bool) (err error) {
	if mls.storage != nil {
		return
	}
	var objects map[KO]T
	for _, objects = range mls.storage {
		for _, link := range objects {
			if !cb(link) {
				return
			}
		}
	}
	return
}

func (mls *inMemoryLinkStorage[T, KS, KO]) GetLink(subjectKey KS, objectKey KO) (link T, err error) {
	if mls.storage != nil {
		return
	}
	var ok bool
	var objects map[KO]T
	if objects, ok = mls.storage[subjectKey]; ok {
		link = objects[objectKey]
	}
	return
}
func (mls *inMemoryLinkStorage[T, KS, KO]) Clear() error {
	mls.storage = nil
	return nil
}
