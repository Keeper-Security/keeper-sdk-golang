package enterprise

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"google.golang.org/protobuf/proto"
)

func newEntity[TP any](data []byte) (entity *TP, err error) {
	var protoEntity = new(TP)
	var ok bool
	var m proto.Message
	if m, ok = any(protoEntity).(proto.Message); ok {
		if err = proto.Unmarshal(data, m); err == nil {
			entity = protoEntity
		}
	} else {
		err = api.NewKeeperError("Invalid proto message class")
	}
	return
}

type iEntityConversion[TP any, TK interface{}, K comparable] interface {
	getStorageKey(*TP) string
	toKeeperEntities(*TP, []byte, func(K, TK))
}
type multipleEntityConversion[TP any, TK interface{}, K comparable] struct {
	onConvertEntityFunc func(*TP, []byte, func(K, TK))
	onStorageKey        func(*TP) string
}

func (mec *multipleEntityConversion[TP, TK, K]) getStorageKey(protoEntity *TP) (primaryKey string) {
	if mec.onStorageKey != nil {
		return mec.onStorageKey(protoEntity)
	}
	panic("Not implemented")
}
func (mec *multipleEntityConversion[TP, TK, K]) toKeeperEntities(protoEntity *TP, treeKey []byte, cb func(K, TK)) {
	if mec.onConvertEntityFunc != nil {
		mec.onConvertEntityFunc(protoEntity, treeKey, cb)
	} else {
		panic("Get Entity: Not implemented")
	}
}

type singleEntityConversion[TP any, TK interface{}, K comparable] struct {
	onStorageKey    func(*TP) string
	onConvertEntity func(*TP, []byte) (K, TK)
}

func (sec *singleEntityConversion[TP, TK, K]) getStorageKey(protoEntity *TP) (primaryKey string) {
	if sec.onStorageKey != nil {
		return sec.onStorageKey(protoEntity)
	}
	panic("Not implemented")
}
func (sec *singleEntityConversion[TP, TK, K]) toKeeperEntities(protoEntity *TP, treeKey []byte, cb func(K, TK)) {
	if sec.onConvertEntity != nil {
		k, tk := sec.onConvertEntity(protoEntity, treeKey)
		cb(k, tk)
	} else {
		panic("Get Entity: Not implemented")
	}
}

type baseEntity[TP any, TK interface{}, K storage.Key] struct {
	iEntityConversion[TP, TK, K]
	data        map[K]TK
	deleteLinks []func(K)
}

func (be *baseEntity[TP, TK, K]) registerCascadeDelete(cb func(K)) {
	be.deleteLinks = append(be.deleteLinks, cb)
}

func (be *baseEntity[TP, TK, K]) clear() {
	be.data = nil
}
func (be *baseEntity[TP, TK, K]) store(data []byte, encryptionKey []byte) (primaryKey string, err error) {
	var protoEntity *TP
	if protoEntity, err = newEntity[TP](data); err != nil {
		return
	}
	if be.data == nil {
		be.data = make(map[K]TK)
	}
	primaryKey = be.getStorageKey(protoEntity)
	be.toKeeperEntities(protoEntity, encryptionKey, func(key K, keeperEntity TK) {
		be.data[key] = keeperEntity
	})
	return
}
func (be *baseEntity[TP, TK, K]) delete(data []byte) (primaryKey string, err error) {
	var protoEntity *TP
	if protoEntity, err = newEntity[TP](data); err != nil {
		return
	}
	primaryKey = be.getStorageKey(protoEntity)
	if be.data == nil {
		return
	}
	be.toKeeperEntities(protoEntity, nil, func(key K, _ TK) {
		delete(be.data, key)
		for _, cb := range be.deleteLinks {
			cb(key)
		}
	})

	return
}

func (be *baseEntity[TP, TK, K]) GetEntity(key K) TK {
	return be.data[key]
}

func (be *baseEntity[TP, TK, K]) GetAllEntities(cb func(TK) bool) {
	if be.data != nil {
		for _, v := range be.data {
			if !cb(v) {
				return
			}
		}
	}
}

type LinkKey[KS storage.Key, KO storage.Key] struct {
	V1 KS
	V2 KO
}

type baseLink[TP any, TK interface{}, KS storage.Key, KO storage.Key] struct {
	iEntityConversion[TP, TK, LinkKey[KS, KO]]
	data map[LinkKey[KS, KO]]TK
}

func (bl *baseLink[TP, TK, KS, KO]) clear() {
	bl.data = nil
}
func (bl *baseLink[TP, TK, KS, KO]) store(data []byte, encryptionKey []byte) (primaryKey string, err error) {
	var protoEntity *TP
	if protoEntity, err = newEntity[TP](data); err != nil {
		return
	}
	if bl.data == nil {
		bl.data = make(map[LinkKey[KS, KO]]TK)
	}
	primaryKey = bl.getStorageKey(protoEntity)
	bl.toKeeperEntities(protoEntity, encryptionKey, func(key LinkKey[KS, KO], keeperEntity TK) {
		bl.data[key] = keeperEntity
	})
	return
}
func (bl *baseLink[TP, TK, KS, KO]) delete(data []byte) (primaryKey string, err error) {
	var protoEntity *TP
	if protoEntity, err = newEntity[TP](data); err != nil {
		return
	}
	primaryKey = bl.getStorageKey(protoEntity)
	if bl.data == nil {
		return
	}
	bl.toKeeperEntities(protoEntity, nil, func(key LinkKey[KS, KO], _ TK) {
		delete(bl.data, key)
	})

	return
}

func (bl *baseLink[TP, TK, KS, KO]) deleteBySubject(subjectId KS) {
	if bl.data == nil {
		return
	}
	var keys []LinkKey[KS, KO]
	for k := range bl.data {
		if k.V1 == subjectId {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		delete(bl.data, k)
	}
}
func (bl *baseLink[TP, TK, KS, KO]) deleteByObject(objectId KO) {
	if bl.data == nil {
		return
	}
	var keys []LinkKey[KS, KO]
	for k := range bl.data {
		if k.V2 == objectId {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		delete(bl.data, k)
	}
}
func (bl *baseLink[TP, TK, KS, KO]) enumerateData(cmp func(key LinkKey[KS, KO]) bool, cb func(TK) bool) {
	if bl.data != nil {
		for k, v := range bl.data {
			if !cmp(k) {
				continue
			}
			if !cb(v) {
				break
			}
		}
	}
}
func (bl *baseLink[TP, TK, KS, KO]) GetLinksBySubject(subjectId KS, cb func(TK) bool) {
	bl.enumerateData(
		func(l LinkKey[KS, KO]) bool { return l.V1 == subjectId },
		func(link TK) bool { return cb(link) })
}
func (bl *baseLink[TP, TK, KS, KO]) GetLinksByObject(objectId KO, cb func(TK) bool) {
	bl.enumerateData(
		func(l LinkKey[KS, KO]) bool { return l.V2 == objectId },
		func(link TK) bool { return cb(link) })
}
func (bl *baseLink[TP, TK, KS, KO]) GetAllLinks(cb func(TK) bool) {
	bl.enumerateData(
		func(l LinkKey[KS, KO]) bool { return true },
		func(link TK) bool { return cb(link) })
}
func (bl *baseLink[TP, TK, KS, KO]) GetLink(subjectId KS, objectId KO) (result TK) {
	result = bl.data[LinkKey[KS, KO]{
		V1: subjectId,
		V2: objectId,
	}]
	return
}
