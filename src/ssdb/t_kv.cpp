/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "t_kv.h"

int SSDBImpl::multi_set(const std::vector<Bytes> &kvs, int offset, char log_type){
	Transaction trans(binlogs);

    uint64_t size = 0;
	std::vector<Bytes>::const_iterator it;
	it = kvs.begin() + offset;
	for(; it != kvs.end(); it += 2){
		const Bytes &key = *it;
		if(key.empty()){
			log_error("empty key!");
			return 0;
			//return -1;
		}
		const Bytes &val = *(it + 1);
		std::string buf = encode_kv_key(key);
        leveldb::Slice val_slice = slice(val);
		binlogs->Put(buf, val_slice);
		binlogs->add_log(log_type, BinlogCommand::KSET, buf, val_slice);
        size += key.size() + val.size();
	}
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("multi_set error: %s", s.ToString().c_str());
		return -1;
	}
    int count = (kvs.size() - offset)/2;
    kv_size += size;
    kv_count += count;
    update_count += count;
	return count;
}

int SSDBImpl::multi_del(const std::vector<Bytes> &keys, int offset, char log_type){
	Transaction trans(binlogs);

	std::vector<Bytes>::const_iterator it;
	it = keys.begin() + offset;
	for(; it != keys.end(); it++){
		const Bytes &key = *it;
		std::string buf = encode_kv_key(key);
		binlogs->Delete(buf);
		binlogs->add_log(log_type, BinlogCommand::KDEL, buf, "");
	}
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("multi_del error: %s", s.ToString().c_str());
		return -1;
	}
	return keys.size() - offset;
}

int SSDBImpl::set(const Bytes &key, const Bytes &val, char log_type){
	if(key.empty()){
		log_error("empty key!");
		//return -1;
		return 0;
	}
	Transaction trans(binlogs);

	std::string buf = encode_kv_key(key);
    leveldb::Slice val_slice = slice(val);
	binlogs->Put(buf, val_slice);
	binlogs->add_log(log_type, BinlogCommand::KSET, buf, val_slice);
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("set error: %s", s.ToString().c_str());
		return -1;
	}
    kv_size += key.size() + val.size();
    kv_count ++;
    update_count ++;
	return 1;
}

int SSDBImpl::setnx(const Bytes &key, const Bytes &val, char log_type){
	if(key.empty()){
		log_error("empty key!");
		//return -1;
		return 0;
	}
	Transaction trans(binlogs);

	std::string tmp;
	int found = this->get(key, &tmp);
	if(found != 0){
		return 0;
	}
	std::string buf = encode_kv_key(key);
    leveldb::Slice val_slice = slice(val);
	binlogs->Put(buf, val_slice);
	binlogs->add_log(log_type, BinlogCommand::KSET, buf, val_slice);
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("set error: %s", s.ToString().c_str());
		return -1;
	}
    kv_size += key.size() + val.size();
    kv_count ++;
    update_count ++;
	return 1;
}

int SSDBImpl::msetnx(const std::vector<Bytes> &kvs, int offset, char log_type){
	Transaction trans(binlogs);

    uint64_t size = 0;
	std::vector<Bytes>::const_iterator it;
	it = kvs.begin() + offset;
	for(; it != kvs.end(); it += 2){
		const Bytes &key = *it;
		if(key.empty()){
			log_error("empty key!");
			return 0;
		}
        std::string tmp;
        int found = this->get(key, &tmp);
        if(found != 0){
            return 0;
        }
		const Bytes &val = *(it + 1);
		std::string buf = encode_kv_key(key);
        leveldb::Slice val_slice = slice(val);
		binlogs->Put(buf, val_slice);
		binlogs->add_log(log_type, BinlogCommand::KSET, buf, val_slice);
        size += key.size() + val.size();
	}
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("msetnx error: %s", s.ToString().c_str());
		return -1;
	}
    kv_size += size;
    kv_count += (kvs.size() - offset)/2;
    update_count += (kvs.size() - offset)/2; 
	return 1;
}

int SSDBImpl::getset(const Bytes &key, std::string *val, const Bytes &newval, char log_type){
	if(key.empty()){
		log_error("empty key!");
		//return -1;
		return 0;
	}
	Transaction trans(binlogs);

	int found = this->get(key, val);
	std::string buf = encode_kv_key(key);
    leveldb::Slice val_slice = slice(newval);
	binlogs->Put(buf, val_slice);
	binlogs->add_log(log_type, BinlogCommand::KSET, buf, val_slice);
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("set error: %s", s.ToString().c_str());
		return -1;
	}
    kv_size += key.size() + newval.size();
    kv_count ++;
    update_count ++;
	return found;
}


int SSDBImpl::del(const Bytes &key, char log_type){
	Transaction trans(binlogs);

	std::string buf = encode_kv_key(key);
	binlogs->begin();
	binlogs->Delete(buf);
	binlogs->add_log(log_type, BinlogCommand::KDEL, buf, "");
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("del error: %s", s.ToString().c_str());
		return -1;
	}
	return 1;
}

int SSDBImpl::incr(const Bytes &key, int64_t by, int64_t *new_val, char log_type){
	Transaction trans(binlogs);

	std::string old;
	int ret = this->get(key, &old);
	if(ret == -1){
		return -1;
	}else if(ret == 0){
		*new_val = by;
	}else{
		*new_val = str_to_int64(old) + by;
		if(errno != 0){
			return 0;
		}
	}

	std::string buf = encode_kv_key(key);
    std::string new_val_str = str(*new_val);;
	binlogs->Put(buf, new_val_str);
	binlogs->add_log(log_type, BinlogCommand::KSET, buf, new_val_str);

	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("del error: %s", s.ToString().c_str());
		return -1;
	}
    if (ret == 0) {
        kv_size += key.size() + 8;
        kv_count ++;
        update_count ++;
    }
	return 1;
}

int SSDBImpl::get(const Bytes &key, std::string *val){
	std::string buf = encode_kv_key(key);

	leveldb::Status s = db->Get(leveldb::ReadOptions(), buf, val);
	if(s.IsNotFound()){
		return 0;
	}
	if(!s.ok()){
		log_error("get error: %s", s.ToString().c_str());
		return -1;
	}
	return 1;
}

KIterator* SSDBImpl::scan(const Bytes &start, const Bytes &end, uint64_t limit){
	std::string key_start, key_end;
	key_start = encode_kv_key(start);
	if(end.empty()){
		key_end = "";
	}else{
		key_end = encode_kv_key(end);
	}
	//dump(key_start.data(), key_start.size(), "scan.start");
	//dump(key_end.data(), key_end.size(), "scan.end");

	return new KIterator(this->iterator(key_start, key_end, limit));
}

KIterator* SSDBImpl::rscan(const Bytes &start, const Bytes &end, uint64_t limit){
	std::string key_start, key_end;

	key_start = encode_kv_key(start);
	if(start.empty()){
		key_start.append(1, 255);
	}
	if(!end.empty()){
		key_end = encode_kv_key(end);
	}
	//dump(key_start.data(), key_start.size(), "scan.start");
	//dump(key_end.data(), key_end.size(), "scan.end");

	return new KIterator(this->rev_iterator(key_start, key_end, limit));
}

int SSDBImpl::setbit(const Bytes &key, int bitoffset, int on, char log_type){
	if(key.empty()){
		log_error("empty key!");
		return 0;
	}
	Transaction trans(binlogs);
	
	std::string val;
	int ret = this->get(key, &val);
	if(ret == -1){
		return -1;
	}
	
	int len = bitoffset / 8;
	int bit = bitoffset % 8;
	if(len >= val.size()){
		val.resize(len + 1, 0);
	}
	int orig = val[len] & (1 << bit);
	if(on == 1){
		val[len] |= (1 << bit);
	}else{
		val[len] &= ~(1 << bit);
	}

	std::string buf = encode_kv_key(key);
	binlogs->Put(buf, val);
	binlogs->add_log(log_type, BinlogCommand::KSET, buf, val);
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("set error: %s", s.ToString().c_str());
		return -1;
	}
    if (ret == 0) {
        kv_size += key.size() + (bitoffset+8)/8;
        kv_count ++;
        update_count ++;
    }
	return orig;
}

int SSDBImpl::getbit(const Bytes &key, int bitoffset){
	std::string val;
	int ret = this->get(key, &val);
	if(ret == -1){
		return -1;
	}
	
	int len = bitoffset / 8;
	int bit = bitoffset % 8;
	if(len >= val.size()){
		return 0;
	}
	return val[len] & (1 << bit);
}

int SSDBImpl::setrange(const Bytes &key, int offset, const Bytes &val, char log_type){
	if(key.empty()){
		log_error("empty key!");
		return 0;
	}
    // FIXME limit max offset and val.size();
	Transaction trans(binlogs);
	
	std::string sval;
	int ret = this->get(key, &sval);
	if(ret == -1){
		return -1;
	}
	
    int len = offset + val.size();
	if(len > sval.size()){
        // FIXME all right? 
		sval.resize(len, 0);
	}
    sval.replace(offset,val.size(),val.String().c_str());

	std::string buf = encode_kv_key(key);
	binlogs->Put(buf, sval);
	binlogs->add_log(log_type, BinlogCommand::KSET, buf, sval);
	leveldb::Status s = binlogs->commit();
	if(!s.ok()){
		log_error("set error: %s", s.ToString().c_str());
		return -1;
	}
    if (ret == 0) {
        kv_size += offset + val.size();
        kv_count ++;
        update_count ++;
    }
	return len;
}

