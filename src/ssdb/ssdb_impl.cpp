/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "ssdb_impl.h"
#include "leveldb/env.h"
#include "leveldb/iterator.h"
#include "leveldb/cache.h"
#include "leveldb/filter_policy.h"

#include "iterator.h"
#include "t_kv.h"
#include "t_hash.h"
#include "t_zset.h"
#include "t_queue.h"

SSDBImpl::SSDBImpl(){
	db = NULL;
    binlog_db = NULL;
	binlogs = NULL;
}

SSDBImpl::~SSDBImpl(){
	if(binlogs){
		delete binlogs;
	}
	if(db){
		delete db;
	}
	if(binlog_db){
		delete binlog_db;
	}
	if(options.block_cache){
		delete options.block_cache;
	}
	if(options.filter_policy){
		delete options.filter_policy;
	}
	if(binlog_options.block_cache){
		delete binlog_options.block_cache;
	}
	if(binlog_options.filter_policy){
		delete binlog_options.filter_policy;
	}
}

SSDB* SSDB::open(const Options &opt, const std::string &dir){
	SSDBImpl *ssdb = new SSDBImpl();
	ssdb->options.create_if_missing = true;
	ssdb->options.max_open_files = opt.max_open_files;
	ssdb->options.filter_policy = leveldb::NewBloomFilterPolicy(10);
	ssdb->options.block_cache = leveldb::NewLRUCache(opt.cache_size * 1048576);
	ssdb->options.block_size = opt.block_size * 1024;
	ssdb->options.write_buffer_size = opt.write_buffer_size * 1024 * 1024;
	ssdb->options.compaction_speed = opt.compaction_speed;
	if(opt.compression == "yes"){
		ssdb->options.compression = leveldb::kSnappyCompression;
	}else{
		ssdb->options.compression = leveldb::kNoCompression;
	}

	leveldb::Status status;

	status = leveldb::DB::Open(ssdb->options, dir, &ssdb->db);
	if(!status.ok()){
		log_error("open db %s failed", dir.c_str());
		goto err;
	}
    
    if (opt.binlog) { // open binlog_db
        std::string binlog_dir;
        int size = dir.size();
        while(size > 0) {
            if (dir.at(size - 1) != '/') {
                break;
            }
            size --;
        }
        binlog_dir.append(dir.substr(0, size));
        binlog_dir.append("_binlog"); 

        ssdb->binlog_options.create_if_missing = true;
        ssdb->binlog_options.compression = leveldb::kSnappyCompression; // default compression
        ssdb->binlog_options.compaction_speed = ssdb->options.compaction_speed;   
        ssdb->binlog_options.max_open_files = ssdb->options.max_open_files > 50 ? 50 : ssdb->options.max_open_files; // max open 50 files for binlog
        ssdb->binlog_options.block_cache = leveldb::NewLRUCache(10 * 1048576); // 10MB LRU cache
        ssdb->binlog_options.block_size = ssdb->options.block_size;
        ssdb->binlog_options.write_buffer_size = ssdb->options.write_buffer_size;
        status = leveldb::DB::Open(ssdb->binlog_options, binlog_dir, &ssdb->binlog_db);
        if(!status.ok()){
            log_error("open db %s failed", binlog_dir.c_str());
            goto err;
        }
    }

	ssdb->binlogs = new BinlogQueue(ssdb->db, ssdb->binlog_db, opt.binlog_capacity, opt.binlog);

	return ssdb;
err:
	if(ssdb){
		delete ssdb;
	}
	return NULL;
}

Iterator* SSDBImpl::iterator(const std::string &start, const std::string &end, uint64_t limit){
	leveldb::Iterator *it;
	leveldb::ReadOptions iterate_options;
	iterate_options.fill_cache = false;
	it = db->NewIterator(iterate_options);
	it->Seek(start);
	if(it->Valid() && it->key() == start){
		it->Next();
	}
	return new Iterator(it, end, limit);
}

Iterator* SSDBImpl::rev_iterator(const std::string &start, const std::string &end, uint64_t limit){
	leveldb::Iterator *it;
	leveldb::ReadOptions iterate_options;
	iterate_options.fill_cache = false;
	it = db->NewIterator(iterate_options);
	it->Seek(start);
	if(!it->Valid()){
		it->SeekToLast();
	}else{
		it->Prev();
	}
	return new Iterator(it, end, limit, Iterator::BACKWARD);
}

/* raw operates */

int SSDBImpl::raw_set(const Bytes &key, const Bytes &val){
	leveldb::WriteOptions write_opts;
	leveldb::Status s = db->Put(write_opts, slice(key), slice(val));
	if(!s.ok()){
		log_error("set error: %s", s.ToString().c_str());
		return -1;
	}
	return 1;
}

int SSDBImpl::raw_del(const Bytes &key){
	leveldb::WriteOptions write_opts;
	leveldb::Status s = db->Delete(write_opts, slice(key));
	if(!s.ok()){
		log_error("del error: %s", s.ToString().c_str());
		return -1;
	}
	return 1;
}

int SSDBImpl::raw_get(const Bytes &key, std::string *val){
	leveldb::ReadOptions opts;
	opts.fill_cache = false;
	leveldb::Status s = db->Get(opts, slice(key), val);
	if(s.IsNotFound()){
		return 0;
	}
	if(!s.ok()){
		log_error("get error: %s", s.ToString().c_str());
		return -1;
	}
	return 1;
}

uint64_t SSDBImpl::size(std::string start, std::string end){
	return this->db_size(db, start, end);
}

uint64_t SSDBImpl::binlog_size(std::string start, std::string end){
	if (binlog_db == NULL) {
        return 0;
	}

	return this->db_size(binlog_db, start, end);
}

uint64_t SSDBImpl::db_size(leveldb::DB *db, std::string start, std::string end){
	std::string s = "A";
	std::string e(1, 'z' + 1);
    if (!start.empty()) {
        s = start;
    }
    if (!end.empty()) {
        e = end;
    }
	leveldb::Range ranges[1];
	ranges[0] = leveldb::Range(s, e);
	uint64_t sizes[1];
	db->GetApproximateSizes(ranges, 1, sizes);
	return sizes[0];
}

std::vector<std::string> SSDBImpl::info(){
	//  "leveldb.num-files-at-level<N>" - return the number of files at level <N>,
	//     where <N> is an ASCII representation of a level number (e.g. "0").
	//  "leveldb.stats" - returns a multi-line string that describes statistics
	//     about the internal operation of the DB.
	//  "leveldb.sstables" - returns a multi-line string that describes all
	//     of the sstables that make up the db contents.
	std::vector<std::string> info;
	std::vector<std::string> keys;
	/*
	for(int i=0; i<7; i++){
		char buf[128];
		snprintf(buf, sizeof(buf), "leveldb.num-files-at-level%d", i);
		keys.push_back(buf);
	}
	*/
	keys.push_back("leveldb.stats");
	//keys.push_back("leveldb.sstables");

	for(size_t i=0; i<keys.size(); i++){
		std::string key = keys[i];
		std::string val;
		if(db->GetProperty(key, &val)){
			info.push_back(key);
			info.push_back(val);
		}
	}

	if(binlog_db) {
        info.push_back("# binlog");
        for(size_t i=0; i<keys.size(); i++){
            std::string key = keys[i];
            std::string val;
            if(binlog_db->GetProperty(key, &val)){
                info.push_back(key);
                info.push_back(val);
            }
        }
	}
	return info;
}

void SSDBImpl::compact(){
	db->CompactRange(NULL, NULL);
	if (binlog_db) {
	    binlog_db->CompactRange(NULL, NULL);
	}
}

int SSDBImpl::key_range(std::vector<std::string> *keys){
	int ret = 0;
	std::string kstart, kend;
	std::string hstart, hend;
	std::string zstart, zend;
	std::string qstart, qend;
	
	Iterator *it;
	
	it = this->iterator(encode_kv_key(""), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::KV){
			std::string n;
			if(decode_kv_key(ks, &n) == -1){
				ret = -1;
			}else{
				kstart = n;
			}
		}
	}
	delete it;
	
	it = this->rev_iterator(encode_kv_key("\xff"), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::KV){
			std::string n;
			if(decode_kv_key(ks, &n) == -1){
				ret = -1;
			}else{
				kend = n;
			}
		}
	}
	delete it;
	
	it = this->iterator(encode_hsize_key(""), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::HSIZE){
			std::string n;
			if(decode_hsize_key(ks, &n) == -1){
				ret = -1;
			}else{
				hstart = n;
			}
		}
	}
	delete it;
	
	it = this->rev_iterator(encode_hsize_key("\xff"), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::HSIZE){
			std::string n;
			if(decode_hsize_key(ks, &n) == -1){
				ret = -1;
			}else{
				hend = n;
			}
		}
	}
	delete it;
	
	it = this->iterator(encode_zsize_key(""), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::ZSIZE){
			std::string n;
			if(decode_hsize_key(ks, &n) == -1){
				ret = -1;
			}else{
				zstart = n;
			}
		}
	}
	delete it;
	
	it = this->rev_iterator(encode_zsize_key("\xff"), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::ZSIZE){
			std::string n;
			if(decode_hsize_key(ks, &n) == -1){
				ret = -1;
			}else{
				zend = n;
			}
		}
	}
	delete it;
	
	it = this->iterator(encode_qsize_key(""), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::QSIZE){
			std::string n;
			if(decode_qsize_key(ks, &n) == -1){
				ret = -1;
			}else{
				qstart = n;
			}
		}
	}
	delete it;
	
	it = this->rev_iterator(encode_qsize_key("\xff"), "", 1);
	if(it->next()){
		Bytes ks = it->key();
		if(ks.data()[0] == DataType::QSIZE){
			std::string n;
			if(decode_qsize_key(ks, &n) == -1){
				ret = -1;
			}else{
				qend = n;
			}
		}
	}
	delete it;

	keys->push_back(kstart);
	keys->push_back(kend);
	keys->push_back(hstart);
	keys->push_back(hend);
	keys->push_back(zstart);
	keys->push_back(zend);
	keys->push_back(qstart);
	keys->push_back(qend);
	
	return ret;
}

int SSDBImpl::fsync(){
	leveldb::WriteOptions write_opts;
	write_opts.sync = true;

	// fsync db and binlog
	leveldb::Status s = db->Delete(write_opts, FSYNC_KEY);
	if(!s.ok()){
		log_error("fsync data error: %s", s.ToString().c_str());
		return -1;
	}
	if (binlog_db) {
        s = binlog_db->Delete(write_opts, FSYNC_KEY);
        if(!s.ok()){
            log_error("fsync binlog error: %s", s.ToString().c_str());
            return -1;
        }
	}
    
	return 1;
}

BinlogQueue *SSDBImpl::get_binlogs() {
    return binlogs;
}
