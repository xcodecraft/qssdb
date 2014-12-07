/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#ifndef SSDB_BINLOG_H_
#define SSDB_BINLOG_H_

#include <string>
#include "leveldb/db.h"
#include "leveldb/options.h"
#include "leveldb/slice.h"
#include "leveldb/status.h"
#include "leveldb/write_batch.h"
#include "../util/thread.h"
#include "../util/bytes.h"


class Binlog{
private:
	std::string buf;
	std::string val_buf;
	static const unsigned int HEADER_LEN = sizeof(uint64_t) + 2;
    static const char BINLOG_VERSION = 0x81; // 1000 0001
public:
	Binlog(){}
	Binlog(uint64_t seq, char type, char cmd, const leveldb::Slice &key, const leveldb::Slice &val);
		
    // original function is load() 
	int load_format_key(const Bytes &s);
	int load_format_key(const leveldb::Slice &s);
	int load_format_key(const std::string &s);

	int load_log_data(const leveldb::Slice &s);

	uint64_t seq() const;
	char type() const;
	char cmd() const;
	const Bytes key() const;
	const Bytes val() const;

/*
	const char* data() const{
		return buf.data();
	}
	int size() const{
		return (int)buf.size();
	}
	const std::string repr() const{
		return this->buf;
	}
*/
    const std::string format_key() const;
    const std::string log_data() const;  

	std::string dumps() const;
};

// circular queue
class BinlogQueue{
private:
#ifdef NDEBUG
	static const int LOG_QUEUE_SIZE  = 10 * 1000 * 1000;
#else
	static const int LOG_QUEUE_SIZE  = 10000;
#endif
	leveldb::DB *db;
	leveldb::DB *binlog_db;
	uint64_t min_seq;
	uint64_t last_seq;
	uint64_t tran_seq;
	int capacity;
	leveldb::WriteBatch batch;
	leveldb::WriteBatch binlog_batch;

	volatile bool thread_quit;
	static void* log_clean_thread_func(void *arg);
	int del(uint64_t seq);
	// [start, end] includesive
	int del_range(uint64_t start, uint64_t end);
		
	void merge();
	bool enabled;
public:
	Mutex mutex;

	BinlogQueue(leveldb::DB *db, leveldb::DB *binlog_db, bool enabled=true);
	~BinlogQueue();
	void begin();
	void rollback();
	leveldb::Status commit();
	// leveldb put
	void Put(const leveldb::Slice& key, const leveldb::Slice& value);
	// leveldb delete
	void Delete(const leveldb::Slice& key);
	void add_log(char type, char cmd, const leveldb::Slice &key, const leveldb::Slice &val);
	void add_log(char type, char cmd, const std::string &key, const std::string &val);

    void set_enabled(bool enabled);
    bool is_enabled();
    void set_last_seq(uint64_t seq);
		
	int get(uint64_t seq, Binlog *log) const;
	int update(uint64_t seq, char type, char cmd, const std::string &key, const std::string &val);
		
	void flush();
		
	/** @returns
	 1 : log.seq greater than or equal to seq
	 0 : not found
	 -1: error
	 */
	int find_next(uint64_t seq, Binlog *log) const;
	int find_last(Binlog *log) const;
		
	std::string stats() const;
};

class Transaction{
private:
	BinlogQueue *logs;
public:
	Transaction(BinlogQueue *logs){
		this->logs = logs;
		logs->mutex.lock();
		logs->begin();
	}
	
	~Transaction(){
		// it is safe to call rollback after commit
		logs->rollback();
		logs->mutex.unlock();
	}
};


#endif
