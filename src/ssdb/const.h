/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#ifndef SSDB_CONST_H_
#define SSDB_CONST_H_

static const int SSDB_SCORE_WIDTH		= 9;
static const int SSDB_KEY_LEN_MAX		= 255;

static const int SSDB_MAX_SCAN_LEN		= 2000000000;

static const int INTER_TYPE             = 1;
static const int UNION_TYPE             = 2;
static const int DIFF_TYPE              = 3;

static const int AGGREGATE_SUM_TYPE     = 1;
static const int AGGREGATE_MIN_TYPE     = 2;
static const int AGGREGATE_MAX_TYPE     = 3;

static const int MIN_LEVELDB_SIZE       = 174;

static const std::string SLAVE_STATUS_PREFIX = "slave.status.";
static const std::string SLAVE_STATUS_RANGE_END = "slave.statut.";

static const std::string FSYNC_KEY = "SSDB.KEY.FOR.FSYNC.DATA.AND.BINLOG";

// node type
static const std::string ROLE_MASTER = "master";
static const std::string ROLE_SLAVE = "slave";

class DataType{
public:
	static const char SYNCLOG	= 1;
	static const char KV		= 'k';
	static const char HASH		= 'h'; // hashmap(sorted by key)
	static const char HSIZE		= 'H';
	static const char ZSET		= 's'; // key => score
	static const char ZSCORE	= 'z'; // key|score => ""
	static const char ZSIZE		= 'Z';
	static const char QUEUE		= 'q';
	static const char QSIZE		= 'Q';
	static const char MIN_PREFIX = HASH;
	static const char MAX_PREFIX = ZSET;
};

class BinlogType{
public:
	static const char NOOP		= 0;
	static const char SYNC		= 1;
	static const char MIRROR	= 2;
	static const char COPY		= 3;
};

class BinlogCommand{
public:
	static const char NONE  = 0;
	static const char KSET  = 1;
	static const char KDEL  = 2;
	static const char HSET  = 3;
	static const char HDEL  = 4;
	static const char ZSET  = 5;
	static const char ZDEL  = 6;

	static const char QPUSH_BACK	= 10;
	static const char QPUSH_FRONT	= 11;
	static const char QPOP_BACK		= 12;
	static const char QPOP_FRONT	= 13;
	static const char QSET			= 14;
	
	static const char BEGIN  = 7;
	static const char END    = 8;
};

#endif
