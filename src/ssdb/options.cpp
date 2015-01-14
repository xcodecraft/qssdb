/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "options.h"
#include "const.h"
#include "../util/strings.h"

Options::Options(){
	Config c;
	this->load(c);
}

void Options::load(const Config &conf){
	cache_size = (size_t)conf.get_num("leveldb.cache_size");
	max_open_files = (size_t)conf.get_num("leveldb.max_open_files");
	write_buffer_size = (size_t)conf.get_num("leveldb.write_buffer_size");
	block_size = (size_t)conf.get_num("leveldb.block_size");
	compaction_speed = conf.get_num("leveldb.compaction_speed");
	compression = conf.get_str("leveldb.compression");
	std::string binlog = conf.get_str("replication.binlog");
	binlog_capacity = conf.get_num("replication.binlog_capacity");

	strtolower(&compression);
	if(compression != "no"){
		compression = "yes";
	}
	strtolower(&binlog);
	if(binlog != "no"){ // default is yes
		this->binlog = true;
	}else{
		this->binlog = false;
	}

	if(cache_size <= 0){
		cache_size = CONFIG_LEVELDB_CACHE_SIZE;
	}
	if(write_buffer_size <= 0){
		write_buffer_size = CONFIG_LEVELDB_WRITE_BUFFER_SIZE;
	}
	if(block_size <= 0){
		block_size = CONFIG_LEVELDB_BLOCK_SIZE;
	}
	if(max_open_files <= 0){
		max_open_files = cache_size / 1024 * 30;
		if(max_open_files < 100){
			max_open_files = 100;
		}
		if(max_open_files > 1000){
			max_open_files = 1000;
		}
	}
    if (binlog_capacity <= 0) {
        binlog_capacity = CONFIG_BINLOG_CAPACITY;
    }
}
