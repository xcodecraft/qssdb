/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#ifndef SSDB_SERVER_H_
#define SSDB_SERVER_H_

#include "include.h"
#include <map>
#include <vector>
#include <set>
#include <string>
#include "ssdb/ssdb_impl.h"
#include "ssdb/ttl.h"
#include "backend_dump.h"
#include "backend_sync.h"
#include "slave.h"
#include "net/server.h"


class SSDBServer
{
private:
	void reg_procs(NetworkServer *net);
    int load_kv_stats();

	void start_fsync_thread();
	void stop_fsync_thread();
	static void* backend_fsync(void *arg);

	void start_compact_thread();
	void stop_compact_thread();
	static void* backend_compact(void *arg);
	
	std::string kv_range_s;
	std::string kv_range_e;

	SSDB *meta;

	// for fsync
	volatile bool fsync_thread_quit;
	pthread_t fsync_tid;

	// for compact
	volatile bool compact_thread_quit;
	pthread_t compact_tid;

public:
	SSDBImpl *ssdb;
	BackendDump *backend_dump;
	BackendSync *backend_sync;
	ExpirationHandler *expiration;
	std::vector<Slave *> slaves;
    std::map<std::string,std::string> addrs;
    Config *conf;
    std::string conf_path;

	// for fsync
	int fsync_period;

	// last compact time
	uint64_t last_compact; // second
	int compact_hour_everyday; // hour every day

	std::string role; // master or slave

	SSDBServer(SSDB *ssdb, SSDB *meta, Config *conf, const std::string &conf_path, NetworkServer *net);
	~SSDBServer();

	int set_kv_range(const std::string &s, const std::string &e);
	int get_kv_range(std::string *s, std::string *e);
	bool in_kv_range(const std::string &key);
	bool in_kv_range(const Bytes &key);

	int set_repli_status(const std::string &id, const std::string &last_seq, const std::string &last_key);
	int get_repli_status(const std::string &id, std::string &last_seq, std::string &last_key);
	int get_all_repli_status(std::vector<std::string> &list);

    int save_kv_stats(bool force=false);

    int create_slave(std::string &ip, int port, std::string &type, std::string &id, std::string auth);
    void destroy_all_slaves();
};


#define CHECK_KEY_RANGE(n) do{ \
		if(req.size() > n){ \
			if(!serv->in_kv_range(req[n])){ \
				resp->push_back("out_of_range"); \
				return 0; \
			} \
		} \
	}while(0)

#define CHECK_NUM_PARAMS(n) do{ \
		if(req.size() < n){ \
			resp->push_back("client_error"); \
			resp->push_back("wrong number of arguments"); \
			return 0; \
		} \
	}while(0)

#define CHECK_OUTPUT_LIMIT(size) do{ \
		if(size > net->client_output_limit){ \
            resp->clear(); \
            resp->reply_status(-1, "client output limit"); \
            return 0; \
		} \
	}while(0)

#define CHECK_SCAN_OUTPUT_LIMIT(size) do{ \
		if(size > net->client_output_limit){ \
            resp->clear(); \
            resp->reply_status(-1, "client output limit"); \
            delete it; \
            return 0; \
		} \
	}while(0)

#endif
