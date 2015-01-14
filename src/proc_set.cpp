/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
/* hash */
#include "serv.h"
#include "net/proc.h"
#include "net/server.h"

static int proc_join_sets(NetworkServer *net, Link *link, const Request &req, Response *resp, int type);
static int proc_join_sets_store(NetworkServer *net, Link *link, const Request &req, Response *resp, int type);
static int proc_join_sets(SSDBServer *serv, const Request &req, int offset, std::set<std::string> *result, int type);

int proc_sadd(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(3);
	SSDBServer *serv = (SSDBServer *)net->data;

    int num = 0;
    const Bytes &name = req[1];
    std::vector<Bytes>::const_iterator it = req.begin() + 2;
    for(; it != req.end(); it += 1){
        const Bytes &key = *it;
        int ret = serv->ssdb->hset(name, key, "");
        if(ret == -1){
            resp->push_back("error");
            return 0;
        } else{
            num += ret;
        }
    }
    serv->save_kv_stats();
    resp->reply_int(0, num);
	return 0;
}

int proc_sismember(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(3);
	SSDBServer *serv = (SSDBServer *)net->data;

	const Bytes &name = req[1];
	const Bytes &member = req[2];
	std::string val;
	int ret = serv->ssdb->hget(name, member, &val);
	resp->reply_bool(ret);
	return 0;
}

int proc_srem(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(3);
	SSDBServer *serv = (SSDBServer *)net->data;

	int num = 0;
	const Bytes &name = req[1];
	std::vector<Bytes>::const_iterator it = req.begin() + 2;
	for(; it != req.end(); it += 1){
		const Bytes &key = *it;
		int ret = serv->ssdb->hdel(name, key);
		if(ret == -1){
			resp->push_back("error");
			return 0;
		}else{
			num += ret;
		}
	}
    serv->save_kv_stats();
	resp->reply_int(0, num);
	return 0;
}

int proc_scard(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(2);
	SSDBServer *serv = (SSDBServer *)net->data;

	int64_t ret = serv->ssdb->hsize(req[1]);
	resp->reply_int(ret, ret);
	return 0;
}

int proc_smembers(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(2);
	SSDBServer *serv = (SSDBServer *)net->data;

	HIterator *it = serv->ssdb->hscan(req[1], "", "", SSDB_MAX_SCAN_LEN);
	resp->push_back("ok");
	uint64_t size = 0;
	while(it->next()){
		size += it->key.size();
		CHECK_SCAN_OUTPUT_LIMIT(size);
		resp->push_back(it->key);
	}
	delete it;
	return 0;
}

int proc_smove(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(4);
	SSDBServer *serv = (SSDBServer *)net->data;

    const Bytes &source = req[1];
    const Bytes &dest = req[2];
    const Bytes &member = req[3];

    int ret = serv->ssdb->smove(source, dest, member);

    if(ret == -1){
        resp->push_back("error");
        return 0;
    }
    serv->save_kv_stats();
    resp->reply_int(0, ret);
	return 0;
}

int proc_redis_sscan(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_redis_scan(net, link, req, resp, REDIS_SSCAN);
}

int proc_sinter(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_sets(net, link, req, resp, INTER_TYPE);
}

int proc_sinterstore(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_sets_store(net, link, req, resp, INTER_TYPE);
}

int proc_sunion(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_sets(net, link, req, resp, UNION_TYPE);
}

int proc_sunionstore(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_sets_store(net, link, req, resp, UNION_TYPE);
}

int proc_sdiff(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_sets(net, link, req, resp, DIFF_TYPE);
}

int proc_sdiffstore(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_sets_store(net, link, req, resp, DIFF_TYPE);
}

static int proc_join_sets(NetworkServer *net, Link *link, const Request &req, Response *resp, int type){
	CHECK_NUM_PARAMS(2);
	SSDBServer *serv = (SSDBServer *)net->data;

    std::set<std::string> result;
    int ret = proc_join_sets(serv, req, 1, &result, type);
    
	resp->push_back("ok");
    for(std::set<std::string>::iterator it = result.begin(); it != result.end(); it ++) {
        resp->push_back(*it);
    }
    return ret;
}

static int proc_join_sets_store(NetworkServer *net, Link *link, const Request &req, Response *resp, int type){
	CHECK_NUM_PARAMS(3);
	SSDBServer *serv = (SSDBServer *)net->data;

    std::set<std::string> result;
    int ret = proc_join_sets(serv, req, 2, &result, type);
    
    for(std::set<std::string>::iterator it = result.begin(); it != result.end(); it ++) {
        int ret = serv->ssdb->hset(req[1], *it, "");
        if(ret == -1){
            resp->push_back("error");
            return 0;
        }
    }
    serv->save_kv_stats();
    resp->reply_int(0, result.size());
    return ret;
}

static int proc_join_sets(SSDBServer *serv, const Request &req, int offset, std::set<std::string> *result, int type){
    int min_len = -1, min_index = 0;
    std::vector< std::set<std::string> > vectors; // FIXME 内部实现是如何，这个内存量比较大的时候是否会有内存问题？
    for (int i = offset; i < req.size(); i ++) {
        std::set<std::string> keys;
        // FIXME 控制大小,防止内存爆掉
	    HIterator *it = serv->ssdb->hscan(req[i], "", "", SSDB_MAX_SCAN_LEN);
        while(it->next()){
            keys.insert(it->key);
        }
	    delete it;
        if (keys.size() == 0) {
            if (type == INTER_TYPE) {
                return 0;
            } else if (i == 1 && type == DIFF_TYPE) {
                return 0;
            }
        }
        vectors.push_back(keys);
        if (min_len == -1 || min_len > keys.size()) {
            min_len = keys.size();
            min_index = i - offset;
        }
    }

    if (type == INTER_TYPE) {
        *result = vectors[min_index]; // copy sets
        for (std::set<std::string>::iterator it = vectors[min_index].begin(); it != vectors[min_index].end(); it ++) {
            std::string key = *it;
            for (int i = 0; i < vectors.size(); i ++) {
                if (i == min_index) {
                    continue;
                }
                if (vectors[i].find(key) == vectors[i].end()){
                    // remove
                    result->erase(key);
                    if(result->empty()) {
                        return 0;
                    }
                    break;
                }
           }
        }
    } else if (type == UNION_TYPE) {
        for (int i = 0; i < vectors.size(); i ++) {
            for (std::set<std::string>::iterator it = vectors[i].begin(); it != vectors[i].end(); it ++) {
                result->insert(*it);
            }
        }
    } else if (type == DIFF_TYPE) {
        *result = vectors[0]; // copy first sets
        
        for (int i = 1; i < vectors.size(); i ++) { // O(n * log(m)) 的复杂度，其中m是first key的数据大小
            for (std::set<std::string>::iterator it = vectors[i].begin(); it != vectors[i].end(); it ++) {
                std::string key = *it;
                if (result->find(key) != result->end()){
                    result->erase(key);
                    if(result->empty()) {
                        return 0;
                    }
                }
            }
        }
    }
	return 0;
}

