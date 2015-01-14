/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
/* zset */
#include "serv.h"
#include "net/proc.h"
#include "net/server.h"

static int proc_join_zsets(NetworkServer *net, Link *link, const Request &req, Response *resp, int type);

int proc_zexists(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	const Bytes &name = req[1];
	const Bytes &key = req[2];
	std::string val;
	int ret = serv->ssdb->zget(name, key, &val);
	resp->reply_bool(ret);
	return 0;
}

int proc_multi_zexists(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	resp->push_back("ok");
	const Bytes &name = req[1];
	std::string val;
	for(Request::const_iterator it=req.begin()+2; it!=req.end(); it++){
		const Bytes &key = *it;
		int64_t ret = serv->ssdb->zget(name, key, &val);
		resp->push_back(key.String());
		if(ret > 0){
			resp->push_back("1");
		}else{
			resp->push_back("0");
		}
	}
	return 0;
}

int proc_multi_zsize(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(2);

	resp->push_back("ok");
	for(Request::const_iterator it=req.begin()+1; it!=req.end(); it++){
		const Bytes &key = *it;
		int64_t ret = serv->ssdb->zsize(key);
		resp->push_back(key.String());
		if(ret == -1){
			resp->push_back("-1");
		}else{
			resp->add(ret);
		}
	}
	return 0;
}

int proc_multi_zset(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	if(req.size() < 4 || req.size() % 2 != 0){
		resp->push_back("client_error");
	}else{
		int num = 0;
		const Bytes &name = req[1];
		std::vector<Bytes>::const_iterator it = req.begin() + 2;
		for(; it != req.end(); it += 2){
			const Bytes &key = *it;
			const Bytes &val = *(it + 1);
			int ret = serv->ssdb->zset(name, key, val);
			if(ret == -1){
				resp->push_back("error");
				return 0;
			}else{
				num += ret;
			}
		}
        serv->save_kv_stats();
		resp->reply_int(0, num);
	}
	return 0;
}

int proc_multi_zdel(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	int num = 0;
	const Bytes &name = req[1];
	std::vector<Bytes>::const_iterator it = req.begin() + 2;
	for(; it != req.end(); it += 1){
		const Bytes &key = *it;
		int ret = serv->ssdb->zdel(name, key);
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

int proc_multi_zget(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	resp->push_back("ok");
	Request::const_iterator it=req.begin() + 1;
	const Bytes name = *it;
	it ++;
	uint64_t size = 0;
	for(; it!=req.end(); it+=1){
		const Bytes &key = *it;
		std::string score;
		int ret = serv->ssdb->zget(name, key, &score);
		if(ret == 1){
			size += key.size() + score.size();
			CHECK_OUTPUT_LIMIT(size);
			resp->push_back(key.String());
			resp->push_back(score);
		}
	}
	return 0;
}

int proc_zset(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	int ret = serv->ssdb->zset(req[1], req[2], req[3]);
    serv->save_kv_stats();
	resp->reply_int(ret, ret);
	return 0;
}

int proc_zsize(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(2);

	int64_t ret = serv->ssdb->zsize(req[1]);
	resp->reply_int(ret, ret);
	return 0;
}

int proc_zget(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	std::string score;
	int ret = serv->ssdb->zget(req[1], req[2], &score);
	resp->reply_get(ret, &score);
	return 0;
}

int proc_zdel(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	int ret = serv->ssdb->zdel(req[1], req[2]);
    serv->save_kv_stats();
	resp->reply_bool(ret);
	return 0;
}

int proc_zrank(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	int64_t ret = serv->ssdb->zrank(req[1], req[2]);
	resp->reply_int(ret, ret);
	return 0;
}

int proc_zrrank(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(3);

	int64_t ret = serv->ssdb->zrrank(req[1], req[2]);
	resp->reply_int(ret, ret);
	return 0;
}

int proc_zrange(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	uint64_t offset = req[2].Uint64();
	uint64_t limit = req[3].Uint64();
	ZIterator *it = serv->ssdb->zrange(req[1], offset, limit);
	resp->push_back("ok");
	uint64_t size = 0;
	while(it->next()){
		size += it->key.size() + it->score.size();
		CHECK_SCAN_OUTPUT_LIMIT(size);
		resp->push_back(it->key);
		resp->push_back(it->score);
	}
	delete it;
	return 0;
}

int proc_zrrange(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	uint64_t offset = req[2].Uint64();
	uint64_t limit = req[3].Uint64();
	ZIterator *it = serv->ssdb->zrrange(req[1], offset, limit);
	resp->push_back("ok");
	uint64_t size = 0;
	while(it->next()){
		size += it->key.size() + it->score.size();
		CHECK_SCAN_OUTPUT_LIMIT(size);
		resp->push_back(it->key);
		resp->push_back(it->score);
	}
	delete it;
	return 0;
}

int proc_zclear(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(2);
	
	const Bytes &name = req[1];
	int64_t count = 0;
	while(1){
		ZIterator *it = serv->ssdb->zrange(name, 0, 1000);
		int num = 0;
		while(it->next()){
			int ret = serv->ssdb->zdel(name, it->key);
			if(ret == -1){
				resp->push_back("error");
				delete it;
				return 0;
			}
			num ++;
		};
		delete it;
		
		if(num == 0){
			break;
		}
		count += num;
	}
    serv->save_kv_stats();
	resp->reply_int(0, count);

	return 0;
}

int proc_zscan(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(6);

	uint64_t limit = req[5].Uint64();
	uint64_t offset = 0;
	if(req.size() > 6){
		offset = limit;
		limit = offset + req[6].Uint64();
	}
	ZIterator *it = serv->ssdb->zscan(req[1], req[2], req[3], req[4], limit);
	if(offset > 0){
		it->skip(offset);
	}
	resp->push_back("ok");
	uint64_t size = 0;
	while(it->next()){
		size += it->key.size() + it->score.size();
		CHECK_SCAN_OUTPUT_LIMIT(size);
		resp->push_back(it->key);
		resp->push_back(it->score);
	}
	delete it;
	return 0;
}

int proc_zrscan(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(6);

	uint64_t limit = req[5].Uint64();
	uint64_t offset = 0;
	if(req.size() > 6){
		offset = limit;
		limit = offset + req[6].Uint64();
	}
	ZIterator *it = serv->ssdb->zrscan(req[1], req[2], req[3], req[4], limit);
	if(offset > 0){
		it->skip(offset);
	}
	resp->push_back("ok");
	uint64_t size = 0;
	while(it->next()){
		size += it->key.size() + it->score.size();
		CHECK_SCAN_OUTPUT_LIMIT(size);
		resp->push_back(it->key);
		resp->push_back(it->score);
	}
	delete it;
	return 0;
}

int proc_redis_zscan(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_redis_scan(net, link, req, resp, REDIS_ZSCAN);
}

int proc_zkeys(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(6);

	uint64_t limit = req[5].Uint64();
	ZIterator *it = serv->ssdb->zscan(req[1], req[2], req[3], req[4], limit);
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

int proc_zlist(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	uint64_t limit = req[3].Uint64();
	std::vector<std::string> list;
	int ret = serv->ssdb->zlist(req[1], req[2], limit, &list);
	resp->reply_list(ret, list);
	return 0;
}

int proc_zrlist(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	uint64_t limit = req[3].Uint64();
	std::vector<std::string> list;
	int ret = serv->ssdb->zrlist(req[1], req[2], limit, &list);
	resp->reply_list(ret, list);
	return 0;
}

// dir := +1|-1
static int _zincr(SSDBServer *serv, const Request &req, Response *resp, int dir){
	CHECK_NUM_PARAMS(3);

	int64_t by = 1;
	if(req.size() > 3){
		by = req[3].Int64();
	}
	int64_t new_val;
	int ret = serv->ssdb->zincr(req[1], req[2], dir * by, &new_val);
    serv->save_kv_stats();
	resp->reply_int(ret, new_val);
	return 0;
}

int proc_zincr(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	return _zincr(serv, req, resp, 1);
}

int proc_zdecr(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	return _zincr(serv, req, resp, -1);
}

int proc_zcount(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	int64_t count = 0;
	ZIterator *it = serv->ssdb->zscan(req[1], "", req[2], req[3], -1);
	while(it->next()){
		count ++;
	}
	delete it;
	
	resp->reply_int(0, count);
	return 0;
}

int proc_zsum(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	int64_t sum = 0;
	ZIterator *it = serv->ssdb->zscan(req[1], "", req[2], req[3], -1);
	while(it->next()){
		sum += str_to_int64(it->score);
	}
	delete it;
	
	resp->reply_int(0, sum);
	return 0;
}

int proc_zavg(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	int64_t sum = 0;
	int64_t count = 0;
	ZIterator *it = serv->ssdb->zscan(req[1], "", req[2], req[3], -1);
	while(it->next()){
		sum += str_to_int64(it->score);
		count ++;
	}
	delete it;
	double avg = (double)sum/count;
	
	resp->push_back("ok");
	resp->add(avg);
	return 0;
}

int proc_zremrangebyscore(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	ZIterator *it = serv->ssdb->zscan(req[1], "", req[2], req[3], -1);
	int64_t count = 0;
	while(it->next()){
		count ++;
		int ret = serv->ssdb->zdel(req[1], it->key);
		if(ret == -1){
			delete it;
			resp->push_back("error");
			return 0;
		}
	}
	delete it;
	
    serv->save_kv_stats();
	resp->reply_int(0, count);
	return 0;
}

int proc_zremrangebyrank(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(4);

	uint64_t start = req[2].Uint64();
	uint64_t end = req[3].Uint64();
	ZIterator *it = serv->ssdb->zrange(req[1], start, end - start + 1);
	int64_t count = 0;
	while(it->next()){
		count ++;
		int ret = serv->ssdb->zdel(req[1], it->key);
		if(ret == -1){
			resp->push_back("error");
			delete it;
			return 0;
		}
	}
	delete it;
	
    serv->save_kv_stats();
	resp->reply_int(0, count);
	return 0;
}

int proc_zinterstore(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_zsets(net, link, req, resp, INTER_TYPE);
}

int proc_zunionstore(NetworkServer *net, Link *link, const Request &req, Response *resp){
    return proc_join_zsets(net, link, req, resp, UNION_TYPE);
}

/*
 * ZUNIONSTORE destination numkeys key [key ...] [WEIGHTS weight [weight ...]] [AGGREGATE SUM|MIN|MAX]
 */
static int proc_join_zsets(NetworkServer *net, Link *link, const Request &req, Response *resp, int type){
    int offset = 3;
	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(offset);

    int numkeys = req[2].Int();
    int size = numkeys + offset;
    if (numkeys <= 0 || req.size() < size) {
		resp->reply_client_error("wrong number of arguments"); 
        return 0;
    }
    
    std::vector<int> weights;
    int aggregate_type = AGGREGATE_SUM_TYPE;

    for (int i = size; i < req.size();) {
        if (req[i] == "weights") {
            CHECK_NUM_PARAMS(i + 1 + numkeys);
            for (int j = 1; j <= numkeys; j ++) {
                weights.push_back(req[i + j].Int());
            }
            i += numkeys + 1;
        } else if (req[i] == "aggregate") {
            CHECK_NUM_PARAMS(i + 2);
            if (req[i+1] == "sum") {
                aggregate_type = AGGREGATE_SUM_TYPE;
            } else if (req[i+1] == "min") {
                aggregate_type = AGGREGATE_MIN_TYPE;
            } else if (req[i+1] == "max") {
                aggregate_type = AGGREGATE_MAX_TYPE;
            } else {
                resp->reply_client_error("wrong format of arguments"); 
                return 0;
            }
            i += 2;
        } else {
            resp->reply_client_error("wrong format of arguments"); 
            return 0;
        }
    }

    if (weights.empty()) {
        for (int i = 0; i < numkeys; i ++) {
            weights.push_back(1);
        }
    }

    int min_len = -1, min_index = 0;
    std::vector< std::map<std::string,int64_t> > vectors; 
    for (int i = offset; i < offset + numkeys; i ++) {
        std::map<std::string,int64_t> key_scores;
        // FIXME 控制大小,防止内存爆掉
	    ZIterator *it = serv->ssdb->zscan(req[i], "", "", "", SSDB_MAX_SCAN_LEN);
        while(it->next()){
            int64_t score = str_to_int64(it->score) * weights[i-offset];
            key_scores[it->key] = score;
        }
	    delete it;
        if (key_scores.size() == 0 && type == INTER_TYPE) {
            resp->reply_int(0, 0);
            return 0;
        }
        vectors.push_back(key_scores);
        if (min_len == -1 || min_len > key_scores.size()) {
            min_len = key_scores.size();
            min_index = i - offset;
        }
    }

    std::map<std::string,int64_t> result;
    if (type == INTER_TYPE) {
        result = vectors[min_index]; // copy sets
        for (std::map<std::string,int64_t>::iterator it = vectors[min_index].begin(); it != vectors[min_index].end(); it ++) {
            std::string key = it->first;
            int64_t score = it->second;
            for (int i = 0; i < vectors.size(); i ++) {
                if (i == min_index) {
                    continue;
                }
                std::map<std::string,int64_t>::iterator fit = vectors[i].find(key);
                if (fit == vectors[i].end()){
                    // remove
                    result.erase(key);
                    break;
                } else {
                    if (aggregate_type == AGGREGATE_MIN_TYPE) {
                        result[key] = score < fit->second ?  score : fit->second;
                    } else if (aggregate_type == AGGREGATE_MAX_TYPE) {
                        result[key] = score > fit->second ? score : fit->second;
                    } else {
                        result[key] = score + fit->second;
                    }
                }
           }
        }
    } else if (type == UNION_TYPE) {
        for (int i = 0; i < vectors.size(); i ++) {
            for (std::map<std::string,int64_t>::iterator it = vectors[i].begin(); it != vectors[i].end(); it ++) {
                std::string key = it->first;
                int64_t score = it->second;
                
                std::map<std::string,int64_t>::iterator rit = result.find(key);

                if (rit == result.end()) { // not found
                    result[key] = score;
                } else {
                    if (aggregate_type == AGGREGATE_MIN_TYPE) {
                        rit->second = score < rit->second ?  score : rit->second;
                    } else if (aggregate_type == AGGREGATE_MAX_TYPE) {
                        rit->second = score > rit->second ?  score : rit->second;
                    } else {
                        rit->second = score + rit->second;
                    }
                }
            }
        }
    }

    for(std::map<std::string,int64_t>::iterator it = result.begin(); it != result.end(); it ++) {
        int ret = serv->ssdb->zset(req[1], it->first, str(it->second));
        if(ret == -1){
            resp->push_back("error");
            return 0;
        }
    }
    serv->save_kv_stats();
    resp->reply_int(0, result.size());
	return 0;
} 
