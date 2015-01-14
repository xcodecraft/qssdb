/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "version.h"
#include "util/log.h"
#include "util/strings.h"
#include "serv.h"
#include "net/proc.h"
#include "net/server.h"
#include "./util/ip_filter.h"

static size_t memory_used();

DEF_PROC(get);
DEF_PROC(set);
DEF_PROC(setx);
DEF_PROC(setnx);
DEF_PROC(msetnx);
DEF_PROC(getset);
DEF_PROC(getbit);
DEF_PROC(setbit);
DEF_PROC(countbit);
DEF_PROC(substr);
DEF_PROC(getrange);
DEF_PROC(setrange);
DEF_PROC(strlen);
DEF_PROC(redis_bitcount);
DEF_PROC(del);
DEF_PROC(incr);
DEF_PROC(decr);
DEF_PROC(scan);
DEF_PROC(rscan);
DEF_PROC(redis_scan);
DEF_PROC(keys);
DEF_PROC(exists);
DEF_PROC(multi_exists);
DEF_PROC(multi_get);
DEF_PROC(multi_set);
DEF_PROC(multi_del);

DEF_PROC(hsize);
DEF_PROC(hget);
DEF_PROC(hset);
DEF_PROC(hdel);
DEF_PROC(hincr);
DEF_PROC(hdecr);
DEF_PROC(hclear);
DEF_PROC(hgetall);
DEF_PROC(hscan);
DEF_PROC(hrscan);
DEF_PROC(redis_hscan);
DEF_PROC(hkeys);
DEF_PROC(hvals);
DEF_PROC(hlist);
DEF_PROC(hrlist);
DEF_PROC(hexists);
DEF_PROC(multi_hexists);
DEF_PROC(multi_hsize);
DEF_PROC(multi_hget);
DEF_PROC(multi_hset);
DEF_PROC(multi_hdel);

DEF_PROC(zrank);
DEF_PROC(zrrank);
DEF_PROC(zrange);
DEF_PROC(zrrange);
DEF_PROC(zsize);
DEF_PROC(zget);
DEF_PROC(zset);
DEF_PROC(zdel);
DEF_PROC(zincr);
DEF_PROC(zdecr);
DEF_PROC(zclear);
DEF_PROC(zscan);
DEF_PROC(zrscan);
DEF_PROC(redis_zscan);
DEF_PROC(zkeys);
DEF_PROC(zlist);
DEF_PROC(zrlist);
DEF_PROC(zcount);
DEF_PROC(zsum);
DEF_PROC(zavg);
DEF_PROC(zexists);
DEF_PROC(zremrangebyrank);
DEF_PROC(zremrangebyscore);
DEF_PROC(multi_zexists);
DEF_PROC(multi_zsize);
DEF_PROC(multi_zget);
DEF_PROC(multi_zset);
DEF_PROC(multi_zdel);
DEF_PROC(zinterstore);
DEF_PROC(zunionstore);
	
DEF_PROC(qsize);
DEF_PROC(qfront);
DEF_PROC(qback);
DEF_PROC(qpush);
DEF_PROC(qpush_front);
DEF_PROC(qpush_back);
DEF_PROC(qpushx_front);
DEF_PROC(qpushx_back);
DEF_PROC(qpop);
DEF_PROC(qpop_front);
DEF_PROC(qpop_back);
DEF_PROC(qbpop_fpush);
DEF_PROC(qtrim_front);
DEF_PROC(qtrim_back);
DEF_PROC(qfix);
DEF_PROC(qclear);
DEF_PROC(qlist);
DEF_PROC(qrlist);
DEF_PROC(qslice);
DEF_PROC(qrange);
DEF_PROC(qget);
DEF_PROC(qset);

DEF_PROC(sadd);
DEF_PROC(sismember);
DEF_PROC(srem);
DEF_PROC(scard);
DEF_PROC(smembers);
DEF_PROC(smove);
DEF_PROC(redis_sscan);
DEF_PROC(sinter);
DEF_PROC(sinterstore);
DEF_PROC(sunion);
DEF_PROC(sunionstore);
DEF_PROC(sdiff);
DEF_PROC(sdiffstore);

DEF_PROC(dump);
DEF_PROC(sync140);
DEF_PROC(info);
DEF_PROC(dbsize);
DEF_PROC(compact);
DEF_PROC(key_range);
DEF_PROC(get_key_range);
DEF_PROC(set_key_range);
DEF_PROC(ttl);
DEF_PROC(expire);
DEF_PROC(clear_binlog);
DEF_PROC(slaveof);
DEF_PROC(client);
DEF_PROC(config);

DEF_PROC(repli);


#define PROC(c, f)     net->proc_map.set_proc(#c, f, proc_##c)

void SSDBServer::reg_procs(NetworkServer *net){
	PROC(get, "rt");
	PROC(set, "wt");
	PROC(del, "wt");
	PROC(setx, "wt");
	PROC(setnx, "wt");
	PROC(msetnx, "wt");
	PROC(getset, "wt");
	PROC(getbit, "rt");
	PROC(setbit, "wt");
	PROC(countbit, "rt");
	PROC(substr, "rt");
	PROC(getrange, "rt");
	PROC(setrange, "wt");
	PROC(strlen, "rt");
	PROC(redis_bitcount, "rt");
	PROC(incr, "wt");
	PROC(decr, "wt");
	PROC(scan, "rt");
	PROC(rscan, "rt");
	PROC(redis_scan, "rt");
	PROC(keys, "rt");
	PROC(exists, "rt");
	PROC(multi_exists, "rt");
	PROC(multi_get, "rt");
	PROC(multi_set, "wt");
	PROC(multi_del, "wt");

	PROC(hsize, "rt");
	PROC(hget, "rt");
	PROC(hset, "wt");
	PROC(hdel, "wt");
	PROC(hincr, "wt");
	PROC(hdecr, "wt");
	PROC(hclear, "wt");
	PROC(hgetall, "rt");
	PROC(hscan, "rt");
	PROC(hrscan, "rt");
	PROC(redis_hscan, "rt");
	PROC(hkeys, "rt");
	PROC(hvals, "rt");
	PROC(hlist, "rt");
	PROC(hrlist, "rt");
	PROC(hexists, "rt");
	PROC(multi_hexists, "rt");
	PROC(multi_hsize, "rt");
	PROC(multi_hget, "rt");
	PROC(multi_hset, "wt");
	PROC(multi_hdel, "wt");

	// because zrank may be extremly slow, execute in a seperate thread
	PROC(zrank, "rt");
	PROC(zrrank, "rt");
	PROC(zrange, "rt");
	PROC(zrrange, "rt");
	PROC(zsize, "rt");
	PROC(zget, "rt");
	PROC(zset, "wt");
	PROC(zdel, "wt");
	PROC(zincr, "wt");
	PROC(zdecr, "wt");
	PROC(zclear, "wt");
	PROC(zscan, "rt");
	PROC(zrscan, "rt");
	PROC(redis_zscan, "rt");
	PROC(zkeys, "rt");
	PROC(zlist, "rt");
	PROC(zrlist, "rt");
	PROC(zcount, "rt");
	PROC(zsum, "rt");
	PROC(zavg, "rt");
	PROC(zremrangebyrank, "wt");
	PROC(zremrangebyscore, "wt");
	PROC(zexists, "rt");
	PROC(multi_zexists, "rt");
	PROC(multi_zsize, "rt");
	PROC(multi_zget, "rt");
	PROC(multi_zset, "wt");
	PROC(multi_zdel, "wt");
	PROC(zinterstore, "wt");
	PROC(zunionstore, "wt");

	PROC(qsize, "rt");
	PROC(qfront, "rt");
	PROC(qback, "rt");
	PROC(qpush, "wt");
	PROC(qpush_front, "wt");
	PROC(qpush_back, "wt");
	PROC(qpushx_front, "wt");
	PROC(qpushx_back, "wt");
	PROC(qpop, "wt");
	PROC(qpop_front, "wt");
	PROC(qpop_back, "wt");
	PROC(qbpop_fpush, "wt");
	PROC(qtrim_front, "wt");
	PROC(qtrim_back, "wt");
	PROC(qfix, "wt");
	PROC(qclear, "wt");
	PROC(qlist, "rt");
	PROC(qrlist, "rt");
	PROC(qslice, "rt");
	PROC(qrange, "rt");
	PROC(qget, "rt");
	PROC(qset, "wt");

    PROC(sadd, "wt");
    PROC(sismember, "rt");
    PROC(srem, "wt");
    PROC(scard, "rt");
    PROC(smembers, "rt");
    PROC(smove, "wt");
    PROC(redis_sscan, "rt");
    PROC(sinter, "rt");
    PROC(sinterstore, "wt");
    PROC(sunion, "rt");
    PROC(sunionstore, "wt");
    PROC(sdiff, "rt");
    PROC(sdiffstore, "wt");

	PROC(clear_binlog, "wt");

	PROC(dump, "b");
	PROC(sync140, "b");
	PROC(info, "rt");
	PROC(dbsize, "rt");
	// doing compaction in a reader thread, because we have only one
	// writer thread(for performance reason); we don't want to block writes
	PROC(compact, "rt");
	PROC(key_range, "r"); // deprecated
	//
	PROC(get_key_range, "r");
	// set_key_range must run in the main thread
	PROC(set_key_range, "r");
	// slaveof must run in the main thread
    PROC(slaveof, "r");
	// client must run in the main thread
	PROC(client, "r");
	// config must run in the main thread
	PROC(config, "r");
	// repli must run in the main thread
	PROC(repli, "r");

	PROC(ttl, "rt");
	PROC(expire, "wt");
}


SSDBServer::SSDBServer(SSDB *ssdb, SSDB *meta, Config *conf, const std::string &conf_path, NetworkServer *net):conf(conf),conf_path(conf_path){
	this->ssdb = (SSDBImpl *)ssdb;
	this->meta = meta;

	net->data = this;
	this->reg_procs(net);

	int sync_speed = conf->get_num("replication.sync_speed");

	backend_dump = new BackendDump(this->ssdb);
	backend_sync = new BackendSync(this->ssdb, sync_speed);
	expiration = new ExpirationHandler(this->ssdb);

    {
        int port = conf->get_num("server.port"); 
        struct ifaddrs *ifh, *ifc;
        char addr[32] = {0};
        if (getifaddrs(&ifh) == 0) {
            struct sockaddr_in *sin = NULL;
            for (ifc = ifh; ifc != NULL; ifc = ifc->ifa_next){
                if(ifc->ifa_addr->sa_family == AF_INET) {
                    sin = (struct sockaddr_in *)ifc->ifa_addr;
                    snprintf(addr, 32, "%s:%d", inet_ntoa(sin->sin_addr), port);
                    addrs[addr] = addr;
                }
            }
            freeifaddrs(ifh);
        }

        snprintf(addr, 32, "localhost:%d", port);
        addrs[addr] = addr;
    }

	{ // slaves
		const Config *repl_conf = conf->get("replication");
		if(repl_conf != NULL){
			std::vector<Config *> children = repl_conf->children;
			for(std::vector<Config *>::iterator it = children.begin(); it != children.end(); it++){
				Config *c = *it;
				if(c->key != "slaveof"){
					continue;
				}
				std::string ip = c->get_str("ip");
				int port = c->get_num("port");
				std::string type = c->get_str("type");
				std::string id = c->get_str("id");
                this->create_slave(ip, port, type, id, c->get_str("auth"));
			}
		}
	}

	// load kv_range
	int ret = this->get_kv_range(&this->kv_range_s, &this->kv_range_e);
	if(ret == -1){
		log_fatal("load key_range failed!");
		exit(1);
	}

    ret = load_kv_stats();
	if(ret == -1){
		log_fatal("load kv_stats failed!");
		exit(1);
	}

	log_info("key_range.kv: \"%s\", \"%s\"",
		str_escape(this->kv_range_s).c_str(),
		str_escape(this->kv_range_e).c_str()
		);
}

SSDBServer::~SSDBServer(){
    save_kv_stats(true);
    destroy_all_slaves();
    addrs.clear();

	delete backend_dump;
	delete backend_sync;
	delete expiration;

	log_debug("SSDBServer finalized");
}

int SSDBServer::create_slave(std::string &ip, int port, std::string &type, std::string &id, std::string auth) {
    if(ip == "") {
        log_warn("slaveof: %s:%d, type: %s failed, ip is empty!", ip.c_str(), port, type.c_str());
        return -1;
    }

    if(port <= 0 || port > 65535){
        log_warn("slaveof: %s:%d, type: %s failed, port should be in (0, 65535)!", ip.c_str(), port, type.c_str());
        return -1;
    }

    char addr[32] = {0};
    snprintf(addr, 32, "%s:%d", ip.c_str(), port);
    if (!addrs[addr].empty()) {
        log_warn("slaveof: %s:%d, type: %s failed, should not sync from self!", ip.c_str(), port, type.c_str());
        return -1;
    }

    std::vector<Slave *>::iterator it;
    for(it = slaves.begin(); it != slaves.end(); it++){
        Slave *slave = *it;
        if (slave->get_master_ip() == ip && slave->get_master_port() == port) {
            log_warn("slaveof: %s:%d, type: %s failed, slave already exist!", ip.c_str(), port, type.c_str());
            return -1;
        }
    }

    bool is_mirror = false;
    if(type == "mirror"){
        is_mirror = true;
    }else{
        type = "sync";
    }

    log_info("slaveof: %s:%d, type: %s id: %s", ip.c_str(), port, type.c_str(), id.c_str());
    Slave *slave = new Slave(ssdb, meta, ip.c_str(), port, is_mirror);
    if(!id.empty()){
        slave->set_id(id);
    }
    slave->auth = auth;
    slave->start();
    slaves.push_back(slave);

    return 0;
}

// not thread safe
void SSDBServer::destroy_all_slaves() {
    std::vector<Slave *>::iterator it;
    for(it = slaves.begin(); it != slaves.end(); it++){
        Slave *slave = *it;
        slave->stop();
        delete slave;
    }

    slaves.clear();
}

int SSDBServer::set_kv_range(const std::string &start, const std::string &end){
	if(meta->hset("key_range", "kv_s", start) == -1){
		return -1;
	}
	if(meta->hset("key_range", "kv_e", end) == -1){
		return -1;
	}

	kv_range_s = start;
	kv_range_e = end;
	return 0;
}

int SSDBServer::get_kv_range(std::string *start, std::string *end){
	if(meta->hget("key_range", "kv_s", start) == -1){
		return -1;
	}
	if(meta->hget("key_range", "kv_e", end) == -1){
		return -1;
	}
	return 0;
}

bool SSDBServer::in_kv_range(const Bytes &key){
	if((this->kv_range_s.size() && this->kv_range_s >= key)
		|| (this->kv_range_e.size() && this->kv_range_e < key))
	{
		return false;
	}
	return true;
}

bool SSDBServer::in_kv_range(const std::string &key){
	if((this->kv_range_s.size() && this->kv_range_s >= key)
		|| (this->kv_range_e.size() && this->kv_range_e < key))
	{
		return false;
	}
	return true;
}

/*
 * reset master replication offset
 */
int SSDBServer::set_repli_status(const std::string &id, const std::string &last_seq, const std::string &last_key) {
    std::string status_key = SLAVE_STATUS_PREFIX + id;

    meta->hset(status_key, "last_key", last_key);
    meta->hset(status_key, "last_seq", last_seq);

    log_info("set_repli_status status_key: %s last_seq: %s last_key: %s" , status_key.c_str(), last_seq.c_str(), last_key.c_str());

    return 0;
}

int SSDBServer::get_repli_status(const std::string &id, std::string &last_seq, std::string &last_key) {
    std::string status_key = SLAVE_STATUS_PREFIX + id;
    meta->hget(status_key, "last_seq", &last_seq);
    meta->hget(status_key, "last_key", &last_key);
    return 0;
}

int SSDBServer::get_all_repli_status(std::vector<std::string> &list) {
    std::vector<std::string> names;
    meta->hlist(SLAVE_STATUS_PREFIX, SLAVE_STATUS_RANGE_END, SSDB_MAX_SCAN_LEN, &names);
    for(std::vector<std::string>::iterator it = names.begin(); it != names.end(); it ++) {
        std::string last_seq, last_key;
        meta->hget(*it, "last_seq", &last_seq);
        meta->hget(*it, "last_key", &last_key);
        if((*it).size() > SLAVE_STATUS_PREFIX.size()) {
            list.push_back((*it).substr(SLAVE_STATUS_PREFIX.size()));
            list.push_back(last_seq);
            list.push_back(last_key);
        }
    }
    return 0;
}

int SSDBServer::load_kv_stats(){
    std::string kv_size_s, kv_count_s, hash_count_s, zset_count_s, queue_count_s; 
	if(meta->hget("key_stats", "kv_size", &kv_size_s) == -1){
		return -1;
	}
	if(meta->hget("key_stats", "kv_count", &kv_count_s) == -1){
		return -1;
	}
	if(meta->hget("key_stats", "hash_count", &hash_count_s) == -1){
		return -1;
	}
	if(meta->hget("key_stats", "zset_count", &zset_count_s) == -1){
		return -1;
	}
	if(meta->hget("key_stats", "queue_count", &queue_count_s) == -1){
		return -1;
	}
    ssdb->kv_size = str_to_uint64(kv_size_s);
    ssdb->kv_count = str_to_uint64(kv_count_s);
    ssdb->hash_count = str_to_uint64(hash_count_s);
    ssdb->zset_count = str_to_uint64(zset_count_s);
    ssdb->queue_count = str_to_uint64(queue_count_s);
    log_info("load_kv_stats kv_size %ld kv_count %ld hash_count %ld zset_count %ld queue_count %ld", ssdb->kv_size, ssdb->kv_count, ssdb->hash_count, ssdb->zset_count, ssdb->queue_count);
	return 0;
}

int SSDBServer::save_kv_stats(bool force){
    if (!force && ssdb->update_count < 1000){
        return 0;
    }
	if(meta->hset("key_stats", "kv_size", str(ssdb->kv_size)) == -1){
		return -1;
	}
	if(meta->hset("key_stats", "kv_count", str(ssdb->kv_count)) == -1){
		return -1;
	}
	if(meta->hset("key_stats", "hash_count", str(ssdb->hash_count)) == -1){
		return -1;
	}
	if(meta->hset("key_stats", "zset_count", str(ssdb->zset_count)) == -1){
		return -1;
	}
	if(meta->hset("key_stats", "queue_count", str(ssdb->queue_count)) == -1){
		return -1;
	}
    ssdb->update_count = 0;
    log_info("save_kv_stats kv_size %ld kv_count %ld hash_count %ld zset_count %ld queue_count %ld", ssdb->kv_size, ssdb->kv_count, ssdb->hash_count, ssdb->zset_count, ssdb->queue_count);
	return 1;
}

/*********************/

int proc_clear_binlog(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	serv->ssdb->binlogs->flush();
	resp->push_back("ok");
	return 0;
}

int proc_dump(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	serv->backend_dump->proc(link);
	return PROC_BACKEND;
}

int proc_sync140(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	serv->backend_sync->proc(link);
	return PROC_BACKEND;
}

int proc_compact(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	serv->ssdb->compact();
	resp->push_back("ok");
	return 0;
}

int proc_key_range(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	std::vector<std::string> tmp;
	int ret = serv->ssdb->key_range(&tmp);
	if(ret == -1){
		resp->push_back("error");
		return -1;
	}
	
	resp->push_back("ok");
	for(int i=0; i<(int)tmp.size(); i++){
		std::string block = tmp[i];
		resp->push_back(block);
	}
	
	return 0;
}

int proc_get_key_range(NetworkServer *net, Link *link, const Request &req, Response *resp){
SSDBServer *serv = (SSDBServer *)net->data;
	std::string s, e;
	int ret = serv->get_kv_range(&s, &e);
	if(ret == -1){
		resp->push_back("error");
	}else{
		resp->push_back("ok");
		resp->push_back(s);
		resp->push_back(e);
	}
	return 0;
}

int proc_set_key_range(NetworkServer *net, Link *link, const Request &req, Response *resp){
SSDBServer *serv = (SSDBServer *)net->data;
	if(req.size() != 3){
		resp->push_back("client_error");
	}else{
		serv->set_kv_range(req[1].String(), req[2].String());
		resp->push_back("ok");
	}
	return 0;
}

int proc_dbsize(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	uint64_t size = serv->ssdb->size();
	resp->push_back("ok");
	resp->push_back(str(size));
	return 0;
}

static int proc_info_base(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_info_leveldb(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_info_cmd(NetworkServer *net, Link *link, const Request &req, Response *resp);

int proc_info(NetworkServer *net, Link *link, const Request &req, Response *resp){
	resp->push_back("ok");

	if(req.size() > 1) {
        if(req[1] == "leveldb") {
            return proc_info_leveldb(net,link,req,resp);
        } else if(req[1] == "cmd"){
            return proc_info_cmd(net,link,req,resp);
        }
	} else {
        return proc_info_base(net,link,req,resp);
	}

	return 0;
}

int proc_info_base(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	resp->push_back("# ssdb-server");
	resp->push_back(str("version:") + SSDB_VERSION);
	uint64_t uptime = (uint64_t)millitime() + net->uptime_start;
	resp->push_back("uptime_in_seconds:" + str(uptime));
	resp->push_back("uptime_in_days:" + str(uptime/86400 + 1));
    {
        // cpu stat
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        resp->push_back("used_cpu_sys:" + str((double)ru.ru_stime.tv_sec+(double)ru.ru_stime.tv_usec/1000000));
        resp->push_back("used_cpu_user:" + str((double)ru.ru_utime.tv_sec+(double)ru.ru_utime.tv_usec/1000000));
        
        // memory stat
        int64_t rss = memory_used();
        char rss_human[32];
        if (rss > 1000000) {
            snprintf(rss_human, sizeof(rss_human), "%ld MB", rss / 1000000);
        } else if (rss > 1000) {
            snprintf(rss_human, sizeof(rss_human), "%ld KB", rss / 1000);
        } else {
            snprintf(rss_human, sizeof(rss_human), "%ld B", rss);
        }
        resp->push_back("used_memory:" + str(rss));
        resp->push_back("used_memory_human:" + str(rss_human));

        // network in/out 
        resp->push_back("bytes_read:" + str((int64_t)net->bytes_read));
        resp->push_back("bytes_written:" + str((int64_t)net->bytes_written));
    }

	resp->push_back("# stats");
	{
		resp->push_back("links:" + str(net->link_count));
	}
	{
		int64_t calls = 0, write_calls = 0;
		proc_map_t::iterator it;
		for(it=net->proc_map.begin(); it!=net->proc_map.end(); it++){
			Command *cmd = it->second;
			calls += cmd->calls;
			if(cmd->flags & Command::FLAG_WRITE){
			    write_calls += cmd->calls;
            }
		}
		resp->push_back("total_calls:" + str(calls));
		resp->push_back("write_calls:" + str(write_calls));
		resp->push_back("read_calls:" + str(calls - write_calls));
	}
	
	{
		uint64_t size = serv->ssdb->size();
		resp->push_back("dbsize:" + str(size));
        std::string kv_start(1,DataType::KV-1);
        std::string kv_end(1,DataType::KV+1);
		uint64_t kv_total_size = serv->ssdb->size(kv_start,kv_end);
        uint64_t kv_count = 0;
        if (serv->ssdb->kv_count != 0) {
            kv_count = kv_total_size / (serv->ssdb->kv_size / serv->ssdb->kv_count + MIN_LEVELDB_SIZE);
        }
		resp->push_back("kv_update_size:" + str(serv->ssdb->kv_size)); // total add/update size
		resp->push_back("kv_update_count:" + str(serv->ssdb->kv_count)); // total add/update count
		resp->push_back("kv_count:" + str(kv_count));
		resp->push_back("hash_count:" + str(serv->ssdb->hash_count));
		resp->push_back("zset_count:" + str(serv->ssdb->zset_count));
		resp->push_back("list_count:" + str(serv->ssdb->queue_count));
	}

	resp->push_back("# binlog");
	{
		std::string s = serv->ssdb->binlogs->stats();
		resp->push_back(s);
	}

	resp->push_back("# slaves");
	{
		std::vector<std::string> syncs = serv->backend_sync->stats();
		resp->push_back("connected_slaves:" + str(syncs.size()));
		std::vector<std::string>::iterator it;
		int count = 0;
		for(it = syncs.begin(); it != syncs.end(); it++){
			std::string s = *it;
			resp->push_back("repl_client" + str(count++) + ":" + s);
		}
	}

	resp->push_back("# masters");
	{
		std::vector<Slave *>::iterator it;
		for(it = serv->slaves.begin(); it != serv->slaves.end(); it++){
			Slave *slave = *it;
			std::string s = slave->stats();
			resp->push_back("repl_slaveof:" + s);
		}
	}

	if(req.size() == 1 || req[1] == "range"){
		resp->push_back("# key_range");
		std::vector<std::string> tmp;
		int ret = serv->ssdb->key_range(&tmp);
		if(ret == 0){
			char buf[512];
			
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[0].data(), tmp[0].size()).c_str(),
				hexmem(tmp[1].data(), tmp[1].size()).c_str()
				);
			resp->push_back(str("key_range.kv:\t") + buf);
			
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[2].data(), tmp[2].size()).c_str(),
				hexmem(tmp[3].data(), tmp[3].size()).c_str()
				);
			resp->push_back(str("key_range.hash:\t") + buf);
			
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[4].data(), tmp[4].size()).c_str(),
				hexmem(tmp[5].data(), tmp[5].size()).c_str()
				);
			resp->push_back(str("key_range.zset:\t") + buf);
			
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[6].data(), tmp[6].size()).c_str(),
				hexmem(tmp[7].data(), tmp[7].size()).c_str()
				);
			resp->push_back(str("key_range.list:\t") + buf);
		}
	}

	return 0;
}

static int proc_info_leveldb(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;

    resp->push_back("# leveldb");
    std::vector<std::string> tmp = serv->ssdb->info();
    for(int i=0; i<(int)tmp.size(); i++){
        std::string block = tmp[i];
        resp->push_back(block);
    }

	return 0;
}

static int proc_info_cmd(NetworkServer *net, Link *link, const Request &req, Response *resp){
    resp->push_back("# cmd");
    proc_map_t::iterator it;
    for(it=net->proc_map.begin(); it!=net->proc_map.end(); it++){
        Command *cmd = it->second;
        char buf[128];
        snprintf(buf, sizeof(buf), "calls=%" PRIu64 ",time_wait=%.0f,time_proc=%.0f",
            cmd->calls, cmd->time_wait, cmd->time_proc);
        resp->push_back("cmd." + cmd->name + ":\t" + buf);
    }
	
	return 0;
}

static int proc_slaveof_noone(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_slaveof_master(NetworkServer *net, Link *link, const Request &req, Response *resp);

int proc_slaveof(NetworkServer *net, Link *link, const Request &req, Response *resp){
    CHECK_NUM_PARAMS(3);

    if (req.size() == 3 && (req[1] != "no" || req[2] != "one")) {
        resp->reply_client_error("param error");
        return 0;
    }

    // slaveof no one, stop slave threads
    if (req[1] == "no" && req[2] == "one") {
        return proc_slaveof_noone(net, link, req, resp);
    } else {
        return proc_slaveof_master(net, link, req, resp);
    }
}

// slaveof no one
static int proc_slaveof_noone(NetworkServer *net, Link *link, const Request &req, Response *resp){
    SSDBServer *serv = (SSDBServer *)net->data; 
    log_info("slaveof no one, remote_ip: %s", link->remote_ip);

    // destroy slaves
    std::vector<Slave *>::iterator it;
    for(it = serv->slaves.begin(); it != serv->slaves.end(); it++){
        Slave *slave = *it;
        std::string s = slave->stats();
        log_info("slaveof no one: current replication stats %s", s.c_str());
    }
    serv->destroy_all_slaves();
    // change conf
    serv->conf->del("replication.slaveof");
    resp->reply_status(0, NULL);

    return 0;
}

// slaveof master_ip master_port (mirror|sync) [id] [auth]
static int proc_slaveof_master(NetworkServer *net, Link *link, const Request &req, Response *resp){
    SSDBServer *serv = (SSDBServer *)net->data; 
    std::string ip = req[1].String();
    int port = req[2].Int();
    if (port <= 0 || errno != 0) {
        resp->reply_client_error("port need > 0");
        return 0;
    }

    std::string type = req[3].String();
    if (type != "sync" && type != "mirror") {
        resp->reply_client_error("need sync or mirror type");
        return 0;
    }

    std::string id = req.size() >= 5 ? req[4].String() : "";
    std::string auth = req.size() >= 6 ? req[5].String() : "";

    if (serv->slaves.size() > 0) {
        log_warn("slaveof %s %d %s %s failed, slave already exist, remote_ip: %s", ip.c_str(), port, type.c_str(), id.c_str(), link->remote_ip);
        resp->reply_status(-1, "slave already exist");
        return 0;
    }
    int status = serv->create_slave(ip, port, type, id, auth);

    if (status == 0) {
        log_info("slaveof %s %d %s %s success, remote_ip: %s", ip.c_str(), port, type.c_str(), id.c_str(), link->remote_ip);
        Config *conf = serv->conf->find_child("replication");
        if (conf == NULL) {
            conf = serv->conf->add_child("replication", "");
        }
        conf = conf->add_child("slaveof", "");
        if (!id.empty()) {
            conf->add_child("id", id.c_str());
        }
        conf->add_child("ip", ip.c_str());
        conf->add_child("port", req[2].String().c_str());
        conf->add_child("type", type.c_str());
        if (!auth.empty()) {
            conf->add_child("auth", auth.c_str());
        }

        resp->reply_status(0, NULL);
    } else {
        log_error("slaveof %s %d %s %s failed, remote_ip: %s", ip.c_str(), port, type.c_str(), id.c_str(), link->remote_ip);
        resp->reply_status(-1, "create slave failed");
    }
    return 0;
}

static int proc_client_list(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_client_kill(NetworkServer *net, Link *link, const Request &req, Response *resp);

int proc_client(NetworkServer *net, Link *link, const Request &req, Response *resp){
    CHECK_NUM_PARAMS(2);

    if (req[1] == "list") {
        return proc_client_list(net, link, req, resp);
    } else if (req[1] == "kill") {
        return proc_client_kill(net, link, req, resp);
    } else {
        resp->reply_client_error("param error");
    }

    return 0;
}

static int proc_client_list(NetworkServer *net, Link *link, const Request &req, Response *resp){
	resp->push_back("ok");

    char info[128];
    double current = millitime();
    for (link_map_t::const_iterator it = net->link_map.begin();it != net->link_map.end(); it ++) {
        Link *link = it->second;
        int age = (int)((current - link->create_time));
        int idle = (int)((current - link->active_time));
        snprintf(info, sizeof(info), "addr=%s age=%d idle=%d cmd=%s", it->first.c_str(), age, idle, link->last_cmd.c_str());
        resp->push_back(info);
    }

    return 0;
}

static int proc_client_kill(NetworkServer *net, Link *link, const Request &req, Response *resp){
    CHECK_NUM_PARAMS(4);

    if (req[2] != "addr") {
        resp->reply_client_error("param error");
        return 0;
    }

    std::string ip = req[3].String();
    link_map_t::iterator it = net->link_map.find(ip);
    if (it != net->link_map.end() && it->second != link) {
        net->kill_link(it->second);
        resp->reply_status(0,NULL);
    } else {
        resp->reply_status(-1,"link not exist");
    }
    
    log_info("proc_client_kill client_addr: %s remote_ip: %s", ip.c_str(), link->remote_ip);
    return 0;
}

static int proc_config_rewrite(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_config_set(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_config_get(NetworkServer *net, Link *link, const Request &req, Response *resp);

int proc_config(NetworkServer *net, Link *link, const Request &req, Response *resp){
    CHECK_NUM_PARAMS(2);

    if (req[1] == "rewrite") {
        return proc_config_rewrite(net, link, req, resp);
    } else if (req[1] == "set") {
        return proc_config_set(net, link, req, resp);
    } else if (req[1] == "get") {
        return proc_config_get(net, link, req, resp);
    } else {
        resp->reply_client_error("param error");
    }

    return 0;
}
static int proc_config_rewrite(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;

	time_t time;
	struct timeval tv;
	struct tm *tm;
    char tmbuf[32];
    char conf_path_bak[serv->conf_path.size() + 32];

    gettimeofday(&tv,NULL);
	time = tv.tv_sec;
	tm = localtime(&time);
    strftime(tmbuf, sizeof(tmbuf), "%Y%m%d_%H%M%S", tm);
    int mill_sec = (int)(tv.tv_usec/1000) > 0 ?  (int)(tv.tv_usec/1000) : 1; // if mill_sec == 0, %3d format will show "  0"
    snprintf(conf_path_bak, sizeof(conf_path_bak), "%s.%s_%03d", serv->conf_path.c_str(), tmbuf, mill_sec);

	int ret = rename(serv->conf_path.c_str(), conf_path_bak);
	if(ret == -1){
		log_error("conf %s rename error: %s", serv->conf_path.c_str(), strerror(errno));
        resp->reply_status(-1,"conf file rename error");
		return 0;
    }
    
    ret = serv->conf->save(serv->conf_path.c_str());
	if(ret == -1){
        log_error("proc_config_rewrite fail, remote_ip: %s", link->remote_ip);
        resp->reply_status(-1,"config rewrite error");
    } else {
        log_info("proc_config_rewrite success, remote_ip: %s", link->remote_ip);
        resp->reply_status(0,NULL);
    }

    return 0;
}

static int proc_config_set(NetworkServer *net, Link *link, const Request &req, Response *resp) {
    CHECK_NUM_PARAMS(4);

    SSDBServer *serv = (SSDBServer *)net->data;
    std::string name = req[2].String();

    if (name == "server.max_connections" || name == "server.timeout" 
            || name == "server.slow_time" || name == "replication.binlog_capacity") {
        int val = req[3].Int();
        if (val <= 0 || errno != 0) {
            goto client_err;
        }

        if (name == "server.max_connections") {
            net->max_connections = val;
        } else if (name == "server.timeout") {
            net->timeout = val;
        } else if (name == "server.slow_time") {
            net->slow_time = val;
        } else if (name == "replication.binlog_capacity") {
            serv->ssdb->binlogs->set_capacity(val);
        }

        serv->conf->set(name.c_str(), req[3].String().c_str());
    } else if (name == "server.client_output_limit") {
        int64_t val = req[3].Int64();
        if (val <= 0 || errno != 0) {
            goto client_err;
        }

        net->client_output_limit = val;
        serv->conf->set(name.c_str(), req[3].String().c_str());
    } else if (name == "server.allow" || name == "server.deny") {
        std::string val = req[3].String();
        std::vector<std::string> ips;
        str_split(val, ips, ",");
    
        serv->conf->del(name.c_str()); // may be multi-configs, so need del 
        if (name == "server.allow") {
            net->ip_filter->clear_allow();
            if (val != "") {
                for(std::vector<std::string>::iterator it = ips.begin(); it != ips.end(); it ++) {
                    net->ip_filter->add_allow(*it);
                }
                serv->conf->set(name.c_str(), val.c_str());
            }
        } else if (name == "server.deny") {
            net->ip_filter->clear_deny();
            if (val != "") {
                for(std::vector<std::string>::iterator it = ips.begin(); it != ips.end(); it ++) {
                    net->ip_filter->add_deny(*it);
                }
                serv->conf->set(name.c_str(), val.c_str());
            }
        }
    } else if (name == "server.readonly") {
        if (req[3].String() == "yes") {
            net->readonly = true;
        } else {
            net->readonly = false;
        }
        serv->conf->set(name.c_str(), req[3].String().c_str());
    } else if (name == "server.auth") {
		std::string password = req[3].String();
		if(password.empty()){
			net->need_auth = false;		
			net->password = "";
			log_info("config set auth: off");
            serv->conf->del(name.c_str());
		}else{
			net->need_auth = true;
			net->password = password;
			log_info("config set auth: on");
            serv->conf->set(name.c_str(), req[3].String().c_str());
		}
    } else {
        resp->reply_status(-1,"config set failed, param not support");
        return 0;
    }
    
    resp->reply_status(0,NULL);
    log_info("proc_config_set name: %s val: %s remote_ip: %s", name.c_str(), req[3].String().c_str(), link->remote_ip);
    return 0;

client_err:
    char errmsg[256];
    snprintf(errmsg, 256, "config set failed, val format error '%s' '%s' ", name.c_str(),req[3].String().c_str());
    resp->reply_client_error(errmsg);
    log_error("proc_config_set %s remote_ip: %s", errmsg, link->remote_ip);
    return 0;
}

#define CONFIG_GET_STR(val, default_val) ((val != NULL && val[0] != '\0')? val : default_val)
#define CONFIG_GET_NUM(val, default_val) (val <= 0 ? default_val : val)
static int proc_config_get(NetworkServer *net, Link *link, const Request &req, Response *resp) {
    CHECK_NUM_PARAMS(3);

    SSDBServer *serv = (SSDBServer *)net->data;
    std::string name = req[2].String();
    resp->push_back("ok");
    if(name != "*" && !name.empty()) {
        std::string val  = serv->conf->get_str(name.c_str());
        resp->push_back(val);
    } else {
        //get all config
        resp->push_back(str("work_dir:")+CONFIG_GET_STR(serv->conf->get_str("work_dir"),CONFIG_WORK_DIR));
        resp->push_back(str("pidfile:")+CONFIG_GET_STR(serv->conf->get_str("pidfile"),""));
        
        resp->push_back(str("server.ip:")+CONFIG_GET_STR(serv->conf->get_str("server.ip"),CONFIG_SERVER_IP));
        resp->push_back(str("server.port:")+str(CONFIG_GET_NUM(serv->conf->get_num("server.port"),0)));
        resp->push_back(str("server.allow:")+CONFIG_GET_STR(serv->conf->get_str("server.allow"),""));
        resp->push_back(str("server.deny:")+CONFIG_GET_STR(serv->conf->get_str("server.deny"),""));
        resp->push_back(str("server.max_connections:")+str(CONFIG_GET_NUM(serv->conf->get_num("server.max_connections"),CONFIG_SERVER_MAX_CONNECTIONS)));
        resp->push_back(str("server.client_output_limit:")+str(CONFIG_GET_NUM(serv->conf->get_num("server.client_output_limit"),CONFIG_SERVER_OUTPUT_LIMIT)));
        resp->push_back(str("server.timeout:")+str(CONFIG_GET_NUM(serv->conf->get_num("server.timeout"),CONFIG_SERVER_TIMEOUT)));
        resp->push_back(str("server.readonly:")+CONFIG_GET_STR(serv->conf->get_str("server.readonly"),CONFIG_SERVER_READONLY));
        resp->push_back(str("server.slow_time:")+str(CONFIG_GET_NUM(serv->conf->get_num("server.slow_time"),CONFIG_SERVER_SLOW_TIME)));

        resp->push_back(str("replication.binlog:")+str(CONFIG_GET_STR(serv->conf->get_str("replication.binlog"),CONFIG_REPLICATION_BINLOG)));
        resp->push_back(str("replication.binlog_capacity:")+str(CONFIG_GET_NUM(serv->conf->get_num("replication.binlog_capacity"),CONFIG_BINLOG_CAPACITY)));

        resp->push_back(str("leveldb.cache_size:")+str(CONFIG_GET_NUM(serv->conf->get_num("leveldb.cache_size"),CONFIG_LEVELDB_CACHE_SIZE)));
        resp->push_back(str("leveldb.write_buffer_size:")+str(CONFIG_GET_NUM(serv->conf->get_num("leveldb.write_buffer_size"),CONFIG_LEVELDB_WRITE_BUFFER_SIZE)));
        resp->push_back(str("leveldb.block_size:")+str(CONFIG_GET_NUM(serv->conf->get_num("leveldb.block_size"),CONFIG_LEVELDB_BLOCK_SIZE)));
    }

    return 0;
}

static int proc_repli_set_offset(NetworkServer *net, Link *link, const Request &req, Response *resp);
static int proc_repli_get_offset(NetworkServer *net, Link *link, const Request &req, Response *resp);

// replication [options] [args] 
// for example: replication set_offset id offset 
int proc_repli(NetworkServer *net, Link *link, const Request &req, Response *resp){
    CHECK_NUM_PARAMS(2);

    if (req[1] == "set_offset") {
        return proc_repli_set_offset(net, link, req, resp);
    } else if (req[1] == "get_offset") {
        return proc_repli_get_offset(net, link, req, resp);
    } else {
        resp->reply_client_error("param error");
    }

    return 0;
}

static int proc_repli_set_offset(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(4);
	SSDBServer *serv = (SSDBServer *)net->data;

    std::string id = req[2].String();
    uint64_t seq = req[3].Uint64();
    if(id == "" || errno != 0) {
        resp->reply_client_error("param error");
        return 0;
    }
    std::string last_key = req.size() >= 5 ? req[4].String() : "";

    std::vector<Slave *>::iterator it;
    for(it = serv->slaves.begin(); it != serv->slaves.end(); it++){
        Slave *slave = *it;
        if (slave->get_id() == id) {
            // don't allow to dynamic update sync offset when the slave is running
            resp->reply_status(-1,"current slave is running, need stop sync");
            return 0;
        }
    }

    serv->set_repli_status(id, str(seq), last_key);
    resp->reply_status(0,NULL);
    log_info("proc_repli_set_offset id: %s seq: %" PRIu64 " remote_ip: %s", id.c_str(), seq, link->remote_ip);

    return 0;
}

static int proc_repli_get_offset(NetworkServer *net, Link *link, const Request &req, Response *resp){
	CHECK_NUM_PARAMS(3);
	SSDBServer *serv = (SSDBServer *)net->data;

    std::string id = req[2].String();
    std::string last_seq, last_key;

    if(id == "*" || id == "") {
        std::vector<std::string> data;
        serv->get_all_repli_status(data);
        if(data.size() % 3 != 0) {
            resp->reply_status(-1, "server error");
            return 0;
        }
        resp->push_back("ok");
        for(std::vector<std::string>::iterator it = data.begin(); it != data.end();) {
            std::string id = *it++;
            std::string last_seq = *it++;
            std::string last_key = *it++;
            resp->push_back("id=" + id + " last_seq=" + last_seq + " last_key=" + last_key);
        }
    } else {
        serv->get_repli_status(id, last_seq, last_key);
        resp->push_back("ok");
        resp->push_back("id=" + id + " last_seq=" + last_seq + " last_key=" + last_key);
    }

    return 0;
}

static int kv_scan(SSDBServer *serv, std::string &cursor_key, const std::string &pattern, bool use_pattern, int count, std::vector<std::string> *result);
static int hash_scan(SSDBServer *serv, const std::string &name, std::string &cursor_key, const std::string &pattern, bool use_pattern, int count, std::vector<std::string> *result, int type);
static int zset_scan(SSDBServer *serv, const std::string &name, std::string &cursor_key, std::string &cursor_score, const std::string &pattern, bool use_pattern, int count, std::vector<std::string> *result);

/*
 * Support redis command:
 *      *SCAN  cursor [match pattern] [count number]
 *
 *      SCAN iterates the set of keys in the currently selected Redis database.
 *      SSCAN iterates elements of Sets types.
 *      HSCAN iterates fields of Hash types and their associated values.
 *      ZSCAN iterates elements of Sorted Set types and their associated scores.
 *
 * The only valid cursors to use are:
 *      The cursor value of 0 when starting an iteration.
 *      The cursor returned by the previous call to SCAN in order to continue the iteration.
 *      Other is undefined
 *
 * There is keep a state in link:
 *      So just support iterator with same client and the same command. 
 *      Other is undefined.
 */
int proc_redis_scan(NetworkServer *net, Link *link, const Request &req, Response *resp, const int type){
    // for example: scan 0 or hscan key 0 or zscan key 0
    int min_size = (type == REDIS_SCAN) ? 2 : 3;

	SSDBServer *serv = (SSDBServer *)net->data;
	CHECK_NUM_PARAMS(min_size); 

    if (req.size() > min_size && req.size() != (min_size + 2) && req.size() != (min_size + 4)) {
		resp->push_back("client_error"); 
		resp->push_back("wrong number of arguments"); 
        return 0;
    }

    int count = 10; // default
    bool use_pattern = false; // [match pattern]
    std::string pattern; 
	uint64_t cursor = req[min_size-1].Uint64();

    for (int i = min_size; i < req.size(); i += 2) {
        if (req[i] == "count") {
            count = req[i+1].Int();
        } else if (req[i] == "match") {
            use_pattern = true;
            pattern = req[i+1].String();
        } else {
            resp->push_back("client_error"); 
            resp->push_back("syntax error"); 
            return 0;
        }
    }

    if (count <= 0) {
        resp->push_back("client_error"); 
        resp->push_back("syntax error"); 
        return 0;
    }

    // cursor => key_start(which is last key keep in link), because leveldb don't support redis's memory hash struct
    std::string cursor_key = link->get_cursor_key(cursor);
    std::string cursor_score = link->get_cursor_score(cursor);
    if (cursor_key.empty()) {
        cursor = 0;
    }
    log_debug("%s: cursor %ld cursor_key '%s' count %d", req[0].String().c_str(), cursor, cursor_key.c_str(), count);

    int result = 0;
    std::vector<std::string> keys;

    // iterator db
    switch(type) {
        case REDIS_SCAN: // scan command, just return key
            result = kv_scan(serv, cursor_key, pattern, use_pattern, count, &keys);
            break;
        case REDIS_SSCAN: // sscan command, need return key
        case REDIS_HSCAN: // hscan command, need return key and val
            result = hash_scan(serv, req[1].String(), cursor_key, pattern, use_pattern, count, &keys, type);
            break;
        case REDIS_ZSCAN: // zscan command, need return key and score
            result = zset_scan(serv, req[1].String(), cursor_key, cursor_score, pattern, use_pattern, count, &keys);
            break;
        default:
            resp->reply_status(-1,"unsupoort scan type");
            return 0;
    }

	resp->push_back("ok");

    if (result >= count) {
        link->reset_cursor(cursor_key, cursor_score, cursor + result);
        resp->add((int64_t)cursor + result);
    } else {
        link->reset_cursor("", "", 0);
        resp->add((int64_t)0);
    }

    for (std::vector<std::string>::iterator it = keys.begin(); it != keys.end(); it ++) {
        resp->push_back(*it);
    }

	return 0;
}

static int kv_scan(SSDBServer *serv, std::string &cursor_key, const std::string &pattern, bool use_pattern, int count, std::vector<std::string> *result) {
    int result_count = 0;
    KIterator *it = serv->ssdb->scan(cursor_key, "", count);
    while(it->next()){
        if (!use_pattern || is_pattern_match(it->key, pattern)) {
            result->push_back(it->key);
        }
        cursor_key = it->key;
        result_count ++;
    }
    delete it;
    return result_count;
}

static int hash_scan(SSDBServer *serv, const std::string &name, std::string &cursor_key, const std::string &pattern, bool use_pattern, int count, std::vector<std::string> *result, int type) {
    int result_count = 0;
    HIterator *it = serv->ssdb->hscan(name, cursor_key, "", count);
    while(it->next()){
        if (!use_pattern || is_pattern_match(it->key, pattern)) {
            result->push_back(it->key);
            if (type == REDIS_HSCAN) {
                result->push_back(it->val);
            }
        }
        cursor_key = it->key;
        result_count ++;
    }
    delete it;
    return result_count;
}

static int zset_scan(SSDBServer *serv, const std::string &name, std::string &cursor_key, std::string &cursor_score, const std::string &pattern, bool use_pattern, int count, std::vector<std::string> *result) {
    int result_count = 0;
    ZIterator *it = serv->ssdb->zscan(name, cursor_key, cursor_score, "", count);
    while(it->next()){
        if (!use_pattern || is_pattern_match(it->key, pattern)) {
            result->push_back(it->key);
            result->push_back(it->score);
        }
        cursor_key = it->key;
        cursor_score = it->score;
        result_count ++;
    }
    delete it;
    return result_count;
}

static size_t memory_used() {
    int fd;
    char filename[256] = {0}, buf[4096] = {0};
    snprintf(filename,sizeof(filename),"/proc/%d/stat",getpid());             
    if ((fd = open(filename,O_RDONLY)) == -1) {
        return 0;
    }

    if (read(fd,buf,sizeof(buf)) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    char *data = buf;

    // location to rss memory stat
    for (int i = 0; data && i < 23; i ++) {
        data = strchr(data,' ');
        if (data) {
            data ++;
        }
    }

    if (!data) {
        return 0;
    }
    
    char *temp = strchr(data,' ');
    if (!temp) {
        return 0;
    }
    *temp = '\0';
    return strtoll(data,NULL,10) * sysconf(_SC_PAGESIZE); // rss_size * page_size
}

