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

DEF_PROC(get);
DEF_PROC(set);
DEF_PROC(setx);
DEF_PROC(setnx);
DEF_PROC(getset);
DEF_PROC(getbit);
DEF_PROC(setbit);
DEF_PROC(countbit);
DEF_PROC(substr);
DEF_PROC(getrange);
DEF_PROC(strlen);
DEF_PROC(redis_bitcount);
DEF_PROC(del);
DEF_PROC(incr);
DEF_PROC(decr);
DEF_PROC(scan);
DEF_PROC(rscan);
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
	
DEF_PROC(qsize);
DEF_PROC(qfront);
DEF_PROC(qback);
DEF_PROC(qpush);
DEF_PROC(qpush_front);
DEF_PROC(qpush_back);
DEF_PROC(qpop);
DEF_PROC(qpop_front);
DEF_PROC(qpop_back);
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


#define PROC(c, f)     net->proc_map.set_proc(#c, f, proc_##c)

void SSDBServer::reg_procs(NetworkServer *net){
	PROC(get, "rt");
	PROC(set, "wt");
	PROC(del, "wt");
	PROC(setx, "wt");
	PROC(setnx, "wt");
	PROC(getset, "wt");
	PROC(getbit, "rt");
	PROC(setbit, "wt");
	PROC(countbit, "rt");
	PROC(substr, "rt");
	PROC(getrange, "rt");
	PROC(strlen, "rt");
	PROC(redis_bitcount, "rt");
	PROC(incr, "wt");
	PROC(decr, "wt");
	PROC(scan, "rt");
	PROC(rscan, "rt");
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

	PROC(qsize, "rt");
	PROC(qfront, "rt");
	PROC(qback, "rt");
	PROC(qpush, "wt");
	PROC(qpush_front, "wt");
	PROC(qpush_back, "wt");
	PROC(qpop, "wt");
	PROC(qpop_front, "wt");
	PROC(qpop_back, "wt");
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

	PROC(ttl, "rt");
	PROC(expire, "wt");
}


SSDBServer::SSDBServer(SSDB *ssdb, SSDB *meta, const Config &conf, NetworkServer *net){
	this->ssdb = (SSDBImpl *)ssdb;
	this->meta = meta;

	net->data = this;
	this->reg_procs(net);

	int sync_speed = conf.get_num("replication.sync_speed");

	backend_dump = new BackendDump(this->ssdb);
	backend_sync = new BackendSync(this->ssdb, sync_speed);
	expiration = new ExpirationHandler(this->ssdb);

    {
        int port = conf.get_num("server.port"); 
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
		const Config *repl_conf = conf.get("replication");
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
                this->create_slave(ip, port, type, id);
			}
		}
	}

	// load kv_range
	int ret = this->get_kv_range(&this->kv_range_s, &this->kv_range_e);
	if(ret == -1){
		log_fatal("load key_range failed!");
		exit(1);
	}
	log_info("key_range.kv: \"%s\", \"%s\"",
		str_escape(this->kv_range_s).c_str(),
		str_escape(this->kv_range_e).c_str()
		);
}

SSDBServer::~SSDBServer(){
    destroy_all_slaves();
    addrs.clear();

	delete backend_dump;
	delete backend_sync;
	delete expiration;
    // FIXME write and thread pool stop ?

	log_debug("SSDBServer finalized");
}

int SSDBServer::create_slave(std::string &ip, int port, std::string &type, std::string &id) {
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
        is_mirror = false;
    }

    log_info("slaveof: %s:%d, type: %s id: %s", ip.c_str(), port, type.c_str(), id.c_str());
    Slave *slave = new Slave(ssdb, meta, ip.c_str(), port, is_mirror);
    if(!id.empty()){
        slave->set_id(id);
    }
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

int proc_info(NetworkServer *net, Link *link, const Request &req, Response *resp){
	SSDBServer *serv = (SSDBServer *)net->data;
	resp->push_back("ok");
	resp->push_back("ssdb-server");
	resp->push_back("version");
	resp->push_back(SSDB_VERSION);
	{
		resp->push_back("links");
		resp->add(net->link_count);
	}
    {
        // cpu stat
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        resp->push_back("used_cpu_sys");
        resp->add((double)ru.ru_stime.tv_sec+(double)ru.ru_stime.tv_usec/1000000);
        resp->push_back("used_cpu_user");
        resp->add((double)ru.ru_utime.tv_sec+(double)ru.ru_utime.tv_usec/1000000);
        
        // memory stat
        int64_t rss = memory_used();
        char rss_human[32];
        if (rss > 1000000) {
            snprintf(rss_human, sizeof(rss_human), "%ld MByte", rss / 1000000);
        } else if (rss > 1000) {
            snprintf(rss_human, sizeof(rss_human), "%ld KByte", rss / 1000);
        } else {
            snprintf(rss_human, sizeof(rss_human), "%ld Byte", rss);
        }
        resp->push_back("used_memory");
        resp->add(rss);
        resp->push_back("used_memory_human");
        resp->push_back(rss_human);
    }
	{
		int64_t calls = 0;
		proc_map_t::iterator it;
		for(it=net->proc_map.begin(); it!=net->proc_map.end(); it++){
			Command *cmd = it->second;
			calls += cmd->calls;
		}
		resp->push_back("total_calls");
		resp->add(calls);
	}
	
	{
		uint64_t size = serv->ssdb->size();
		resp->push_back("dbsize");
		resp->push_back(str(size));
	}

	{
		std::string s = serv->ssdb->binlogs->stats();
		resp->push_back("binlogs");
		resp->push_back(s);
	}
	{
		std::vector<std::string> syncs = serv->backend_sync->stats();
		std::vector<std::string>::iterator it;
		for(it = syncs.begin(); it != syncs.end(); it++){
			std::string s = *it;
			resp->push_back("replication");
			resp->push_back(s);
		}
	}
	{
		std::vector<Slave *>::iterator it;
		for(it = serv->slaves.begin(); it != serv->slaves.end(); it++){
			Slave *slave = *it;
			std::string s = slave->stats();
			resp->push_back("replication");
			resp->push_back(s);
		}
	}

	if(req.size() == 1 || req[1] == "range"){
		std::vector<std::string> tmp;
		int ret = serv->ssdb->key_range(&tmp);
		if(ret == 0){
			char buf[512];
			
			resp->push_back("key_range.kv");
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[0].data(), tmp[0].size()).c_str(),
				hexmem(tmp[1].data(), tmp[1].size()).c_str()
				);
			resp->push_back(buf);
			
			resp->push_back("key_range.hash");
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[2].data(), tmp[2].size()).c_str(),
				hexmem(tmp[3].data(), tmp[3].size()).c_str()
				);
			resp->push_back(buf);
			
			resp->push_back("key_range.zset");
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[4].data(), tmp[4].size()).c_str(),
				hexmem(tmp[5].data(), tmp[5].size()).c_str()
				);
			resp->push_back(buf);
			
			resp->push_back("key_range.list");
			snprintf(buf, sizeof(buf), "\"%s\" - \"%s\"",
				hexmem(tmp[6].data(), tmp[6].size()).c_str(),
				hexmem(tmp[7].data(), tmp[7].size()).c_str()
				);
			resp->push_back(buf);
		}
	}

	if(req.size() == 1 || req[1] == "leveldb"){
		std::vector<std::string> tmp = serv->ssdb->info();
		for(int i=0; i<(int)tmp.size(); i++){
			std::string block = tmp[i];
			resp->push_back(block);
		}
	}

	if(req.size() > 1 && req[1] == "cmd"){
		proc_map_t::iterator it;
		for(it=net->proc_map.begin(); it!=net->proc_map.end(); it++){
			Command *cmd = it->second;
			resp->push_back("cmd." + cmd->name);
			char buf[128];
			snprintf(buf, sizeof(buf), "calls: %" PRIu64 "\ttime_wait: %.0f\ttime_proc: %.0f",
				cmd->calls, cmd->time_wait, cmd->time_proc);
			resp->push_back(buf);
		}
	}
	
	return 0;
}

int proc_slaveof(NetworkServer *net, Link *link, const Request &req, Response *resp){
    SSDBServer *serv = (SSDBServer *)net->data; 

    if (req.size() < 3 ||
            (req.size() == 3 && (req[1] != "no" || req[2] != "one"))) {
        resp->push_back("client_error");
        return 0;
    }

    // slaveof no one, stop slave threads
    if (req[1] == "no" && req[2] == "one") {
        serv->destroy_all_slaves();

        // FIXME log more info: current replication masters, current position
        log_info("slaveof no one");
        resp->reply_status(0, NULL);
        return 0;
    } 
    
    // slaveof master_ip master_port (mirror|sync) [id]

    std::string ip = req[1].String();
    int port = req[2].Int();
    std::string type = req[3].String();
    std::string id = req.size() >= 5 ? req[4].String() : "";

    int status = serv->create_slave(ip, port, type, id);

    if (status == 0) {
        resp->reply_status(0, NULL);
    } else {
        resp->reply_status(-1, "create slave failed");
    }
    // FIXME dump ssdb.conf
    return 0;
}

size_t memory_used() {
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

