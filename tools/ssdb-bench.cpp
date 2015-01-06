/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <string>
#include <vector>
#include <map>
#include "net/link.h"
#include "net/fde.h"
#include "util/log.h"
#include "util/strings.h"
#include "version.h"

#include "../src/include.h"

struct Data
{
	std::string key;
	std::string val;
	std::string num;
};

std::map<std::string, Data *> *ds;
Fdevents *fdes;
std::vector<Link *> *free_links;

std::vector<std::string> test_cases;

void welcome(){
	printf("ssdb-bench - SSDB benchmark tool, %s\n", SSDB_VERSION);
	printf("Copyright (c) 2013-2014 ssdb.io\n");
	printf("\n");
}

void usage(int argc, char **argv){
	printf("Usage:\n");
	printf("    %s [-h host] [-p port] [-n requests] [-c clients] [-s size] [-t test_cases] [-s size]\n", argv[0]);
	printf("\n");
	printf("Options:\n");
	printf("    ip          server ip (default 127.0.0.1)\n");
	printf("    port        server port (default 8888)\n");
	printf("    requests    Total number of requests (default 10000)\n");
	printf("    clients     Number of parallel connections (default 50)\n");
	printf("    size        Size of item\n");
	printf("    test_case   change the test_case to run, default is all. for example: set or set,get or set,get,hset,hget\n");
	printf("\n");
}

bool is_test_case(std::string cmd){
    if (test_cases.empty()) {
        // all case
        return true;
    }

    for(std::vector<std::string>::iterator it = test_cases.begin(); it != test_cases.end(); it ++) {
        if (*it == cmd) {
            return true;
        }
    }

    return false;
}

void init_data(int num, int size){
	srand(time(NULL));
    char buf[32];
    snprintf(buf,sizeof(buf),"%d",size);
    std::string tmp;
    tmp.append("%0");
    tmp.append(buf);
    tmp.append("d");
    
	ds = new std::map<std::string, Data *>();
	while(ds->size() < num){
		Data *d = new Data();
		char buf[1024];

		int n = rand();
		snprintf(buf, sizeof(buf), "%d", n);
		d->num = buf;
		snprintf(buf, sizeof(buf), "%ld", ds->size());
		d->key = buf;
		snprintf(buf, sizeof(buf), tmp.c_str(), n);
		d->val = buf;
		ds->insert(make_pair(d->num, d));
	}
}

void init_links(int num, const char *ip, int port){
	fdes = new Fdevents();
	free_links = new std::vector<Link *>();

	for(int i=0; i<num; i++){
		Link *link = Link::connect(ip, port);
		if(!link){
			fprintf(stderr, "connect error! %s\n", strerror(errno));
			exit(0);
		}
		fdes->set(link->fd(), FDEVENT_IN, 0, link);
		free_links->push_back(link);
	}
}

void send_req(Link *link, const std::string &cmd, const Data *d){
	if(cmd == "set"){
		link->send(cmd, d->key, d->val);
	}else if(cmd == "get"){
		link->send(cmd, d->key);
	}else if(cmd == "del"){
		link->send(cmd, d->key);
	}else if(cmd == "hset"){
		link->send(cmd, "TEST", d->key, d->val);
	}else if(cmd == "hget"){
		link->send(cmd, "TEST", d->key);
	}else if(cmd == "hdel"){
		link->send(cmd, "TEST", d->key);
	}else if(cmd == "zset"){
		link->send(cmd, "TEST", d->key, d->num);
	}else if(cmd == "zget"){
		link->send(cmd, "TEST", d->key);
	}else if(cmd == "zdel"){
		link->send(cmd, "TEST", d->key);
	}else if(cmd == "qpush"){
		link->send(cmd, "TEST", d->key);
	}else if(cmd == "qpop"){
		link->send(cmd, "TEST");
	}else{
		log_error("bad command!");
		exit(0);
	}
	link->flush();
}

void bench(std::string cmd){
	if (!is_test_case(cmd)) {
		return;
	}

	int total = (int)ds->size();
	int finished = 0;
	int num_sent = 0;
	
	printf("========== %s ==========\n", cmd.c_str());

	std::map<std::string, Data *>::iterator it;
	it = ds->begin();
	
	double stime = millitime();
	while(1){
		while(!free_links->empty()){
			if(num_sent == total){
				break;
			}
			num_sent ++;

			Link *link = free_links->back();
			free_links->pop_back();
			
			send_req(link, cmd, it->second);
			it ++;
		}

		const Fdevents::events_t *events;
		events = fdes->wait(50);
		if(events == NULL){
			log_error("events.wait error: %s", strerror(errno));
			break;
		}

		for(int i=0; i<(int)events->size(); i++){
			const Fdevent *fde = events->at(i);
			Link *link = (Link *)fde->data.ptr;

			int len = link->read();
			if(len <= 0){
				log_error("fd: %d, read: %d, delete link", link->fd(), len);
				exit(0);
			}

			const std::vector<Bytes> *resp = link->recv();
			if(resp == NULL){
				log_error("error");
				break;
			}else if(resp->empty()){
				continue;
			}else{
				if(resp->at(0) != "ok"){
					log_error("bad response: %s", resp->at(0).String().c_str());
					exit(0);
				}
				free_links->push_back(link);
				finished ++;
				if(finished == total){
					double etime = millitime();
					double ts = (stime == etime)? 1 : (etime - stime);
					double speed = total / ts;
					printf("qps: %d, time: %.3f s\n", (int)speed, ts);
					return;
				}
			}
		}
	}
}


int main(int argc, char **argv){
	const char *ip = "127.0.0.1";
	int port = 8888;
	int requests = 10000;
	int clients = 50;
	int size = 100;

	welcome();
	usage(argc, argv);
    
	if((argc - 1) % 2 != 0) {
	    printf("Param error***************************\n");
        exit(0);
    }

	for(int i=1; i<argc; i++){
		if(strcmp("-v", argv[i]) == 0){
			exit(0);
		} else if(strcmp("-p", argv[i]) == 0) {
            port = atoi(argv[++i]);
        } else if(strcmp("-h", argv[i]) == 0) {
            ip = argv[++i];
        } else if(strcmp("-c", argv[i]) == 0) {
            clients = atoi(argv[++i]);
        } else if(strcmp("-n", argv[i]) == 0) {
            requests = atoi(argv[++i]);
        } else if(strcmp("-n", argv[i]) == 0) {
            size = atoi(argv[++i]);
        } else if(strcmp("-t", argv[i]) == 0) {
            str_split(argv[++i], test_cases, ","); 
        } else {
	        printf("Param error***************************\n");
            exit(0);
        }
	}

	//printf("preparing data...\n");
	init_data(requests, size);
	//printf("preparing links...\n");
	init_links(clients, ip, port);

	bench("set");
	bench("get");
	bench("del");

	bench("hset");
	bench("hget");
	bench("hdel");

	bench("zset");
	bench("zget");
	bench("zdel");

	bench("qpush");
	bench("qpop");
    
	printf("\n");

	return 0;
}

