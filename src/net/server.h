/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#ifndef NET_SERVER_H_
#define NET_SERVER_H_

#include "../include.h"
#include "../util/sorted_set.h"
#include <string>
#include <vector>
#include <map>

#include "fde.h"
#include "proc.h"
#include "worker.h"

class Link;
class Config;
class IpFilter;
class Fdevents;

typedef std::vector<Link *> ready_list_t;
typedef std::map<std::string, Link *> link_map_t;

class NetworkServer
{
private:
	int tick_interval;
	int status_report_ticks;

	//Config *conf;
	Link *serv_link;
	IpFilter *ip_filter;
	Fdevents *fdes;

	Link* accept_link();

	int proc_result(ProcJob *job, ready_list_t *ready_list);
	int proc_client_event(const Fdevent *fde, ready_list_t *ready_list);

	void proc(ProcJob *job);

	static const int READER_THREADS = 10;
	static const int WRITER_THREADS = 1;
	ProcWorkerPool *writer;
	ProcWorkerPool *reader;

	NetworkServer();

protected:
	void usage(int argc, char **argv);

public:
	void *data;
	ProcMap proc_map;
    link_map_t link_map;
	SortedSet active_links;
	int link_count;
	bool need_auth;
	std::string password;
	int max_connections;
	int timeout; // second 
	uint64_t client_output_limit; // byte 
	uint64_t bytes_written; // byte 
	uint64_t bytes_read; // byte 

	~NetworkServer();
	
	// could be called only once
	static NetworkServer* init(const char *conf_file);
	static NetworkServer* init(const Config &conf);
	void serve();
	void destroy_link(Link *link);
	void destroy_idle_link();
};


#endif
