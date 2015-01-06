/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "server.h"
#include "../util/strings.h"
#include "../util/file.h"
#include "../util/config.h"
#include "../util/log.h"
#include "../util/ip_filter.h"
#include "link.h"
#include <vector>

static DEF_PROC(ping);
static DEF_PROC(info);
static DEF_PROC(auth);

#define TICK_INTERVAL          100 // ms
#define STATUS_REPORT_TICKS    (300 * 1000/TICK_INTERVAL) // second

#define DEFAULT_SLOW_TIME       10 // 10 ms
#define DEFAULT_TIMEOUT         INT_MAX // not timeout
#define DEFAULT_OUTPUT_LIMIT    (1024 * 1024 * 100) // 100 MB

volatile bool quit = false;
volatile uint32_t g_ticks = 0;

void signal_handler(int sig){
	switch(sig){
		case SIGTERM:
		case SIGINT:{
			quit = true;
			break;
		}
		case SIGALRM:{
			g_ticks ++;
			break;
		}
	}
}

NetworkServer::NetworkServer(){
	tick_interval = TICK_INTERVAL;
	status_report_ticks = STATUS_REPORT_TICKS;

	//conf = NULL;
	serv_link = NULL;
	link_count = 0;
    max_connections = INT_MAX;
    client_output_limit = DEFAULT_OUTPUT_LIMIT;
    timeout = DEFAULT_TIMEOUT;
    slow_time = DEFAULT_SLOW_TIME;
    readonly = false;

    bytes_read = 0;
    bytes_written = 0;

	fdes = new Fdevents();
	ip_filter = new IpFilter();

	// add built-in procs, can be overridden
	proc_map.set_proc("ping", "r", proc_ping);
	proc_map.set_proc("info", "r", proc_info);
	proc_map.set_proc("auth", "r", proc_auth);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#ifndef __CYGWIN__
	signal(SIGALRM, signal_handler);
	{
		struct itimerval tv;
		tv.it_interval.tv_sec = (TICK_INTERVAL / 1000);
		tv.it_interval.tv_usec = (TICK_INTERVAL % 1000) * 1000;
		tv.it_value.tv_sec = 1;
		tv.it_value.tv_usec = 0;
		setitimer(ITIMER_REAL, &tv, NULL);
	}
#endif
}
	
NetworkServer::~NetworkServer(){
	//delete conf;
	delete serv_link;
	delete fdes;
	delete ip_filter;

	writer->stop();
	delete writer;
	reader->stop();
	delete reader;
}

NetworkServer* NetworkServer::init(const char *conf_file){
	if(!is_file(conf_file)){
		fprintf(stderr, "'%s' is not a file or not exists!\n", conf_file);
		exit(1);
	}

	Config *conf = Config::load(conf_file);
	if(!conf){
		fprintf(stderr, "error loading conf file: '%s'\n", conf_file);
		exit(1);
	}
	{
		std::string conf_dir = real_dirname(conf_file);
		if(chdir(conf_dir.c_str()) == -1){
			fprintf(stderr, "error chdir: %s\n", conf_dir.c_str());
			exit(1);
		}
	}
	NetworkServer* serv = init(*conf);
	delete conf;
	return serv;
}

NetworkServer* NetworkServer::init(const Config &conf){
	static bool inited = false;
	if(inited){
		return NULL;
	}
	inited = true;
	
	NetworkServer *serv = new NetworkServer();
	// init ip_filter
	{
		Config *cc = (Config *)conf.get("server");
		if(cc != NULL){
			std::vector<Config *> *children = &cc->children;
			std::vector<Config *>::iterator it;
			for(it = children->begin(); it != children->end(); it++){
				if((*it)->key == "allow"){
					std::string val = (*it)->str();
					log_info("    allow %s", val.c_str());
					std::vector<std::string> ips;
					str_split(val, ips, ",");
					for(std::vector<std::string>::iterator it = ips.begin(); it != ips.end(); it ++) {
					    serv->ip_filter->add_allow(*it);
					}
				}
				if((*it)->key == "deny"){
					std::string val = (*it)->str();
					log_info("    deny %s", val.c_str());
					std::vector<std::string> ips;
					str_split(val, ips, ",");
					for(std::vector<std::string>::iterator it = ips.begin(); it != ips.end(); it ++) {
					    serv->ip_filter->add_deny(*it);
					}
				}
				if((*it)->key == "max_connections"){
					int max_connections = (*it)->num();
					log_info("    max_connections %d", max_connections);
                    if (max_connections > 0) {
                        serv->max_connections = max_connections;
                    }
				}
				if((*it)->key == "client_output_limit"){
					int64_t client_output_limit = (*it)->num();
					log_info("    client_output_limit %ld", client_output_limit);
                    if (client_output_limit > 0) {
                        serv->client_output_limit = client_output_limit;
                    }
				}
				if((*it)->key == "timeout"){
					int timeout = (*it)->num();
					log_info("    timeout %d", timeout);
                    if (timeout > 0) {
                        serv->timeout = timeout;
                    }
				}
				if((*it)->key == "readonly"){
					std::string val = (*it)->str();
					log_info("    readonly %s", val.c_str());
					if (val == "yes") {
					    serv->readonly = true;
					}
				}
				if((*it)->key == "slow_time"){
					int slow_time = (*it)->num();
					log_info("    slow_time %d", slow_time);
					if (slow_time > 0) {
					    serv->slow_time = slow_time;
					}
				}
			}
		}
	}
	
	{ // server
		const char *ip = conf.get_str("server.ip");
		int port = conf.get_num("server.port");
		if(ip == NULL || ip[0] == '\0'){
			ip = "127.0.0.1";
		}
		
		serv->serv_link = Link::listen(ip, port);
		if(serv->serv_link == NULL){
			log_fatal("error opening server socket! %s", strerror(errno));
			fprintf(stderr, "error opening server socket! %s\n", strerror(errno));
			exit(1);
		}
		log_info("server listen on %s:%d", ip, port);

		std::string password;
		password = conf.get_str("server.auth");
		if(password.empty()){
			log_info("auth: off");
		}else{
			log_info("auth: on");
		}
		serv->need_auth = false;		
		if(!password.empty()){
			serv->need_auth = true;
			serv->password = password;
		}
	}
	return serv;
}

void NetworkServer::serve(){
	writer = new ProcWorkerPool("writer");
	writer->start(WRITER_THREADS);
	reader = new ProcWorkerPool("reader");
	reader->start(READER_THREADS);

	ready_list_t ready_list;
	ready_list_t ready_list_2;
	ready_list_t::iterator it;
	const Fdevents::events_t *events;

	fdes->set(serv_link->fd(), FDEVENT_IN, 0, serv_link);
	fdes->set(this->reader->fd(), FDEVENT_IN, 0, this->reader);
	fdes->set(this->writer->fd(), FDEVENT_IN, 0, this->writer);
	
	uint32_t last_ticks = g_ticks;
	
	while(!quit){
		// status report
		if((uint32_t)(g_ticks - last_ticks) >= STATUS_REPORT_TICKS){
			last_ticks = g_ticks;
			log_info("server running, links: %d", this->link_count);
		}
		
		ready_list.swap(ready_list_2);
		ready_list_2.clear();
		
		if(!ready_list.empty()){
			// ready_list not empty, so we should return immediately
			events = fdes->wait(0);
		}else{
			events = fdes->wait(50);
		}
		if(events == NULL){
			log_fatal("events.wait error: %s", strerror(errno));
			break;
		}
		
		for(int i=0; i<(int)events->size(); i++){
			const Fdevent *fde = events->at(i);
			if(fde->data.ptr == serv_link){
				Link *link = accept_link();
				if(link){
					this->link_count ++;				
					log_debug("new link from %s:%d, fd: %d, links: %d",
						link->remote_ip, link->remote_port, link->fd(), this->link_count);
					fdes->set(link->fd(), FDEVENT_IN, 1, link);
				}
			}else if(fde->data.ptr == this->reader || fde->data.ptr == this->writer){
				ProcWorkerPool *worker = (ProcWorkerPool *)fde->data.ptr;
				ProcJob job;
				if(worker->pop(&job) == 0){
					log_fatal("reading result from workers error!");
					exit(0);
				}
				if(proc_result(&job, &ready_list) == PROC_ERROR){
					//
                }
			}else{
				proc_client_event(fde, &ready_list);
			}
		}

		for(it = ready_list.begin(); it != ready_list.end(); it ++){
			Link *link = *it;
			if(link->error()){
                destroy_link(link);
				continue;
			}

			const Request *req = link->recv();
			if(req == NULL){
				log_warn("fd: %d, link parse error, delete link", link->fd());
                destroy_link(link);
				continue;
			}
			if(req->empty()){
				link->unRef();
				fdes->set(link->fd(), FDEVENT_IN, 1, link);
				log_debug("serve parse incomplete request, remote_ip: %s ref: %d", link->remote_ip, link->ref_count);
				continue;
			}
			
			link->active_time = millitime();
            //FIXME
			char remote_ip_port[32];
		    snprintf(remote_ip_port, 32, "%s:%d", link->remote_ip, link->remote_port);
			this->active_links.add(remote_ip_port,(int64_t)link->active_time);

			ProcJob job;
			job.link = link;
			this->proc(&job);
			if(job.result == PROC_THREAD){
				fdes->del(link->fd());
				continue;
			}
			if(job.result == PROC_BACKEND){
				fdes->del(link->fd());
				this->link_count --;
                char remote_ip_port[32];
                snprintf(remote_ip_port, 32, "%s:%d", link->remote_ip, link->remote_port);
                this->link_map.erase(remote_ip_port);
                this->active_links.del(remote_ip_port);
                // don't delete link
				continue;
			}
			
			if(proc_result(&job, &ready_list_2) == PROC_ERROR){
				//
            }
		} // end foreach ready link

        //every event loop
        destroy_idle_link();
	}
}

Link* NetworkServer::accept_link(){
	Link *link = serv_link->accept();
	if(link == NULL){
		log_error("accept failed! %s", strerror(errno));
		return NULL;
	}
	if(!ip_filter->check_pass(link->remote_ip)){
		log_debug("ip_filter deny link from %s:%d", link->remote_ip, link->remote_port);
		delete link;
		return NULL;
	}
    if ((this->link_count >= this->max_connections) && strcmp(link->remote_ip, "127.0.0.1") != 0) {
		log_debug("connection is over the limit. current %d max %d", this->link_count, this->max_connections);
		delete link;
        return NULL;
    }
				
	link->nodelay();
	link->noblock();
	link->create_time = millitime();
	link->active_time = link->create_time;

    char remote_ip_port[32];
    snprintf(remote_ip_port, 32, "%s:%d", link->remote_ip, link->remote_port);
    this->link_map[remote_ip_port] = link;
    this->active_links.add(remote_ip_port,(int64_t)link->active_time);

	return link;
}

void NetworkServer::destroy_link(Link *link){
	this->link_count --;
	this->fdes->del(link->fd());

    char remote_ip_port[32];
    snprintf(remote_ip_port, 32, "%s:%d", link->remote_ip, link->remote_port);
    this->link_map.erase(remote_ip_port);
    this->active_links.del(remote_ip_port);
	delete link;
}

int NetworkServer::proc_result(ProcJob *job, ready_list_t *ready_list){
	Link *link = job->link;
	int len;
			
	if(job->cmd){
		job->cmd->calls += 1;
		job->cmd->time_wait += job->time_wait;
		job->cmd->time_proc += job->time_proc;

		double total_time = job->time_wait + job->time_proc;
		if (total_time >= this->slow_time) {
		    slowlog_warn("proc slow, remote_ip: %s wait: %.3f proc: %.3f total: %.3f req: %s", 
                    link->remote_ip, job->time_wait, job->time_proc, total_time, 
			        serialize_req(*link->last_recv()).c_str());
		}
	}
	if(job->result == PROC_ERROR){
		log_info("fd: %d, proc error, delete link", link->fd());
		goto proc_err;
	}
    if(link->error()){
		log_debug("fd: %d, link error, delete link", link->fd());
		goto proc_err;
    }
	
	len = link->write();
	//log_debug("write: %d", len);
	if(len < 0){
		log_debug("fd: %d, write: %d, delete link", link->fd(), len);
		goto proc_err;
	}
	this->bytes_written += len;

	if(!link->output->empty()){
		fdes->set(link->fd(), FDEVENT_OUT, 1, link);
	}
	if(link->input->empty()){
		fdes->set(link->fd(), FDEVENT_IN, 1, link);
        link->unRef();
        log_debug("proc_result remote_ip: %s ref: %d", link->remote_ip, link->ref_count);
	}else{
		fdes->clr(link->fd(), FDEVENT_IN);
		ready_list->push_back(link);
	}
	return PROC_OK;

proc_err:
    destroy_link(link);
	return PROC_ERROR;
}

/*
event:
	read => ready_list OR close
	write => NONE
proc =>
	done: write & (read OR ready_list)
	async: stop (read & write)
	
1. When writing to a link, it may happen to be in the ready_list,
so we cannot close that link in write process, we could only
just mark it as closed.

2. When reading from a link, it is never in the ready_list, so it
is safe to close it in read process, also safe to put it into
ready_list.

3. Ignore FDEVENT_ERR

A link is in either one of these places:
	1. ready list
	2. async worker queue
So it safe to delete link when processing ready list and async worker result.
*/
int NetworkServer::proc_client_event(const Fdevent *fde, ready_list_t *ready_list){
	Link *link = (Link *)fde->data.ptr;
	if(fde->events & FDEVENT_IN){
		link->ref();
		log_debug("proc_client_event remote_ip: %s ref: %d", link->remote_ip, link->ref_count);
		ready_list->push_back(link);
		if(link->error()){
			return 0;
		}
		int len = link->read();
		//log_debug("fd: %d read: %d", link->fd(), len);
		if(len <= 0){
			log_debug("fd: %d, read: %d, delete link", link->fd(), len);
			link->mark_error();
			return 0;
		}
		this->bytes_read += len;
	}
	if(fde->events & FDEVENT_OUT){
		if(link->error()){
			return 0;
		}
		int len = link->write();
		if(len <= 0){
			log_debug("fd: %d, write: %d, delete link", link->fd(), len);
			link->mark_error();
			return 0;
		}
		this->bytes_written += len;
		if(link->output->empty()){
			fdes->clr(link->fd(), FDEVENT_OUT);
		}
	}
	return 0;
}

void NetworkServer::proc(ProcJob *job){
	job->serv = this;
	job->result = PROC_OK;
	job->stime = millitime();

	const Request *req = job->link->last_recv();
	Response resp;

	do{
		// AUTH
		if(this->need_auth && job->link->auth == false && req->at(0) != "auth"){
			resp.push_back("noauth");
			resp.push_back("authentication required");
			break;
		}
		
		Command *cmd = proc_map.get_proc(req->at(0));
		if(!cmd){
			resp.push_back("client_error");
			resp.push_back("Unknown Command: " + req->at(0).String());
			break;
		}
		job->cmd = cmd;
		if (cmd->name != "client") {
			job->link->last_cmd = cmd->name;
        }

		if(cmd->flags & Command::FLAG_THREAD){
			if(cmd->flags & Command::FLAG_WRITE){
				if (this->readonly) {
				    resp.reply_status(-1, "server is readonly");
				    break;
				}
				job->result = PROC_THREAD;
				writer->push(*job);
			}else{
				job->result = PROC_THREAD;
				reader->push(*job);
			}
			return;
		}

		proc_t p = cmd->proc;
		job->time_wait = 1000 * (millitime() - job->stime);
		job->result = (*p)(this, job->link, *req, &resp);
		job->time_proc = 1000 * (millitime() - job->stime) - job->time_wait;
	}while(0);
	
	if(job->link->send(resp.resp) == -1){
		job->result = PROC_ERROR;
	}else{
		if(log_level() >= Logger::LEVEL_DEBUG){
			log_debug("w:%.3f,p:%.3f, req: %s, resp: %s",
				job->time_wait, job->time_proc,
				serialize_req(*req).c_str(),
				serialize_req(resp.resp).c_str());
		}
	}
}

/*
 * event loop will check the idle link, if idle > timeout, just destroy
 */
void NetworkServer::destroy_idle_link(){
    int loop = 0;
    int64_t current = (int64_t)millitime(); 

    while(loop < 100) {
        std::string key;
        int64_t active_time;
        this->active_links.front(&key, &active_time);

        if (key.empty()) {
            return;
        }

        if (active_time + this->timeout > current) {
            return;
        }

        Link *link = this->link_map[key];

        if (link == NULL) {
            log_warn("destroy_idle_link failed, link %s not exit", key.c_str());
            return;
        }

        log_info("destroy_idle_link success, destroy idle link: %s", key.c_str());

        if (link->ref_count == 0) {
            log_debug("destroy_idle_link destroy_link, link: %s", key.c_str());
            destroy_link(link); // delete link
        } else {
            log_debug("destroy_idle_link mark_error, link: %s", key.c_str());
            link->mark_error(); // mark link error
            // just for remove from sorted_set head, add 100s
            this->active_links.add(key,active_time + 100);
        }
        loop ++;
    }
}

/* built-in procs */

static int proc_ping(NetworkServer *net, Link *link, const Request &req, Response *resp){
	resp->push_back("ok");
	return 0;
}

static int proc_info(NetworkServer *net, Link *link, const Request &req, Response *resp){
	resp->push_back("ok");
	resp->push_back("ideawu's network server framework");
	resp->push_back("version");
	resp->push_back("1.0");
	resp->push_back("links");
	resp->add(net->link_count);
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
	return 0;
}

static int proc_auth(NetworkServer *net, Link *link, const Request &req, Response *resp){
	if(req.size() != 2){
		resp->push_back("client_error");
	}else{
		if(!net->need_auth || req[1] == net->password){
			link->auth = true;
			resp->push_back("ok");
			resp->push_back("1");
		}else{
			resp->push_back("error");
			resp->push_back("invalid password");
		}
	}
	return 0;
}
