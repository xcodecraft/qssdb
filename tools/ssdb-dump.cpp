/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "include.h"
#include <sys/types.h>
#include <sys/stat.h>

#include <string>
#include <vector>

#include "leveldb/db.h"
#include "leveldb/options.h"
#include "leveldb/slice.h"
#include "leveldb/iterator.h"
#include "leveldb/filter_policy.h"
#include "leveldb/cache.h"

#include "include.h"
#include "ssdb/const.h"
#include "ssdb/options.h"
#include "ssdb/t_hash.h"
#include "ssdb/binlog.h"
#include "net/link.h"
#include "util/log.h"
#include "util/file.h"
#include "util/strings.h"

struct DumpConf {
	std::string ip;
	int port;
	std::string auth;
	std::string output_folder;
	std::string conf_file;
	std::string id;
};

DumpConf dump_conf;
Options opt;
Config *conf = NULL;

template<class T>
static std::string serialize_req(T &req){
	std::string ret;
	char buf[50];
	for(int i=0; i<req.size(); i++){
		if(i >= 5 && i < req.size() - 1){
			sprintf(buf, "[%d more...]", (int)req.size() - i - 1);
			ret.append(buf);
			break;
		}
		if(((req[0] == "get" || req[0] == "set") && i == 1) || req[i].size() < 30){
			std::string h = hexmem(req[i].data(), req[i].size());
			ret.append(h);
		}else{
			sprintf(buf, "[%d bytes]", (int)req[i].size());
			ret.append(buf);
		}
		if(i < req.size() - 1){
			ret.append(" ");
		}
	}
	return ret;
}

void welcome(){
	printf("ssdb-dump - SSDB backup command\n");
	printf("Copyright (c) 2012-2014 ssdb.io\n");
	printf("\n");
}

void usage(int argc, char **argv){
	printf("Usage: %s -o output_folder -f conf_file\n"
			"  -h <hostname>      Server hostname (default: 127.0.0.1).\n"
			"  -p <port>          Server port (default: 8888).\n"
			"  -a <password>      Password to use when connecting to the server.\n"
			"  -o <output_folder> local backup folder that will be created.\n"
			"  -f <conf_file>     conf file that the server used\n"
			"  -i <id>            dump id (the same with sync id)"
			"\n",
			argv[0]);
	exit(1);
}

int parse_options(DumpConf *dump_conf, int argc, char **argv){
	int i;
	for(i = 1; i < argc; i++) {
		bool lastarg = i==argc-1;
		if(!strcmp(argv[i],"-h") && !lastarg){
			dump_conf->ip = argv[++i];
		}else if(!strcmp(argv[i], "-h") && lastarg){
			usage(argc, argv);
		}else if(!strcmp(argv[i], "-p") && !lastarg){
			dump_conf->port = atoi(argv[++i]);
		}else if(!strcmp(argv[i], "-a") && !lastarg){
			dump_conf->auth = argv[++i];
		}else if(!strcmp(argv[i], "-o") && !lastarg){
			dump_conf->output_folder = argv[++i];
		}else if(!strcmp(argv[i], "-f") && !lastarg){
			dump_conf->conf_file = argv[++i];
		}else if(!strcmp(argv[i], "-i") && !lastarg){
			dump_conf->id = argv[++i];
		}else{
			if(argv[i][0] == '-'){
				fprintf(stderr,
					"Unrecognized option or bad number of args for: '%s'\n",
					argv[i]);
					exit(1);
			}else{
				/* Likely the command name, stop here. */
				break;
			}
		}
	}
	return i;
}

void init_conf()
{
	if (dump_conf.conf_file.empty()) {
	    return;
	}
	conf = Config::load(dump_conf.conf_file.c_str());
	if(!conf){
		fprintf(stderr, "error loading conf file %s\n", dump_conf.conf_file.c_str());
		exit(1);
	}
	opt.load(*conf);
}

// data
leveldb::Status db_open(Options &opt, std::string &data_dir, leveldb::DB **db)
{
	leveldb::Status status;
	leveldb::Options options;
	options.create_if_missing = true;
	options.max_open_files = opt.max_open_files;
	options.filter_policy = leveldb::NewBloomFilterPolicy(10);
	options.block_size = opt.block_size * 1024;
	options.write_buffer_size = opt.write_buffer_size * 1024 *1024;
	options.compaction_speed = opt.compaction_speed;
	if(opt.compression == "yes"){
		options.compression = leveldb::kSnappyCompression;
	}else{
		options.compression = leveldb::kNoCompression;
	}
	status = leveldb::DB::Open(options, data_dir, db);
	return status;
}

// binlog
leveldb::Status binlog_open(Options &opt, std::string &data_dir, leveldb::DB **db)
{
	leveldb::Options options;
	options.create_if_missing = true;
	options.compression = leveldb::kSnappyCompression; // default compression
	options.block_size = opt.block_size * 1024;
	options.write_buffer_size = opt.write_buffer_size * 1024 *1024;

	return leveldb::DB::Open(options, data_dir, db);
}

int save_sync_status(DumpConf *dump_conf, leveldb::DB *meta_db, uint64_t last_seq)
{
	std::string status_key;

	if(dump_conf->id.empty()) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s|%d", dump_conf->ip.c_str(), dump_conf->port);
        status_key = SLAVE_STATUS_PREFIX + buf;
	} else {
        status_key = SLAVE_STATUS_PREFIX + dump_conf->id;
	}

	std::string hkey_last_seq = encode_hash_key(status_key, "last_seq");
    leveldb::Status status = meta_db->Put(leveldb::WriteOptions(), hkey_last_seq, str(last_seq));
    if(!status.ok()) {
        return -1;
    }
	std::string hkey_last_key = encode_hash_key(status_key, "last_key");
    status = meta_db->Put(leveldb::WriteOptions(), hkey_last_key, "");
    if(!status.ok()) {
        return -1;
    }
    return 0;
}

void dump_end(DumpConf *dump_conf, leveldb::DB *meta_db, BinlogQueue *binlogs, uint64_t last_seq)
{
    if(last_seq == 0) {
        return;
    }

    int res;
    res = save_sync_status(dump_conf, meta_db, last_seq);
    if(res == -1){
        fprintf(stderr, "save last_seq to meta error!\n");
        fprintf(stderr, "ERROR: failed to dump data!\n");
        exit(1);
    }
    res = binlogs->update(last_seq, BinlogType::NOOP, BinlogCommand::NONE, "", "");
    if(res == -1){
        fprintf(stderr, "save last_seq to binlog error!\n");
        fprintf(stderr, "ERROR: failed to dump data!\n");
        exit(1);
    }
}

int main(int argc, char **argv){
	welcome();
	set_log_level(Logger::LEVEL_MIN);

	dump_conf.ip = "127.0.0.1";
	dump_conf.port = 0;

	parse_options(&dump_conf, argc, argv);
	init_conf();

	if(dump_conf.auth.empty() && conf != NULL){
		dump_conf.auth = conf->get_str("server.auth");
	}

	if(dump_conf.port == 0) {
	    if(conf != NULL) {
		    dump_conf.port = conf->get_num("server.port");
	    } else {
		    dump_conf.port = 8888;
	    }
	}
	if(dump_conf.output_folder.empty()){
		fprintf(stderr, "ERROR: -o <output_folder> is required!\n");
		usage(argc, argv);
		exit(1);
	}

	if(file_exists(dump_conf.output_folder.c_str())){
		fprintf(stderr, "ERROR: output_folder[%s] exists!\n", dump_conf.output_folder.c_str());
		exit(1);
	}
	if(mkdir(dump_conf.output_folder.c_str(), 0777) == -1){
		fprintf(stderr, "ERROR: error create backup directory!\n");
		exit(1);
	}

	std::string data_dir = dump_conf.output_folder;
	data_dir.append("/data");

	std::string binlog_dir = data_dir;
	binlog_dir.append("_binlog");

	std::string meta_dir = dump_conf.output_folder;
	meta_dir.append("/meta");

	// connect to server
	Link *link = Link::connect(dump_conf.ip.c_str(), dump_conf.port);
	if(link == NULL){
		fprintf(stderr, "ERROR: error connecting to server: %s:%d!\n", dump_conf.ip.c_str(),dump_conf.port);
		exit(1);
	}
	if(!dump_conf.auth.empty()){
		const std::vector<Bytes> *resp = link->request("auth", dump_conf.auth.c_str());
		if(resp == NULL || resp->at(0) != "ok"){
			fprintf(stderr, "ERROR: auth error!\n");
			exit(1);
		}
	}
	link->send("dump", "A", "", "-1");
	link->flush();

	leveldb::DB* data_db;
	leveldb::DB* meta_db;
	leveldb::DB* binlog_db;
	BinlogQueue* binlogs;
	leveldb::Status status;

	status = db_open(opt, data_dir, &data_db);
	if(!status.ok()){
		fprintf(stderr, "ERROR: open leveldb data: %s error!\n", data_dir.c_str());
		exit(1);
	}

	status = binlog_open(opt, binlog_dir, &binlog_db);
	if(!status.ok()){
		fprintf(stderr, "ERROR: open leveldb binlog: %s error!\n", binlog_dir.c_str());
		exit(1);
	}
	binlogs = new BinlogQueue(data_db, binlog_db, opt.binlog_capacity, true);

	Options default_options;
	status = db_open(default_options, meta_dir, &meta_db);
	if(!status.ok()){
		fprintf(stderr, "ERROR: open leveldb meta: %s error!\n", meta_dir.c_str());
		exit(1);
	}

	uint64_t dump_count = 0;
	uint64_t last_seq = 0;
	while(1){
		const std::vector<Bytes> *req = link->recv();
		if(req == NULL){
			fprintf(stderr, "recv error\n");
			fprintf(stderr, "ERROR: failed to dump data!\n");
			exit(1);
		}else if(req->empty()){
			int len = link->read();
			if(len <= 0){
				fprintf(stderr, "read error: %s\n", strerror(errno));
				fprintf(stderr, "ERROR: failed to dump data!\n");
				exit(1);
			}
		}else{
			Bytes cmd = req->at(0);
			if(cmd == "begin"){
				printf("recv begin...\n");
			}else if(cmd == "end"){
				dump_end(&dump_conf, meta_db, binlogs, last_seq);
				printf("received %ld entry(s)\n", dump_count);
				printf("recv end\n\n");
				break;
			}else if(cmd == "set_offset"){
				if(req->size() != 2){
					fprintf(stderr, "invalid set_offset params!\n");
					fprintf(stderr, "ERROR: failed to dump data!\n");
					exit(1);
				}
				last_seq = req->at(1).Uint64();
				if(errno != 0) {
					fprintf(stderr, "invalid set_offset params!\n");
					fprintf(stderr, "ERROR: failed to dump data!\n");
					exit(1);
				}
				printf("recv set_offset, last_seq %ld \n", last_seq);
			}else if(cmd == "set"){
                /*
                std::string s = serialize_req(*req);
                printf("%s\n", s.c_str());
                */

				if(req->size() != 3){
					fprintf(stderr, "invalid set params!\n");
					fprintf(stderr, "ERROR: failed to dump data!\n");
					exit(1);
				}
				Bytes key = req->at(1);
				Bytes val = req->at(2);
				if(key.size() == 0 || key.data()[0] == DataType::SYNCLOG){
					continue;
				}

				leveldb::Slice k(key.data(), key.size());
				leveldb::Slice v(val.data(), val.size());
				status = data_db->Put(leveldb::WriteOptions(), k, v);
				// printf("set %s %s\n", str_escape(key.data(), key.size()).c_str(), str_escape(val.data(), val.size()).c_str());
				if(!status.ok()){
					fprintf(stderr, "put leveldb error!\n");
					fprintf(stderr, "ERROR: failed to dump data!\n");
					exit(1);
				}

				dump_count ++;
				if((uint64_t)log10(dump_count - 1) != (uint64_t)log10(dump_count) || (dump_count > 0 && dump_count % 50000 == 0)){
					printf("received %ld entry(s)\n", dump_count);
				}
			}else{
				fprintf(stderr, "error: unknown command %s\n", std::string(cmd.data(), cmd.size()).c_str());
				fprintf(stderr, "ERROR: failed to dump data!\n");
				exit(1);
			}
		}
	}
	printf("total dumped %ld entry(s)\n", dump_count);

	/*
	printf("checking data...\n");
	leveldb::Iterator *it;
	it = db->NewIterator(leveldb::ReadOptions());
	int save_count = 0;
	for(it->SeekToFirst(); it->Valid(); it->Next()){
		save_count ++;
		//std::string k = hexmem(it->key().data(), it->key().size());
		//std::string v = hexmem(it->value().data(), it->value().size());
		//printf("%d %s : %s", save_count, k.c_str(), v.c_str());
	}
	if(dump_count != save_count){
        printf("checking failed! dumped: %d, saved: %d\n", dump_count, save_count);
	}else{
        printf("checking OK.\n");
        printf("\n");
	}
	*/

	{
		std::string val;
		if(data_db->GetProperty("leveldb.stats", &val)){
			printf("%s\n", val.c_str());
		}
	}

	printf("compacting data...\n");
	data_db->CompactRange(NULL, NULL);

	{
		std::string val;
		if(data_db->GetProperty("leveldb.stats", &val)){
			printf("%s\n", val.c_str());
		}
	}

	printf("backup has been made to folder: %s\n", dump_conf.output_folder.c_str());

	delete link;
	delete data_db;
	delete meta_db;
	delete binlogs;
	delete binlog_db;
	return 0;
}
