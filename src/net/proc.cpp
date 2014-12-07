/*
Copyright (c) 2012-2014 The SSDB Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
*/
#include "proc.h"
#include "server.h"
#include "../util/log.h"

ProcMap::ProcMap(){
}

ProcMap::~ProcMap(){
	proc_map_t::iterator it;
	for(it=proc_map.begin(); it!=proc_map.end(); it++){
		delete it->second;
	}
	proc_map.clear();
}

void ProcMap::set_proc(const std::string &c, proc_t proc){
	this->set_proc(c, "t", proc);
}

void ProcMap::set_proc(const std::string &c, const char *sflags, proc_t proc){
	Command *cmd = this->get_proc(c);
	if(!cmd){
		cmd = new Command();
		cmd->name = c;
		proc_map[cmd->name] = cmd;
	}
	cmd->proc = proc;
	cmd->flags = 0;
	for(const char *p=sflags; *p!='\0'; p++){
		switch(*p){
			case 'r':
				cmd->flags |= Command::FLAG_READ;
				break;
			case 'w':
				cmd->flags |= Command::FLAG_WRITE;
				break;
			case 'b':
				cmd->flags |= Command::FLAG_BACKEND;
				break;
			case 't':
				cmd->flags |= Command::FLAG_THREAD;
				break;
		}
	}
}

Command* ProcMap::get_proc(const Bytes &str){
	proc_map_t::iterator it = proc_map.find(str);
	if(it != proc_map.end()){
		return it->second;
	}
	return NULL;
}

// FIXME 待性能优化，pattern被多次解析
/*
 * support pattern:
 *      string 
 *      string*  (prefix match)
 *      *string  (suffix match)
 *      *string* (fuzzy match)
 *
 *  Return:
 *      true is match, false is not match.
 */
bool is_pattern_match(const std::string &source, std::string pattern) {
    if (pattern.empty()) {
        return false;
    }

    bool is_match_all = true;
    for (int i = 0; i < pattern.size(); i ++) {
        if (pattern.at(i) != '*') {
            is_match_all = false;
            break;
        }
    }

    if (is_match_all) {
        return true;
    }

    bool prefix_not_pattern = (pattern.at(0) != '*');
    bool suffix_not_pattern = (pattern.at(pattern.size()-1) != '*');

    std::string::size_type startpos = 0;  
    while (startpos!= std::string::npos){
        startpos = pattern.find('*');
        if(startpos != std::string::npos){ 
          pattern.replace(startpos,1,"");
        }
    } 

    if (source.size() < pattern.size()) {
        return false;
    }

    if (prefix_not_pattern && suffix_not_pattern) {
        return source.compare(pattern) == 0;
    }

    if (prefix_not_pattern) {
        return pattern.compare(source.substr(0,pattern.size())) == 0;
    }

    if (suffix_not_pattern) {
        return pattern.compare(source.substr(source.size()-pattern.size(),pattern.size())) == 0;
    }

    return source.find(pattern) != std::string::npos;
}
