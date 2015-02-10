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
bool is_pattern_match(const std::string &source, std::string &pattern, bool prefix_fuzzy_match, bool suffix_fuzzy_match) {
    if (source.size() < pattern.size()) {
        return false;
    }

    // check if equal
    if (!prefix_fuzzy_match && !suffix_fuzzy_match) {
        return source.compare(pattern) == 0;
    }

    // check if prefix match
    if (!prefix_fuzzy_match) {
        return pattern.compare(source.substr(0,pattern.size())) == 0;
    }

    // check if suffix match
    if (!suffix_fuzzy_match) {
        return pattern.compare(source.substr(source.size()-pattern.size(),pattern.size())) == 0;
    }

    // check if contain
    return source.find(pattern) != std::string::npos;
}

/*
 * parse pattern:
 *      string 
 *      string*  (prefix match)
 *      *string  (suffix match)
 *      *string* (fuzzy match)
 *
 * param and return:
 *      if patten is "*" or "", match_all is true, and then return
 *      if patten is startwith "*", prefix_fuzzy_match is true
 *      if patten is endwith "*", suffix_fuzzy_match is true
 */
void parse_scan_pattern(const std::string &source_pattern, std::string &pattern, bool &match_all, bool &prefix_fuzzy_match, bool &suffix_fuzzy_match) {
    pattern = source_pattern;
    match_all = true;
    if (pattern.empty()) {
        return;
    }

    for (int i = 0; i < pattern.size(); i ++) {
        if (pattern.at(i) != '*') {
            match_all = false;
            break;
        }
    }

    if (match_all) {
        return;
    }

    prefix_fuzzy_match = (pattern.at(0) == '*');
    suffix_fuzzy_match = (pattern.at(pattern.size()-1) == '*');

    std::string::size_type startpos = pattern.find('*');
    while (startpos != std::string::npos){
        pattern.replace(startpos,1,"");
        startpos = pattern.find('*');
    } 
}
