/*
Copyright (C) 2013-2020 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

class sinsp_filter_optimizer_entry
{
public:
	sinsp_filter* m_filter;
	string m_rule; // optional
	string m_filterstr; // optional
};

class field_ops
{
public:
	vector<string> m_equal;
	vector<string> m_contains;
	vector<string> m_icontains;
	vector<string> m_startswith;
	vector<string> m_endswith;
	vector<string> m_in;
	vector<string> m_pmatch;
	vector<string> m_other;
};

class match_stats
{
public:
	uint32_t m_equal = 0;
	uint32_t m_contains = 0;
	uint32_t m_icontains = 0;
	uint32_t m_startswith = 0;
	uint32_t m_endswith = 0;
	uint32_t m_in = 0;
	uint32_t m_pmatch = 0;
	uint32_t m_other = 0;
};

class chk_compare_helper
{
public:
	static uint32_t count_expr_checks(gen_event_filter_expression* e);
	static uint32_t get_chk_field_importance(sinsp_filter_check* c);
	static uint32_t get_chk_fields_cnt(sinsp_filter_check* c);
	static uint32_t get_chk_fields_size(sinsp_filter_check* c);
};

class SINSP_PUBLIC sinsp_filter_optimizer
{
public:
	void add_filter(sinsp_filter_optimizer_entry* filter);
	void optimize();
	void dedup();

	void normalize_expr(gen_event_filter_expression* e);
	string expr_to_string(gen_event_filter_expression* e);

	vector<sinsp_filter_optimizer_entry> m_filters;

private:
	uint32_t compare_check(sinsp_filter_check* chk1, sinsp_filter_check* chk2);
	boolop get_check_boolop(gen_event_filter_expression* e, uint32_t pos);
	bool compare_boolop(boolop op1, boolop op2);
	uint32_t compare_expr(gen_event_filter_expression* e1, gen_event_filter_expression* e2, uint32_t depth);
	void add_dupplicate(uint32_t res, gen_event_filter_expression* e1, gen_event_filter_expression* e2);
	bool already_compared(gen_event_filter_expression* e1, gen_event_filter_expression* e2);
	void find_duplicates(gen_event_filter_expression* e1, gen_event_filter_expression* e2, int depth);

	void normalize();

	void collapse_matches_check(sinsp_filter_check* chk);
	void collapse_matches_expr(gen_event_filter_expression* e);
	void optimization_collapse_matches();

	bool can_move_check_into_in(sinsp_filter_check* fc);
	void get_in_able_fields(gen_event_filter_expression* e, OUT map<string, uint32_t>* in_able_fields);
	void merge_into_in_expr(gen_event_filter_expression* e);
	void optimization_merge_into_in();

	bool is_expr_disabled(gen_event_filter_expression* e);
	bool is_expr_always_false(gen_event_filter_expression* e);
	void optimization_remove_disabled();
	void optimization_remove_always_false();

	void sort_expr_checks_by_weight(gen_event_filter_expression* e);
	void optimization_sort_checks_by_weight();

	// The following are for debug purposes
	string check_to_string(sinsp_filter_check* chk);
	string child_to_string(gen_event_filter_check* child, bool is_expression);
	void print_filters();
	void print_expr(gen_event_filter_expression* e1);

	map<pair<gen_event_filter_expression*, gen_event_filter_expression*>, uint32_t> m_compared_checks;
	map<pair<gen_event_filter_expression*, gen_event_filter_expression*>, uint32_t> m_dups;
	//map<string, vector<uint8_t*>> m_collapsed_fields;
	map<string, field_ops> m_collapsed_fields;
	match_stats m_match_stats;
	uint32_t m_ndups = 0;
	uint32_t m_n_printed_expr;
	bool is_flattened = false;
};
