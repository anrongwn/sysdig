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

//
// Why isn't this parser written using antlr or some other parser generator?
// Essentially, after dealing with that stuff multiple times in the past, and fighting for a day
// to configure everything with crappy documentation and code that doesn't compile,
// I decided that I agree with this http://mortoray.com/2012/07/20/why-i-dont-use-a-parser-generator/
// and that I'm going with a manually written parser. The grammar is simple enough that it's not
// going to take more time. On the other hand I will avoid a crappy dependency that breaks my
// code at every new release, and I will have a cleaner and easier to understand code base.
//

#include <regex>
#include <algorithm>

#include "sinsp.h"
#include "sinsp_int.h"
#include "utils.h"

#include "filter.h"
#include "filter_optimizer.h"
#include "filterchecks.h"
#include "value_parser.h"

char* cmpop_to_string(cmpop op)
{
	switch(op)
	{
	case CO_NONE:
		return "none";
	case CO_EQ:
		return "=";
	case CO_NE:
		return "!=";
	case CO_LT:
		return "<";
	case CO_LE:
		return "<=";
	case CO_GT:
		return ">";
	case CO_GE:
		return ">=";
	case CO_CONTAINS:
		return "contains";
	case CO_IN:
		return "in";
	case CO_EXISTS:
		return "exists";
	case CO_ICONTAINS:
		return "icontains";
	case CO_STARTSWITH:
		return "startswith";
	case CO_GLOB:
		return "glob";
	case CO_PMATCH:
		return "pmatch";
	case CO_ENDSWITH:
		return "endswith";
	case CO_INTERSECTS:
		return "intersects";
	default:
		return "<NA>";
	}
}

void sinsp_filter_optimizer::add_filter(sinsp_filter_optimizer_entry* filter)
{
	m_filters.push_back(*filter);

	gen_event_filter_expression c;
	sinsp_filter_check* pos = dynamic_cast<sinsp_filter_check*>(&c);
}

boolop sinsp_filter_optimizer::get_check_boolop(gen_event_filter_expression* e, uint32_t pos)
{
	boolop res;

	gen_event_filter_check* chk = e->m_checks[pos];
	uint32_t tot_checks = (uint32_t)e->m_checks.size();

	if(pos == 0)
	{
		//
		// The first check borrows the boolop from the follower (if it has one)
		//
		if(chk->m_boolop == BO_NONE)
		{
			if(tot_checks > 1)
			{
				res = e->m_checks[1]->m_boolop;
				// Clear the last bit of the boolop to make sure it's positive
				res = (boolop)(((uint32_t)res) & ~1);
			}
			else
			{
				res = BO_NONE;
			}
		}
		else if(chk->m_boolop == BO_NOT)
		{
			if(tot_checks > 1)
			{
				res = e->m_checks[1]->m_boolop;
				// Set the last bit of the boolop to make sure it's negative
				res = (boolop)(((uint32_t)res) | 1);
			}
			else
			{
				res = BO_NOT;
			}
		}
		else
		{
			throw sinsp_exception("optimizer error: first epression child has unknown boolop " + to_string(chk->m_boolop));
		}
	}
	else
	{
		res = chk->m_boolop;
	}

	return res;
}

bool sinsp_filter_optimizer::compare_boolop(boolop op1, boolop op2)
{
	if(op1 == BO_NONE && ((op2 & BO_NOT) == 0))
	{
		return true;
	}

	if(op2 == BO_NONE && ((op1 & BO_NOT) == 0))
	{
		return true;
	}

	return op1 == op2;
}

//
// Returns 1 if the checks are the same, 0 otherwise.
//
uint32_t sinsp_filter_optimizer::compare_check(sinsp_filter_check* chk1, sinsp_filter_check* chk2)
{
	string name1 = chk1->m_field->m_name;
	string name2 = chk2->m_field->m_name;
//	uint32_t id = chk->m_field_id;
//	string ename = chk->m_info.m_name;
////	uint64_t val = *(uint64_t*)&(m_val_storages[0][0]);
////bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len)
//	//m_val_storage_len
//
//	string vs;
//	for(auto it : chk->m_val_storages_members)
//	{
//		vs += (to_string(it.second) + ":");
//	}
//	vs = vs.substr(0, vs.length() - 1);
//
//	printf("%s %s %s", ts.c_str(), cmpop_to_string(chk->m_cmpop), vs.c_str());

	if(name1 == name2)
	{
		if(chk1->m_val_storages_members.size() == chk2->m_val_storages_members.size())
		{
			vector<filter_value_t> vsv1;
			for(auto it : chk1->m_val_storages_members)
			{
				vsv1.push_back(it);
			}

			vector<filter_value_t> vsv2;
			for(auto it : chk2->m_val_storages_members)
			{
				vsv2.push_back(it);
			}

			uint32_t ecnt = 0;

			for(uint32_t j = 0; j < vsv1.size(); j++)
			{
				for(uint32_t k = 0; k < vsv2.size(); k++)
				{
					if(vsv1[j].second == vsv2[k].second)
					{
						if(memcmp(vsv1[j].first, vsv2[k].first, vsv1[j].second) == 0)
						{
							ecnt++;
						}
					}
				}
			}

					
			if(ecnt == vsv1.size())
			{
				return true;
			}
			else if(ecnt > vsv1.size())
			{
				ASSERT(false);
				return true;
			}
		}
	}

	return 0;
}

uint32_t sinsp_filter_optimizer::compare_expr(gen_event_filter_expression* e1, gen_event_filter_expression* e2, uint32_t depth)
{
	uint32_t res = 0;
	uint32_t size1 = (uint32_t)e1->m_checks.size();
	uint32_t size2 = (uint32_t)e2->m_checks.size();

	for(uint32_t j = 0; j < size1; j++)
	{
printf("%u A %u\n", depth,j);
		gen_event_filter_check* chk1 = e1->m_checks[j];
		ASSERT(chk1 != NULL);
		gen_event_filter_expression* fe1 = dynamic_cast<gen_event_filter_expression*>(chk1);
		bool is_chk1_expression = (fe1 != NULL);
		cmpop chk1_cmpop = (is_chk1_expression && fe1->m_checks.size() > 1)? chk1->m_cmpop: CO_NONE;
		boolop chk1_boolop = get_check_boolop(e1, j);

		for(uint32_t k = 0; k < size2; k++)
		{
printf("%u B %u\n", depth,k);
			gen_event_filter_check* chk2 = e2->m_checks[k];
			ASSERT(chk2 != NULL);
			gen_event_filter_expression* fe2 = dynamic_cast<gen_event_filter_expression*>(chk2);
			bool is_chk2_expression = (fe2 != NULL);
			cmpop chk2_cmpop = (is_chk2_expression && fe2->m_checks.size() > 1)? chk2->m_cmpop: CO_NONE;
			boolop chk2_boolop = get_check_boolop(e2, k);

printf("%u Z %d %d\n", depth, (int)chk1_cmpop, (int)chk2_cmpop);
if((uint32_t)chk1_cmpop > 15 || (uint32_t)chk1_cmpop > 15)
{
	int a = 0;
}
			if(is_chk1_expression == is_chk2_expression &&
				chk1_cmpop == chk2_cmpop &&
				compare_boolop(chk1_boolop, chk2_boolop))
			{
printf("%u C\n", depth);
				if(is_chk1_expression)
				{
printf("%u D\n", depth);
					gen_event_filter_expression* ce1 = (gen_event_filter_expression*)chk1;
					gen_event_filter_expression* ce2 = (gen_event_filter_expression*)chk2;
					if(ce1->m_checks.size() == ce2->m_checks.size())
					{
printf("%u E\n", depth);
						uint32_t cres = compare_expr(ce1, ce2, depth + 1);
						if(cres == ce1->m_checks.size())
						{
							res++;
							break;
						}
					}
				}
				else
				{
					uint32_t cres = compare_check((sinsp_filter_check*)chk1, (sinsp_filter_check*)chk2);
					if(cres != 0)
					{
						res += cres;
						break;
					}
				}
			}
		}
	}

	return res;
}

void sinsp_filter_optimizer::add_dupplicate(uint32_t res, gen_event_filter_expression* e1, gen_event_filter_expression* e2)
{
	if(res > 0)
	{
		pair<gen_event_filter_expression*, gen_event_filter_expression*> mi(min(e1, e2), max(e1, e2));
		//if(m_dups.find(mi) != m_dups.end())
		//{
		//	//
		//	// We already found this match
		//	// XXX we should update this if the new res is longer
		//	//
		//	ASSERT(m_dups[mi] == res);
		//	return;
		//}

printf("\n\n %p %p-----------------------------------------------IIIIIIIIIII\n", e1, e2);
print_expr(e1);
printf("\n\n");
print_expr(e2);
printf("\n\n %p %p----------------------------------------------------------\n", e1, e2);

		m_dups[mi] = res;
		m_ndups++;

		//printf("SRC RULE: %s", m_filters[j].m_rule.c_str());
		//printf("DST RULE: %s\n", m_filters[k].m_rule.c_str());
		//printf("MATCHES: %u / %u\n", res, (uint32_t)fe1->m_checks.size());
		//print_expr(fe1);
		//printf("\n\n");
		//print_expr(fe2);
		//printf("\n\n");
	}
}

void sinsp_filter_optimizer::pei(gen_event_filter_expression* e1, gen_event_filter_expression* e2, int depth)
{
	bool is_chk1_expression = (dynamic_cast<gen_event_filter_expression*>(e1) != NULL);
	bool is_chk2_expression = (dynamic_cast<gen_event_filter_expression*>(e2) != NULL);

	printf("--------------------------------------------------\n");
	printf("%d ", depth);
	if(is_chk1_expression)
	{
		print_expr(e1);
	}
	else
	{
		printf("NE");
	}
	printf("\n");
	printf("-------\n");
	printf("%d ", depth);
	if(is_chk2_expression)
	{
		print_expr(e2);
	}
	else
	{
		printf("NE");
	}
	printf("\n");
}

bool sinsp_filter_optimizer::already_compared(gen_event_filter_expression* e1, gen_event_filter_expression* e2)
{
		pair<gen_event_filter_expression*, gen_event_filter_expression*> mi(min(e1, e2), max(e1, e2));
		if(m_compared_checks.find(mi) == m_compared_checks.end())
		{
			m_compared_checks[mi] = 1;
			return false;
		}
		else
		{
			return true;
		}
}

void sinsp_filter_optimizer::find_duplicates(gen_event_filter_expression* e1, gen_event_filter_expression* e2, int depth)
{
	if(already_compared(e1, e2))
	{
		return;
	}

	uint32_t res = compare_expr(e1, e2, 0);
printf("*%d\n", res);
	add_dupplicate(res, e1, e2);
return;
	uint32_t size1 = (uint32_t)e1->m_checks.size();
	uint32_t size2 = (uint32_t)e2->m_checks.size();

	for(uint32_t j = 0; j < size1; j++)
	{
		gen_event_filter_check* cchk1 = e1->m_checks[j];
		ASSERT(cchk1 != NULL);
		gen_event_filter_expression* cfe1 = dynamic_cast<gen_event_filter_expression*>(cchk1);
		bool is_chk1_expression = (cfe1 != NULL);

		if(is_chk1_expression)
		{
			find_duplicates(cfe1, e2, depth+1);
		}
	}

	for(uint32_t k = 0; k < size2; k++)
	{
		gen_event_filter_check* cchk2 = e2->m_checks[k];
		ASSERT(cchk2 != NULL);
		gen_event_filter_expression* cfe2 = dynamic_cast<gen_event_filter_expression*>(cchk2);
		bool is_chk2_expression = (cfe2 != NULL);

		if(is_chk2_expression)
		{
			find_duplicates(e1, cfe2, depth+1);
		}
	}

	for(uint32_t j = 0; j < size1; j++)
	{
		gen_event_filter_check* cchk1 = e1->m_checks[j];
		ASSERT(cchk1 != NULL);
		gen_event_filter_expression* cfe1 = dynamic_cast<gen_event_filter_expression*>(cchk1);
		bool is_chk1_expression = (cfe1 != NULL);

		for(uint32_t k = 0; k < size2; k++)
		{
			gen_event_filter_check* cchk2 = e2->m_checks[k];
			ASSERT(cchk2 != NULL);
			gen_event_filter_expression* cfe2 = dynamic_cast<gen_event_filter_expression*>(cchk2);
			bool is_chk2_expression = (cfe2 != NULL);

			if(is_chk1_expression && is_chk2_expression)
			{
				find_duplicates(cfe1, cfe2, depth+1);
			}
		}
	}
}

inline bool op_is_not(boolop op)
{
	return ((op & BO_NOT) == BO_NOT);
}

inline boolop op_set_not(boolop op)
{
	return (boolop)(op | BO_NOT);
}

inline boolop op_clear_not(boolop op)
{
	return (boolop)(op & (uint32_t)~BO_NOT);
}

inline boolop op_flip_not(boolop op)
{
	return (boolop)(op ^ 1);
}

void sinsp_filter_optimizer::flatten_expr(gen_event_filter_expression* e)
{
	uint32_t size = (uint32_t)e->m_checks.size();
	int32_t gpbo = e->get_expr_boolop();
	boolop gprbo = e->m_boolop;
	ASSERT(gpbo != -1);

	for(uint32_t j = 0; j < size; j++)
	{
		gen_event_filter_check* chk = e->m_checks[j];
		ASSERT(chk != NULL);
		gen_event_filter_expression* ce = dynamic_cast<gen_event_filter_expression*>(chk);
		bool is_chk1_expression = (ce != NULL);

		//
		// We only flatten expressions
		//
		if(is_chk1_expression)
		{
			//
			// Flatten the child first
			//
			flatten_expr(ce);

			int32_t pbo = ce->get_expr_boolop();
			ASSERT(pbo != -1);
			boolop prbo = ce->m_boolop;
			bool moveup = false;

			if(ce->m_checks.size() == 1)
			{
				if(op_is_not(ce->m_checks[0]->m_boolop))
				{
					prbo = op_flip_not(prbo);
				}

				moveup = true;
			}
			else
			{
				//
				// Cannot move checks up when parent is a not
				//
				if(!op_is_not(ce->m_boolop))
				{
					if((size == 1 && ce->m_boolop == BO_NONE) || // parent is alone and has no bool op. This means it's a single check with 1 child.
						(size > 1 && pbo == gpbo) || // parent is not alone but the boolop of its group matches the one of the child
						pbo == (ce->m_boolop & (uint32_t)~1)) // parent has same boolop as childs, modulo a not
					{
						if(op_is_not(ce->m_checks[0]->m_boolop))
						{
							prbo = op_set_not(prbo);
						}

						moveup = true;
					}
				}
				else if(op_is_not(ce->m_boolop) && op_is_not(e->m_boolop)) // both parent and grandparent are a a not, canceling each other
				{
					if(size == 1)
					{
						moveup = true;
						e->m_boolop = (boolop)(gprbo & (uint32_t)~1);
						if(op_is_not(ce->m_checks[0]->m_boolop))
						{
							prbo = op_set_not(prbo);
						}
						else
						{
							prbo = op_clear_not(prbo);
						}
					}
				}
			}

			if(moveup)
			{
				e->m_checks.erase(e->m_checks.begin() + j);
				e->m_checks.insert(e->m_checks.begin() + j, ce->m_checks.begin(), ce->m_checks.end());
				e->m_checks[j]->m_boolop = (boolop)prbo;

				//
				// We changed the input expression. Re-run the flattening from the beginning and then
				// exit right away to avoid processing modified childs.
				//
				flatten_expr(e);
				break;
			}
		}
	}
}

void sinsp_filter_optimizer::flatten()
{
	for(uint32_t j = 0; j < m_filters.size(); j++)
	{
		gen_event_filter_expression* fe = (gen_event_filter_expression*)m_filters[j].m_filter->m_filter;

		// top tier checks come with boolop not set.
		// Set it to NONE.
		fe->m_boolop = BO_NONE;
//print_expr(fe);
//printf("\n");
//printf("----\n");
		flatten_expr((gen_event_filter_expression*)fe);
//print_expr(fe);
//printf("\n");
//printf("-----------------------------------------------------------------\n");
	}

	int a = 0;
}

void sinsp_filter_optimizer::dedup()
{
//	flatten();

	for(uint32_t j = 0; j < m_filters.size(); j++)
	{
		for(uint32_t k = 0; k < m_filters.size() - 1; k++)
		{
if(j<2 || j>2)
{
	continue;
}
if(k != 1)
{
	continue;
}
			gen_event_filter_expression* fe1 = m_filters[j].m_filter->m_filter;
			gen_event_filter_expression* fe2 = m_filters[k].m_filter->m_filter;
//print_expr(fe1);
//printf("\n\n");
//print_expr(fe2);
			if(j > k)
			{
				find_duplicates(fe1, fe2, 0);
			}
		}
	}

	fprintf(stderr, "TOT MATCHES: %u %u\n", m_ndups, (uint32_t)m_dups.size());
	int a = 0;
exit(0);
}

string sinsp_filter_optimizer::check_to_string(sinsp_filter_check* chk)
{
	string ts = chk->m_field->m_name;
	uint32_t id = chk->m_field_id;
	string ename = chk->m_info.m_name;
//	uint64_t val = *(uint64_t*)&(m_val_storages[0][0]);
//bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len)
	//m_val_storage_len

	string vs;
	for(auto it : chk->m_val_storages_members)
	{
		vs += chk->rawval_to_string(it.first, chk->m_field->m_type, chk->m_field->m_print_format, it.second);
		vs += ",";
		// vs += (to_string(it.second) + ":");
	}
	vs = vs.substr(0, vs.length() - 1);

	return ts + " " + cmpop_to_string(chk->m_cmpop) + " " + vs;
}

string sinsp_filter_optimizer::child_to_string(gen_event_filter_check* child, bool is_expression)
{
	if(is_expression)
	{
		return expr_to_string((gen_event_filter_expression*)child);
	}
	else
	{
		return check_to_string((sinsp_filter_check*)child);
	}
}

string sinsp_filter_optimizer::expr_to_string(gen_event_filter_expression* e1)
{
	uint32_t j;
	uint32_t size = (uint32_t)e1->m_checks.size();
	gen_event_filter_check* chk = NULL;
	m_n_printed_expr++;
	string res;

	res = "(";
	for(j = 0; j < size; j++)
	{
		chk = e1->m_checks[j];
		gen_event_filter_expression* fe = dynamic_cast<gen_event_filter_expression*>(chk);
		bool is_expression = (fe != NULL);

		ASSERT(chk != NULL);

		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res += child_to_string(chk, is_expression);
				break;
			case BO_NOT:
				res += "not ";
				res += child_to_string(chk, is_expression);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				res += " or ";
				res += child_to_string(chk, is_expression);
				break;
			case BO_AND:
				res += " and ";
				res += child_to_string(chk, is_expression);
				break;
			case BO_ORNOT:
				res += " or not";
				res += child_to_string(chk, is_expression);
				break;
			case BO_ANDNOT:
				res += " and not ";
				res += child_to_string(chk, is_expression);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}

	res += ")";

	return res;
}

void sinsp_filter_optimizer::print_expr(gen_event_filter_expression* e1)
{
	string es = expr_to_string(e1);
	printf("%s", es.c_str());
}
