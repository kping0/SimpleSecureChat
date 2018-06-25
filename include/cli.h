
/*
 *  <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
 *  Copyright (C) 2017-2018 The SimpleSecureChat Authors. <kping0> 
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SSC_CLI_MENU_HEADER
#define SSC_CLI_MENU_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ncurses.h>
#include <form.h>
#include <panel.h>
#include <sqlite3.h>
#include <openssl/bio.h>
#include "settings.h"
#include "serialization.h"
#include "sscdbfunc.h"
#include "msgfunc.h"

typedef struct _win_border_struct {
	chtype ls,rs,ts,bs,tl,tr,bl,br;
}WIN_BORDER;

typedef struct _list_page_struct {
	int currently_selected;
	int elements;
	byte* screen_content[100];
}WPAGE;

typedef struct _WIN_struct{
	byte* name;
	int startx,starty;
	int height,width;
	WIN_BORDER border;
	WPAGE* current_page;
	WPAGE* pages[1000];
	int page_index;
	int page_count;
}WIN;

/*
 * simple structure to contain the most used variables
 */
typedef struct _SSCGlobalVars{ 
	sqlite3* db;
	BIO* conn;
	EVP_PKEY* privkey;
	WIN* current;
	WIN* previous;
	WIN* contacts;
	WIN* received;
	WIN* sent;
}SSCGV;

void ssc_cli_init(void);

void ssc_cli_end(void);

WIN* ssc_cli_cust_newwin(int height, int width, int starty, int startx);

void ssc_cli_cust_updwin(WIN* p_win,bool flag);

void ssc_cli_add_page(WIN* p_win);

void ssc_cli_window_reload(WIN* p_win);

void ssc_cli_switch_current(WIN* p_win);

void ssc_cli_msg_page_sync(SSCGV* gv);

void ssc_cli_next_page(SSCGV* gv);

void ssc_cli_prev_page(SSCGV* gv);

void ssc_cli_last_page(SSCGV* gv);

void ssc_cli_add_item(WIN* p_win,byte* block);

void ssc_cli_window_upd_highlight(SSCGV* gv);

byte* ssc_cli_get_current(SSCGV* gv);

int ssc_cli_cursor_move(SSCGV* gv,int c_y,int c_x);

int ssc_cli_msg_cursor_move(SSCGV* gv,int c_y,int c_x);

byte* _getstr(void);

void ssc_cli_add_message(WIN* window4msg,WIN* window4space,byte* message);

void ssc_cli_cmd_parser(SSCGV* gv,byte* userinput);

void ssc_cli_msg_clear(SSCGV* gv);

byte* ssc_cli_currently_selected(WIN* p_win);

void ssc_cli_reload_contacts(SSCGV* gv);

void ssc_cli_msg_upd(SSCGV* gv,byte* username);
	

#endif /* SSC_CLI_MENU_HEADER */
