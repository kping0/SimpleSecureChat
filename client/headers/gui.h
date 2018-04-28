
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

#ifndef SSCGUIHEADER  
#define SSCGUIHEADER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "sscssl.h" //needed for struct ssl_str
#include <sqlite3.h>
#include "settings.h"
#include "serialization.h"
#include "sscdbfunc.h"
#include "msgfunc.h"
#include <assert.h>

struct sscs_backend_variables{ //structure mainly for gui use so it can be passed to gtk+ functions that can only be passed a gpointer
	struct ssl_str* connection_variables; //connection variables to server
	EVP_PKEY* pubkey; //User public Key
	EVP_PKEY* privkey; //User private key
	sqlite3* db; //Database handle
}; 
typedef struct sscs_backend_variables sscbackend;

struct sscswidgets_gui{
	sscbackend* backend_vars; //pointer to variables used by internal functions	
	GtkWidget *contactslist; //handle to contactslist
	GtkWidget *messagelist;	//Handle to messagelist (all send messages to partner)
	GtkWidget *recvlist; //Handle to recvlist(all received messages from partner)
	GtkWidget *window; //Handle to Window
	GtkLabel *chatpartnerlabel; //label that changes when you switch chat partner
	char** current_username; //Username of chat partner (not the local user)
};
typedef struct sscswidgets_gui sscvars_gui;

struct sscsbutton_gui{
	struct sscswidgets_gui* widgets;
	char* item;
};

void init_gui(struct sscswidgets_gui* data);

void clear_messages_gui(struct sscswidgets_gui* data);

void clear_recvlist_gui(struct sscswidgets_gui* data);

void append_list_string_gui(GtkWidget* list,char* item); //add label to widget list

void change_current_user_gui(GtkWidget* widget,gpointer data); 

void add_contact_gui(GtkWidget* contactslist,struct sscswidgets_gui* widgets,char* contactname);

void send_message_entry_gui(GtkEntry* entry,gpointer data);

void add_user_entry_gui(GtkEntry* entry,gpointer data);

void addnewuser_gui(struct sscswidgets_gui* widgets_gui,char* username);

void getmessages_gui(GtkWidget* notused,gpointer data);

#endif /* SSCGUIHEADER */
#ifndef SSCGUIHEADER  
#define SSCGUIHEADER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "sscssl.h" //needed for struct ssl_str
#include <sqlite3.h>
#include "settings.h"
#include "serialization.h"
#include "sscdbfunc.h"
#include "msgfunc.h"
#include <assert.h>

struct sscs_backend_variables{ //structure mainly for gui use so it can be passed to gtk+ functions that can only be passed a gpointer
	struct ssl_str* connection_variables; //connection variables to server
	EVP_PKEY* pubkey; //User public Key
	EVP_PKEY* privkey; //User private key
	sqlite3* db; //Database handle
}; 
typedef struct sscs_backend_variables sscbackend;

struct sscswidgets_gui{
	sscbackend* backend_vars; //pointer to variables used by internal functions	
	GtkWidget *contactslist; //handle to contactslist
	GtkWidget *messagelist;	//Handle to messagelist (all send messages to partner)
	GtkWidget *recvlist; //Handle to recvlist(all received messages from partner)
	GtkWidget *window; //Handle to Window
	GtkLabel *chatpartnerlabel; //label that changes when you switch chat partner
	char** current_username; //Username of chat partner (not the local user)
};
typedef struct sscswidgets_gui sscvars_gui;

struct sscsbutton_gui{
	struct sscswidgets_gui* widgets;
	char* item;
};

void init_gui(struct sscswidgets_gui* data);

void clear_messages_gui(struct sscswidgets_gui* data);

void clear_recvlist_gui(struct sscswidgets_gui* data);

void append_list_string_gui(GtkWidget* list,char* item); //add label to widget list

void change_current_user_gui(GtkWidget* widget,gpointer data); 

void add_contact_gui(GtkWidget* contactslist,struct sscswidgets_gui* widgets,char* contactname);

void send_message_entry_gui(GtkEntry* entry,gpointer data);

void add_user_entry_gui(GtkEntry* entry,gpointer data);

void addnewuser_gui(struct sscswidgets_gui* widgets_gui,char* username);

void getmessages_gui(GtkWidget* notused,gpointer data);

#endif /* SSCGUIHEADER */
