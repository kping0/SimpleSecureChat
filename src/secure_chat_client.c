
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h> 
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include <openssl/rand.h> 
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <sqlite3.h> 

/* Custom Header */
#include "sscssl.h" //Connection functions
#include "sscasymmetric.h" //keypair functions
#include "sscdbfunc.h" //DB manipulation functions 
#include "base64.h" //Base64 Functions
#include "serialization.h" //SimpleSecureSerialization library (to replace binn)
#include "msgfunc.h" //encrypt-decrypt-verify-sign functions
#include "settings.h" //Modify to change configuration of SSC
#include "cli.h" //cli functions
#include "thread_locking.h" //thread locking code
#include "simpleconfig.h" //config support
#include "loadconfig_client.h" //function to load config

#ifdef SSC_GUI
#include <gtk/gtk.h>
#include "gui.h"

gboolean timedupdate_gui(void* data){
	clear_messages_gui(data);	
	getmessages_gui(data);
//	internal_scroll_window_msg_bottom_gui(data);
	return 1;
}

#endif /* SSC_GUI */

int pexit(byte* error){
	cerror("Exiting: %s",error);
	exit(EXIT_FAILURE);
}

/* Start of application */
int main(void){
	fprintf(stdout,"Welcome to %s. Report bugs to %s.\n",PACKAGE_STRING,PACKAGE_BUGREPORT);

	SCONFIG* config = loadconfig_client(); /* get config info */
	if(!config)cexit("Could not retrieve configuration");

/*  Init OpenSSL Library */
	(void)SSL_library_init(); 
	SSL_load_error_strings(); 
	init_locks(); /* enable OpenSSL thread-safety (via pthread_mutexes) */

	/* Connect to server */
	char* hostcert = sconfig_get_str(config,"HOST_CERT");
	char* hostname = sconfig_get_str(config,"HOST_NAME");
	char* hostport = sconfig_get_str(config,"HOST_PORT"); /* later turned into int */
	cdebug("Trying to connect to %s:%s",hostname,hostport);
	struct ssl_str *tls_vars = malloc(sizeof(struct ssl_str));
	if(tls_conn(tls_vars,hostcert,hostname,hostport)){ /*function that creates a TLS connection & alters the struct(ssl_str)ssl_o*/
		cdebug("Successfully connected to %s:%s (server) ",hostname,hostport);
		free(hostcert);
		free(hostname);
		free(hostport);
	}
	else{
		cerror("Failed to connect to server");
		free(tls_vars);
		free(hostcert);
		free(hostname);
		free(hostport);
		exit(1);
	}
	/*
	 * Load Public & Private Keys
	 */
	EVP_PKEY* pubk_evp = EVP_PKEY_new(); 
	EVP_PKEY* priv_evp = EVP_PKEY_new();
	char* pub_key_path = sconfig_get_str(config,"PUB_KEY");
	char* priv_key_path = sconfig_get_str(config,"PRIV_KEY");
	cdebug("key paths %s -- %s",pub_key_path,priv_key_path);
	int keysize_rsa = sconfig_get_int(config,"KEYSIZE");
	if(!load_keypair(pubk_evp,priv_evp,pub_key_path,priv_key_path)){
		cerror("Could not load keypair, generating new one -- this can take a while...");
		EVP_PKEY_free(pubk_evp);
		EVP_PKEY_free(priv_evp);
		create_keypair(pub_key_path,priv_key_path,keysize_rsa);
		cinfo("Generated keypair, please restart SimpleSecureChat to load it");
		return 0;
	}
	else {
		cdebug("Successfully loaded keypair from disk");
		assert(test_keypair(pubk_evp,priv_evp) == 1);
	}
//Load SQLITE Database
	char* db_path = sconfig_get_str(config,"DB_FNAME");
	sqlite3 *db = init_db(db_path);
	if(db != NULL){
		cdebug("Successfully loaded DB");
	}
	else{
		cerror("Could not load Database");
		goto CLEANUP;	
	}
	if(db_user_init(db,pub_key_path) != 1){
		cerror("Failed to init userinfo in database");
		goto CLEANUP;
	}
	free(priv_key_path);
	free(pub_key_path);
#ifdef DEBUG
	cinfo("Starting Debug Sign/Verify test");
	const byte msg[] = "This is a secret message";
	byte *sig = NULL;
	size_t slen = 0;
	int rc = sign_msg(msg,sizeof(msg),&sig,&slen,priv_evp);
	if(rc == 0) {
		 cinfo("Successfully created signature");
    	} else {
		 cerror("Failed to create signature, return  code %d",rc);
   	}
	rc = verify_msg(msg,sizeof(msg),sig,slen,pubk_evp);
	if(rc == 0){
		cinfo("Successfully verified signature");
	}	
	else{
		cerror("Failed to verify signature");
	}

	//register your user
	char* your_username_for_debug = get_muser(db); /* terrible variable name :) */
	cinfo("Your username is %s, syncing it with the server",your_username_for_debug);
	free(your_username_for_debug);
#endif /* DEBUG*/
	byte* regubuf = (byte*)register_user_str(db);
	assert(regubuf != NULL && strlen((const char*)regubuf) > 0);
	BIO_write(tls_vars->bio_obj,regubuf,strlen((const char*)regubuf)); 
	byte rsp[3];
	memset(rsp,0,3);			
	BIO_read(tls_vars->bio_obj,rsp,3);
	if(strncmp((const char*)rsp,"ERR",3) == 0){
		cdebug("Failed to register user (maybe user exists on server?) ");
	}
	free(regubuf);

//Authenticate USER
	byte* authmsg = auth_usr(db);
	cdebug("Authenticating your user...");
	assert(authmsg != NULL && strlen((const char*)authmsg) > 0);
	BIO_write(tls_vars->bio_obj,authmsg,strlen((const char*)authmsg));
	free(authmsg);

/*
 * If SSC is compiled with SSC_GUI the user has a choice between CLI and GUI, otherwise the below is never called
 */
#ifdef SSC_GUI
	fprintf(stdout,"[SELECT] Do you want to use the GUI (y/Y | n/N) : ");
	unsigned int gui_or_cli_selection = fgetc(stdin);
	while(fgetc(stdin) != '\n'){} //Clear STDIN
	if(gui_or_cli_selection == 'y' || gui_or_cli_selection == 'Y'){

	/*
	* Setting up gui variables
	*/
		cdebug("Starting Gui...");
		struct sscs_backend_variables* backend_vars = malloc(sizeof(struct sscs_backend_variables));
		backend_vars->pubkey = pubk_evp;
		backend_vars->privkey = priv_evp;
		backend_vars->db = db;
		backend_vars->connection_variables = tls_vars;
		gtk_init(NULL,NULL); /* init gtk */

		/* load css stylesheets */
		GtkCssProvider* css_provider = gtk_css_provider_new();
		if(!gtk_css_provider_load_from_path(css_provider,"gui_deps/usrcustom.cssfile",NULL)){
			g_object_unref(css_provider);
			cexit("Could not load css stylesheet");
		}
		GdkScreen* screen = gdk_display_get_default_screen(gdk_display_get_default());
		gtk_style_context_add_provider_for_screen(screen,GTK_STYLE_PROVIDER(css_provider),GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	
	
		GtkBuilder* gtkBuilder = gtk_builder_new();		
		gtkBuilder = gtk_builder_new();
		gtk_builder_add_from_file(gtkBuilder,"gui_deps/dynamic.glade",NULL);
		GtkWidget *window = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"mainwindow"));
		GtkWidget *contactslist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"contactslist"));
		GtkWidget *messagelist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"messageslist"));
		GtkWidget *sendmessagetext = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"sendmessagetext"));
		GtkWidget *addusertext = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"addusertext"));
		GtkWidget *chatpartnerlabel = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"currentchatpartner"));
		GtkWidget *recvlist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"recvlist"));
		
		GtkWidget *messagescrollwindow = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"messages_scrolled_window"));

		struct sscswidgets_gui* widgetsobj = malloc(sizeof(struct sscswidgets_gui));
		widgetsobj->window = window;
		widgetsobj->contactslist = contactslist;
		widgetsobj->messagelist = messagelist;
		widgetsobj->chatpartnerlabel = (GtkLabel*)chatpartnerlabel;
		widgetsobj->recvlist = recvlist;
		widgetsobj->messagescrollwindow = messagescrollwindow;
		widgetsobj->backend_vars = backend_vars;
		byte* username = NULL;
		widgetsobj->current_username = &username;

		/* Connect signals to the handlers for sending messages & adding users */
		g_signal_connect(G_OBJECT(window),"destroy",G_CALLBACK(gtk_main_quit),NULL);
		g_signal_connect(G_OBJECT(sendmessagetext),"activate",G_CALLBACK(send_message_entry_gui),widgetsobj);
		g_signal_connect(G_OBJECT(addusertext),"activate",G_CALLBACK(add_user_entry_gui),widgetsobj);
/* TESTING */
		GtkWidget* test_func = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"test_func"));
		g_signal_connect(G_OBJECT(test_func),"clicked",G_CALLBACK(internal_scroll_window_msg_bottom_gui_2),widgetsobj);
/* TESTING */
		g_object_unref(G_OBJECT(gtkBuilder));
		init_gui(widgetsobj); /* do ssc neccessary (such as adding the contacts on the sidebar) */
		gtk_widget_show_all(window);

		g_timeout_add(1000,&timedupdate_gui,widgetsobj); //this updates the gui and retrieves messages from the server every 1000ms
		/* Start Main Loop */

		gtk_main();
		goto CLEANUP;
	}
#endif /* SSC_GUI */

	/*
	 * NCurses CLI Interface 
	 */
	ssc_cli_init(); //Start interface
	init_pair(1,COLOR_CYAN,COLOR_BLACK);
	init_pair(2,COLOR_GREEN,COLOR_BLACK);
	int row,col;
	getmaxyx(stdscr,row,col);
	/*
	 * Create Help Window at the start of the application
	 */
	attron(COLOR_PAIR(1));
	WIN* help_window = ssc_cli_cust_newwin(row * 0.85,col * 0.7, 5, 10);
	ssc_cli_cust_updwin(help_window,TRUE);
	attroff(COLOR_PAIR(1));
	attron(A_BOLD);
	attron(COLOR_PAIR(2));
	ssc_cli_add_item(help_window,(byte*)"--- SIMPLESECURECHAT HELP ---");
	attroff(A_BOLD);
	ssc_cli_add_item(help_window,(byte*)"This UI has vim style controls. ");
	ssc_cli_add_item(help_window,(byte*)"To switch between columns, use 'h' , 'l' , [TAB] or R/L arrow");
	ssc_cli_add_item(help_window,(byte*)"To go down a column, use 'j' or the down arrow.");
	ssc_cli_add_item(help_window,(byte*)"To go up a column, use 'k' or the up arrow.");
	ssc_cli_add_item(help_window,(byte*)"To quit, hit 'q'");
	attron(A_BOLD);
	ssc_cli_add_item(help_window,(byte*)" ");
	ssc_cli_add_item(help_window,(byte*)"--- COMMANDS ---");
	attroff(A_BOLD);
	ssc_cli_add_item(help_window,(byte*)"To enter a command, hit ':' .");
	ssc_cli_add_item(help_window,(byte*)"Commands can be used for many things, like: ");
	ssc_cli_add_item(help_window,(byte*)"Sending messages ':send username message'");
	ssc_cli_add_item(help_window,(byte*)"Adding friends ':add username'");
	ssc_cli_add_item(help_window,(byte*)"Switching users ':switch username'");
	ssc_cli_add_item(help_window,(byte*)"Deleting users ':delete username' ");
	ssc_cli_add_item(help_window,(byte*)" ");
	ssc_cli_add_item(help_window,(byte*)"Hit [ENTER] to begin");
	(void)getch(); //Wait for userinput
	ssc_cli_cust_updwin(help_window,FALSE); //delete the window
	attron(A_BOLD);
	mvwprintw(stdscr,row-2,1,"To exit,hit 'q'"); //add exit message to bottom of the screen
	attroff(A_BOLD);
	attron(COLOR_PAIR(2));
	/*
 	 * Create the 3 Panels(Windows) for Contacts, Received Messages & Sent Messages
	 */
	SSCGV* gv = malloc(sizeof(SSCGV)); //allocate memory for general variables structure
	/* Create Contacts Window */
	int contacts_starty = row * 0.02 + 1;
	int contacts_startx = col * 0.02  ;
	int contacts_height = row - ((row * 0.05)) - 2;
	int contacts_width = col/4 - ((col * 0.05));
	gv->contacts = ssc_cli_cust_newwin(contacts_height,contacts_width,contacts_starty,contacts_startx); 
	ssc_cli_cust_updwin(gv->contacts,TRUE);	//load the window
	
	/* Create Received Messages Window */
	int received_starty = row * 0.02 + 1;
	int received_startx = col * 0.02 + contacts_startx + contacts_width;
	int received_height = contacts_height;
	int received_width = ((col - (0.06 * col) - contacts_width )/2) ;
	gv->received = ssc_cli_cust_newwin(received_height,received_width,received_starty,received_startx); 
	ssc_cli_cust_updwin(gv->received,TRUE); //load the window

	/* Create Sent Messages Window */
	int sent_starty = row * 0.02 + 1;
	int sent_startx = received_startx + received_width;
	int sent_height = received_height;
	int sent_width = received_width; 
	gv->sent = ssc_cli_cust_newwin(sent_height,sent_width,sent_starty,sent_startx);
	ssc_cli_cust_updwin(gv->sent,TRUE);

	/* Add Labels to the windows */
	attroff(COLOR_PAIR(2));
	attron(COLOR_PAIR(1));
	attron(A_REVERSE);
	mvwprintw(stdscr,1,(col * 0.02 + 2)," Contacts ");
	mvwprintw(stdscr,1,(received_startx + 2)," Received ");
	mvwprintw(stdscr,1,(sent_startx + 2)," Sent ");
	attroff(A_REVERSE);

	/* setup the variables for the main loop */
	int current_panel = 1;
	int ch,i,x,y;
	ch = i = x = y = 0;
	byte* usrcmd;

	gv->conn = tls_vars->bio_obj;
	gv->db = db;
	gv->current = gv->contacts;
	gv->previous =  gv->sent;
	gv->privkey = priv_evp;


#ifdef SSC_UPDATE_THREAD
	start_message_update(gv); /* Start the seperate message update thread */
#endif /* SSC_UPDATE_THREAD */

	ssc_cli_reload_contacts(gv); /* load the contacts from the database */

	/* Start the Main Loop */
	halfdelay(5); /* Set halfdelay to   */
	while((ch = getch()) != 'q'){
		switch(ch){
			case ERR: 
				ssc_cli_msg_upd(gv,ssc_cli_currently_selected(gv->contacts)); /* update the messages tab */
				break;
			case ':': //command mode 
				cbreak(); //switch out of halfdelay
				usrcmd = _getstr(); //get userinput
				ssc_cli_cmd_parser(gv,usrcmd); //parse commands
				free(usrcmd); //free userinput
				halfdelay(5); //switch back into halfdelay
				break;
			case KEY_DOWN:
			case 'j': //go down
				//Calculate the next curor position (y = y+2)
				getyx(stdscr,y,x);
				y += 2;
				if(current_panel == 1){
					ssc_cli_msg_clear(gv); //clear messages

					ssc_cli_cursor_move(gv,y,x); //move the cursor to the item below
					//add clear & reload messages for current 
					ssc_cli_window_upd_highlight(gv); //highlight the appropriate item in the list (based on the cursor position)
					ssc_cli_msg_upd(gv,ssc_cli_currently_selected(gv->contacts)); //update the messages column
				}
				else if(current_panel == 2){
					ssc_cli_msg_cursor_move(gv,y,x);
					ssc_cli_window_upd_highlight(gv); //highlight the appropriate item in the list (based on the cursor position)
				}
				else if(current_panel == 3){
					ssc_cli_msg_cursor_move(gv,y,x);
					ssc_cli_window_upd_highlight(gv); //highlight the appropriate item in the list (based on the cursor position)
				}
				break;
			case KEY_UP:
			case 'k': //go up 
				// Calculate the next cursor position (y = y-2)
				getyx(stdscr,y,x);
				y -= 2;
				if(current_panel == 1){
					ssc_cli_msg_clear(gv); //clear messages

					ssc_cli_cursor_move(gv,y,x); //move the cursor to the item below
					//add clear & reload messages for current 
					ssc_cli_window_upd_highlight(gv); //highlight the appropriate item in the list (based on the cursor position)
					ssc_cli_msg_upd(gv,ssc_cli_currently_selected(gv->contacts)); //update the messages column
				}
				else if(current_panel == 2){
					ssc_cli_msg_cursor_move(gv,y,x);
					ssc_cli_window_upd_highlight(gv); //highlight the appropriate item in the list (based on the cursor position)
				}
				else if(current_panel == 3){
					ssc_cli_msg_cursor_move(gv,y,x);
					ssc_cli_window_upd_highlight(gv); //highlight the appropriate item in the list (based on the cursor position)
				}			
				break;
			case 'h':
			case KEY_LEFT: //tab (Switch to the next window)
				current_panel--;
				if(current_panel == -1)current_panel = 3;
				if(current_panel == 1){ //User is in the contacts window
					gv->current = gv->contacts;
					gv->previous = gv->sent;
				}
				if(current_panel == 2){ // User is in the received window
					gv->current = gv->received;
					gv->previous = gv->contacts;
				}
				if(current_panel == 3){ //User is in the sent window
					gv->current = gv->sent;
					gv->previous = gv->received;
				}
				if(gv->previous != gv->contacts)ssc_cli_window_reload(gv->previous); //reload the previous window (to get rid of the highlighted item) if previous != contacts
				ssc_cli_switch_current(gv->current); //update the cursor
				ssc_cli_window_upd_highlight(gv); //update the highlighted item 
				break;
			case KEY_RIGHT:
			case 'l':
			case 9: //tab (Switch to the next window)
				current_panel++;
				if(current_panel == 4)current_panel = 1; //if tab is hit on the last panel, return to the first panel
				if(current_panel == 1){ //User is in the contacts window
					gv->current = gv->contacts;
					gv->previous = gv->sent;
				}
				if(current_panel == 2){ // User is in the received window
					gv->current = gv->received;
					gv->previous = gv->contacts;
				}
				if(current_panel == 3){ //User is in the sent window
					gv->current = gv->sent;
					gv->previous = gv->received;
				}
				if(gv->previous != gv->contacts)ssc_cli_window_reload(gv->previous); //reload the previous window (to get rid of the highlighted item) if previous != contacts
				ssc_cli_switch_current(gv->current); //update the cursor
				ssc_cli_window_upd_highlight(gv); //update the highlighted item 
				break;
		}
		refresh(); // load changes
	}
	ssc_cli_end();

/*Clean up objects in memory */
CLEANUP:
	cinfo("Cleaning up Objects... Exiting SimpleSecureChat");
	sqlite3_close(db);
	EVP_PKEY_free(pubk_evp);
	EVP_PKEY_free(priv_evp);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	BIO_free_all(tls_vars->bio_obj);
	SSL_CTX_free(tls_vars->ctx);
	free(tls_vars);
	tls_vars = NULL;
	kill_locks();
	return 1;
}
