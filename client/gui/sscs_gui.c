#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

struct sscswidgets_gui{
	GtkWidget *contactslist; //handle to contactslist
	GtkWidget *messagelist;	//Handle to messagelist
	GtkWidget *window; //Handle to Window
	char** current_username; //Username of chat partner (not the local user)
};

struct sscsbutton_gui{
	struct sscswidgets_gui* widgets;	
	char* item;
};

void clear_messages_gui(struct sscswidgets_gui* data){
	GtkContainer* container = (GtkContainer*)data->messagelist;	
	GList *children, *iter;
	children = gtk_container_get_children(GTK_CONTAINER(container));
	for(iter = children; iter != NULL; iter = g_list_next(iter)){
		gtk_widget_destroy(GTK_WIDGET(iter->data));
	}
	g_list_free(children);
	return;
}

void append_list_string_gui(GtkWidget* list,char* item){ //Add Label to Container List
	GtkWidget* label = gtk_label_new(item);
	gtk_container_add((GtkContainer*)list,label);
	gtk_widget_show(label);
	return;
}

void change_current_user_gui(GtkWidget* widget,gpointer data){
	(void)widget;
	struct sscsbutton_gui* pobj = data;
	clear_messages_gui(pobj->widgets);
	printf("changing current user from %s to %s\n",*((pobj->widgets)->current_username),pobj->item);
	free(*((pobj->widgets)->current_username)); //Release previous 
	*((pobj->widgets)->current_username) = pobj->item; //Change the pointer in main() to the current_username
	return;
}


void add_contact_gui(GtkWidget* contactslist,struct sscswidgets_gui* widgets,char* contactname){
	size_t contactname_len = strlen(contactname);
	if(contactname_len <= 0 || contactname_len >= 100)return;
	struct sscsbutton_gui* passedstruct = malloc(sizeof(struct sscsbutton_gui));
	passedstruct->widgets = widgets;

	char* contactname_alloc = malloc(contactname_len+1);
	memcpy(contactname_alloc,contactname,contactname_len+1);
	passedstruct->item = contactname_alloc;

	GtkWidget* button = gtk_button_new_with_label(contactname);
	g_signal_connect(G_OBJECT(button),"clicked",G_CALLBACK(change_current_user_gui),passedstruct);
	gtk_container_add((GtkContainer*)contactslist,button);
	gtk_widget_show(button);
	return;
}

void send_message_entry_gui(GtkEntry* entry,gpointer data){
	struct sscswidgets_gui* widgets = data;
	GtkWidget* messagelist = widgets->messagelist;	
	const char* message = gtk_entry_get_text(GTK_ENTRY(entry));
	append_list_string_gui(messagelist,message);
	gtk_entry_set_text(entry,"");
	printf("Sending Message to %s\n",*(widgets->current_username));
	return;
}

void add_user_entry_gui(GtkEntry* entry,gpointer data){
	struct sscswidgets_gui* widgets = data;
	GtkWidget* contactslist =  widgets->contactslist;
	char* username = (char*)gtk_entry_get_text(GTK_ENTRY(entry));
	add_contact_gui(contactslist,widgets,username);	
	gtk_entry_set_text(entry,"");
	return;
}

int main(void){
	puts("Starting GUI...");
	GtkBuilder* gtkBuilder;
	GtkWidget *window;
	gtk_init(NULL,NULL);
	gtkBuilder = gtk_builder_new();
	gtk_builder_add_from_file(gtkBuilder,"gui.glade",NULL);
	window = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"mainwindow"));
	GtkWidget *contactslist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"contactslist"));
	GtkWidget *messagelist = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"messageslist"));
	GtkWidget *sendmessagetext = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"sendmessagetext"));
	GtkWidget *addusertext = GTK_WIDGET(gtk_builder_get_object(gtkBuilder,"addusertext"));
	struct sscswidgets_gui* widgetsobj = malloc(sizeof(struct sscswidgets_gui));
	widgetsobj->window = window;
	widgetsobj->contactslist = contactslist;
	widgetsobj->messagelist = messagelist;
	char* username = NULL;
	widgetsobj->current_username = &username;
	append_list_string_gui(messagelist,"testmessage");
	append_list_string_gui(messagelist,"message2");
	add_contact_gui(contactslist,widgetsobj,"contact1");
	add_contact_gui(contactslist,widgetsobj,"contact2");
	g_object_unref(G_OBJECT(gtkBuilder));
	g_signal_connect(G_OBJECT(window),"destroy",G_CALLBACK(gtk_main_quit),NULL);
	g_signal_connect(G_OBJECT(sendmessagetext),"activate",G_CALLBACK(send_message_entry_gui),widgetsobj);
	g_signal_connect(G_OBJECT(addusertext),"activate",G_CALLBACK(add_user_entry_gui),widgetsobj);
	gtk_widget_show_all(window);
	gtk_main();
	return 0;
}
