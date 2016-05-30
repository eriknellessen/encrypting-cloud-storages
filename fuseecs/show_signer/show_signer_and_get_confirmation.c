#include <gtk/gtk.h>
#include <stdlib.h>

int signer_confirmed = 0;

static void abort_operation(GtkWidget *widget, gpointer data){
	signer_confirmed = 0;
}

static void confirm_operation(GtkWidget *widget, gpointer data){
	signer_confirmed = 1;
}

static void activate(GtkApplication *app, gpointer user_data){
	GtkWidget *window;
	GtkWidget *label;
	GtkWidget *button_abort;
	GtkWidget *button_confirm;
	GtkWidget *buttons_box;
	GtkWidget *label_and_buttons_box;

	//Create window
	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window), "Signer verification");
	gtk_window_set_default_size(GTK_WINDOW(window), 200, 200);

	//Create label showing the signature information
	label = gtk_label_new((char *) user_data);
	label_and_buttons_box = gtk_flow_box_new();
	gtk_flow_box_set_selection_mode((GtkFlowBox *) label_and_buttons_box, GTK_SELECTION_NONE);
	gtk_flow_box_set_max_children_per_line((GtkFlowBox *) label_and_buttons_box, 1);
	gtk_flow_box_insert((GtkFlowBox *) label_and_buttons_box, label, -1);

	//Create buttons
	buttons_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);

	button_abort = gtk_button_new_with_label("Not OK");
	g_signal_connect(button_abort, "clicked", G_CALLBACK(abort_operation), NULL);
	g_signal_connect_swapped(button_abort, "clicked", G_CALLBACK(gtk_widget_destroy), window);
	gtk_container_add(GTK_CONTAINER(buttons_box), button_abort);

	button_confirm = gtk_button_new_with_label("OK");
	g_signal_connect(button_confirm, "clicked", G_CALLBACK(confirm_operation), NULL);
	g_signal_connect_swapped(button_confirm, "clicked", G_CALLBACK(gtk_widget_destroy), window);
	gtk_container_add(GTK_CONTAINER(buttons_box), button_confirm);

	gtk_flow_box_insert((GtkFlowBox *) label_and_buttons_box, buttons_box, -1);

	gtk_container_add(GTK_CONTAINER (window), label_and_buttons_box);

	//Show window
	gtk_widget_show_all(window);
}

//TODO: The last shown GTK window is shown (in a destroyed way), until the next one is opened.
static int build_gtk_app(char *signature_information){
	GtkApplication *app;
	int status;

	app = gtk_application_new("de.nellessen.encryptingCloudStorages.showSigner", G_APPLICATION_FLAGS_NONE);
	g_signal_connect(app, "activate", G_CALLBACK(activate), signature_information);
	status = g_application_run(G_APPLICATION(app), 0, NULL);
	g_object_unref(app);

	return status;
}

int show_signer_and_get_confirmation(char *signature_information){
	if(build_gtk_app(signature_information) != 0){
		fprintf(stderr, "Could not build gtk app.\n");
		exit(-1);
	}

	return signer_confirmed;
}